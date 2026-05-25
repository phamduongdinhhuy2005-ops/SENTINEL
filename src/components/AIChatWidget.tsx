import { useCallback, useEffect, useRef, useState } from 'react';
import DOMPurify from 'dompurify';
import { AIChatMessage, AiQueryPayload, genMsgId, HISTORY_TURNS, INPUT_PLACEHOLDER_HINTS, routeQuery } from '../ai/aiRouter';
import { getOrchestrator } from '../ai/llm/hybridOrchestrator.js';
import { useAIStore } from '../store/useAIStore';
import { useStore } from '../store/useStore';
import { formatOwaspCategory } from '../utils/owasp';
import { buildRemediationPlan, formatRemediationPlanForPrompt } from '../utils/remediationPlan';

// Mở rộng AIChatMessage để mang theo thông tin debug provider
interface ExtendedAIChatMessage extends AIChatMessage {
  warnings?: string[];
  providersTried?: string[];
  latencyMs?: number;
}

type AIProviderId = 'groq' | 'gemini' | 'openrouter' | 'together' | 'huggingface';
type AIConfigProvider = { configured: boolean; stored?: boolean; envKeys?: string[] };

const AI_PROVIDER_OPTIONS: Array<{ id: AIProviderId; label: string; hint: string }> = [
  { id: 'groq',        label: 'Groq',        hint: 'GROQ_API_KEY - nhanh, hợp để chat bảo mật' },
  { id: 'gemini',      label: 'Gemini',      hint: 'GEMINI_API_KEY - dùng Google AI Studio' },
  { id: 'openrouter',  label: 'OpenRouter',  hint: 'OPENROUTER_API_KEY - nhiều model qua một key' },
  { id: 'together',    label: 'Together AI', hint: 'TOGETHER_API_KEY' },
  { id: 'huggingface', label: 'HuggingFace', hint: 'HF_API_KEY hoặc HUGGINGFACE_API_KEY' },
];

// ── Bộ render Markdown ────────────────────────────────────────────────────────
function renderMd(raw: string): string {
  let text = raw
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map(l => l.trimEnd())
    .join('\n');

  text = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const codeBlocks: string[] = [];
  text = text.replace(/```[\w]*\n?([\s\S]*?)```/g, (_, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(`<pre class="ai-pre"><code>${code.trimEnd()}</code></pre>`);
    return `ΩCODE${idx}Ω`;
  });

  const inl = (t: string) =>
    t
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code class="ai-code">$1</code>');

  const rawLines = text.split('\n');
  const lines: string[] = [];
  let prevBlank = false;
  for (const l of rawLines) {
    const isBlank = !l.trim();
    if (isBlank && prevBlank) continue;
    lines.push(l);
    prevBlank = isBlank;
  }

  const out: string[] = [];
  let listType = '';
  let listItems: string[] = [];

  const flushList = () => {
    if (!listItems.length) return;
    const tag = listType === 'ol' ? 'ol' : 'ul';
    const cls = listType === 'ol' ? 'ai-ol' : 'ai-ul';
    out.push(`<${tag} class="${cls}">${listItems.map(i => `<li>${i}</li>`).join('')}</${tag}>`);
    listItems = [];
    listType = '';
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) { flushList(); continue; }

    const codeMatch = line.match(/ΩCODE(\d+)Ω/);
    if (codeMatch) { flushList(); out.push(codeBlocks[parseInt(codeMatch[1])]); continue; }

    if (line === '---' || line === '***' || line === '___') {
      flushList(); out.push('<hr class="ai-hr"/>'); continue;
    }

    const h1 = line.match(/^# (.+)$/);
    if (h1) { flushList(); out.push(`<div class="ai-h2">${inl(h1[1])}</div>`); continue; }
    const h2 = line.match(/^## (.+)$/);
    if (h2) { flushList(); out.push(`<div class="ai-h3">${inl(h2[1])}</div>`); continue; }
    const h3 = line.match(/^### (.+)$/);
    if (h3) { flushList(); out.push(`<div class="ai-h4">${inl(h3[1])}</div>`); continue; }

    if (line.startsWith('|') && line.endsWith('|')) {
      if (/^\|[-:\s|]+\|$/.test(line)) continue;
      flushList();
      const cells = line.slice(1, -1).split('|').map(c => c.trim());
      const row = `<tr>${cells.map((c, i) => `<${i === 0 ? 'th' : 'td'}>${inl(c)}</${i === 0 ? 'th' : 'td'}>`).join('')}</tr>`;
      const last = out[out.length - 1];
      if (last && last.startsWith('<table')) {
        out[out.length - 1] = last.replace('</table>', row + '</table>');
      } else {
        out.push(`<table class="ai-table">${row}</table>`);
      }
      continue;
    }

    const bullet = line.match(/^[-*] (.+)$/);
    if (bullet) {
      if (listType !== 'ul') { flushList(); listType = 'ul'; }
      listItems.push(inl(bullet[1]));
      continue;
    }

    const numbered = line.match(/^\d+\. (.+)$/);
    if (numbered) {
      if (listType !== 'ol') { flushList(); listType = 'ol'; }
      listItems.push(inl(numbered[1]));
      continue;
    }

    flushList();
    out.push(`<p class="ai-p">${inl(line)}</p>`);
  }

  flushList();
  return DOMPurify.sanitize(out.join(''), {
    ALLOWED_TAGS: ['p', 'strong', 'em', 'code', 'pre', 'ul', 'ol', 'li', 'table', 'tr', 'th', 'td', 'hr', 'div'],
    ALLOWED_ATTR: ['class'],
  });
}

// ── Câu hỏi gợi ý nhanh (bổ sung thêm nhiều chủ đề) ──────────────────────────
const QUICK_QS = [
  // 🛡️ Công cụ
  { label: 'Sentinel là gì?',       q: 'SENTINEL là gì?',                    category: 'Công cụ' },
  { label: 'URL Scan',               q: 'URL Scan là gì và dùng thế nào?',    category: 'Công cụ' },
  { label: 'Project Scan',           q: 'Project Scan hoạt động như thế nào?', category: 'Công cụ' },
  { label: 'Crawl Depth',            q: 'Crawl Depth là gì?',                 category: 'Công cụ' },
  { label: 'Request Budget',         q: 'Request Budget là gì?',              category: 'Công cụ' },
  { label: 'Xác thực',               q: 'Cách thêm Authentication khi scan?', category: 'Công cụ' },
  { label: 'Xuất báo cáo',           q: 'Cách export báo cáo?',               category: 'Công cụ' },
  { label: 'Lịch sử scan',           q: 'Cách xem lịch sử scan?',             category: 'Công cụ' },
  { label: 'Collector',              q: 'Collector trong Findings là gì?',    category: 'Công cụ' },
  { label: 'False positive',         q: 'Khi nào phát hiện có thể là false positive?', category: 'Công cụ' },
  { label: 'Risk Score',             q: 'Risk Score được tính như thế nào?',  category: 'Công cụ' },
  { label: 'Checklist',              q: 'Tab Checklist dùng để làm gì?',      category: 'Công cụ' },
  { label: 'Scan chậm?',             q: 'Tại sao scan chạy chậm?',            category: 'Công cụ' },
  // 🔴 Lỗ hổng
  { label: 'SQL Injection',          q: 'SQL Injection là gì và cách fix?',   category: 'Lỗ hổng' },
  { label: 'XSS',                    q: 'XSS là gì và cách fix?',             category: 'Lỗ hổng' },
  { label: 'CSRF',                   q: 'CSRF là gì và cách fix?',            category: 'Lỗ hổng' },
  { label: 'CORS',                   q: 'CORS misconfiguration là gì?',       category: 'Lỗ hổng' },
  { label: 'JWT',                    q: 'JWT và các lỗi thường gặp?',         category: 'Lỗ hổng' },
  { label: 'SSRF',                   q: 'SSRF là gì?',                        category: 'Lỗ hổng' },
  { label: 'SSTI',                   q: 'SSTI là gì và cách fix?',            category: 'Lỗ hổng' },
  { label: 'IDOR',                   q: 'IDOR là gì?',                        category: 'Lỗ hổng' },
  { label: 'Path Traversal',         q: 'Path Traversal là gì?',              category: 'Lỗ hổng' },
  { label: 'Clickjacking',           q: 'Clickjacking là gì?',                category: 'Lỗ hổng' },
  { label: 'Open Redirect',          q: 'Open Redirect là gì?',               category: 'Lỗ hổng' },
  { label: 'Command Injection',      q: 'Command Injection là gì?',           category: 'Lỗ hổng' },
  { label: 'XXE Injection',          q: 'XXE là gì?',                         category: 'Lỗ hổng' },
  { label: 'BOLA / API IDOR',        q: 'BOLA/API IDOR là gì?',               category: 'Lỗ hổng' },
  { label: 'File Upload',            q: 'Lỗ hổng File Upload là gì?',         category: 'Lỗ hổng' },
  { label: 'GraphQL Security',       q: 'GraphQL có các lỗ hổng bảo mật nào?', category: 'Lỗ hổng' },
  { label: 'WebSocket Security',     q: 'WebSocket có các lỗ hổng bảo mật nào?', category: 'Lỗ hổng' },
  // ✅ Thực hành
  { label: 'Security Headers',       q: 'Security Headers là gì?',            category: 'Thực hành' },
  { label: 'Hardcoded Secrets',      q: 'SENTINEL tìm secrets hardcode như thế nào?', category: 'Thực hành' },
  { label: 'Rate Limiting',          q: 'Rate Limiting và Brute Force Protection là gì?', category: 'Thực hành' },
  { label: 'Password Security',      q: 'Cách lưu mật khẩu an toàn?',        category: 'Thực hành' },
  { label: 'API Security',           q: 'Các lỗ hổng bảo mật API phổ biến?', category: 'Thực hành' },
  { label: 'Session Management',     q: 'Session Management an toàn như thế nào?', category: 'Thực hành' },
  { label: 'Subresource Integrity',  q: 'Subresource Integrity (SRI) là gì?', category: 'Thực hành' },
  { label: 'Docker Security',        q: 'Các lỗi bảo mật Docker phổ biến?',  category: 'Thực hành' },
  { label: 'Env Config',             q: 'Cách quản lý configuration và biến môi trường an toàn?', category: 'Thực hành' },
  { label: '2FA / MFA',              q: '2FA/MFA là gì và tại sao quan trọng?', category: 'Thực hành' },
  { label: 'OAuth 2.0',              q: 'OAuth 2.0 và các lỗ hổng thường gặp?', category: 'Thực hành' },
  { label: 'Sensitive Data',         q: 'Sensitive Data Exposure là gì?',     category: 'Thực hành' },
  // 📋 OWASP
  { label: 'OWASP Top 10',           q: 'OWASP Top 10 là gì?',               category: 'OWASP' },
  { label: 'A01 – Access Control',   q: 'A01 Broken Access Control là gì?',  category: 'OWASP' },
  { label: 'A02 – Cryptography',     q: 'A02 Cryptographic Failures là gì?', category: 'OWASP' },
  { label: 'A03 – Injection',        q: 'A03 Injection là gì?',              category: 'OWASP' },
  { label: 'A04 – Insecure Design',  q: 'A04 Insecure Design là gì?',        category: 'OWASP' },
  { label: 'A05 – Misconfig',        q: 'A05 Security Misconfiguration là gì?', category: 'OWASP' },
  { label: 'A06 – Components',       q: 'A06 Vulnerable Components là gì?',  category: 'OWASP' },
  { label: 'A07 – Auth Failures',    q: 'A07 Auth & Session Failures là gì?', category: 'OWASP' },
  { label: 'A08 – Integrity',        q: 'A08 Software Integrity Failures là gì?', category: 'OWASP' },
  { label: 'A09 – Logging',          q: 'A09 Security Logging Failures là gì?', category: 'OWASP' },
  { label: 'A10 – SSRF',             q: 'A10 SSRF là gì?',                   category: 'OWASP' },
  { label: 'Pentest vs Scan',        q: 'Pentest và Vulnerability Scanning khác nhau như thế nào?', category: 'OWASP' },
];

const CATEGORIES = ['Công cụ', 'Lỗ hổng', 'Thực hành', 'OWASP'];

// ── Các icon SVG ──────────────────────────────────────────────────────────────
const IconShield = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
  </svg>
);
const IconClose = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);
const IconTrash = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
  </svg>
);
const IconSend = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
    <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/>
  </svg>
);
const IconStop = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
    <rect x="6" y="6" width="12" height="12" rx="2" ry="2"/>
  </svg>
);
const IconLightbulb = ({ active }: { active: boolean }) => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill={active ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21h6"/>
    <path d="M12 3a6 6 0 0 1 6 6c0 2.5-1.2 4.6-3 5.9V17a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1v-2.1C7.2 13.6 6 11.5 6 9a6 6 0 0 1 6-6z"/>
  </svg>
);
const IconChevron = ({ up }: { up: boolean }) => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <polyline points={up ? "18 15 12 9 6 15" : "6 9 12 15 18 9"}/>
  </svg>
);
const IconCopy = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
  </svg>
);
const IconSettings = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3"/>
    <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.6-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1A2 2 0 1 1 7.1 4l.1.1a1.7 1.7 0 0 0 1.9.3h.1a1.7 1.7 0 0 0 .9-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 .9 1.5h.1a1.7 1.7 0 0 0 1.9-.3l.1-.1A2 2 0 1 1 19.9 7l-.1.1a1.7 1.7 0 0 0-.3 1.9v.1a1.7 1.7 0 0 0 1.5.9h.1a2 2 0 1 1 0 4H21a1.7 1.7 0 0 0-1.6 1z"/>
  </svg>
);
const BotAvatar = () => (
  <div className="ai-avatar ai-avatar--bot">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  </div>
);
const UserAvatar = () => (
  <div className="ai-avatar ai-avatar--user">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
    </svg>
  </div>
);

// ── Độ trễ gõ chữ mô phỏng theo độ dài câu trả lời ────────────────────────────
function getTypingDelay(_answer: string): number {
  return 120 + Math.random() * 80;
}

// ── Hook xoay vòng placeholder ────────────────────────────────────────────────
function useRotatingPlaceholder(hints: string[], intervalMs = 4000) {
  const [idx, setIdx] = useState(0);
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = setInterval(() => {
      setVisible(false);
      setTimeout(() => {
        setIdx(i => (i + 1) % hints.length);
        setVisible(true);
      }, 300);
    }, intervalMs);
    return () => clearInterval(timer);
  }, [hints.length, intervalMs]);

  return { hint: hints[idx], visible };
}

// ── Hàm sao chép vào clipboard ────────────────────────────────────────────────
function copyText(text: string) {
  // Loại bỏ HTML để nội dung sao chép sạch hơn
  const clean = text.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
  navigator.clipboard?.writeText(clean).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = clean;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

async function hasConfiguredLlmProvider(): Promise<boolean> {
  const bridge = (globalThis as {
    owaspWorkbench?: {
      getAIProviders?: () => Promise<Record<string, { configured: boolean }>>;
    };
  }).owaspWorkbench;
  if (!bridge?.getAIProviders) return false;
  try {
    const providers = await bridge.getAIProviders();
    return Object.values(providers).some(provider => provider.configured);
  } catch {
    return false;
  }
}

async function fetchAIConfig(): Promise<{ providers: Record<string, AIConfigProvider>; userDataPath?: string }> {
  const bridge = (globalThis as {
    owaspWorkbench?: {
      getAIConfig?: () => Promise<{
        ok: boolean;
        providers?: Record<string, AIConfigProvider>;
        userDataPath?: string;
      }>;
    };
  }).owaspWorkbench;
  if (!bridge?.getAIConfig) return { providers: {} };
  const result = await bridge.getAIConfig();
  return { providers: result.providers || {}, userDataPath: result.userDataPath };
}

async function saveAIConfig(keys: Record<string, string>) {
  const bridge = (globalThis as {
    owaspWorkbench?: {
      saveAIConfig?: (payload: { keys: Record<string, string> }) => Promise<{
        ok: boolean;
        error?: string;
        providers?: Record<string, AIConfigProvider>;
        userDataPath?: string;
      }>;
    };
  }).owaspWorkbench;
  if (!bridge?.saveAIConfig) throw new Error('Không tìm thấy cầu nối cấu hình AI.');
  return bridge.saveAIConfig({ keys });
}

interface ResolvedAssistantAnswer {
  answer: string;
  llmStatus: 'online' | 'offline';
  providerUsed?: string;
  source?: 'knowledge_base' | 'llm' | 'synthesized';
  warnings?: string[];
  providersTried?: string[];
  latencyMs?: number;
}

async function resolveAssistantAnswer(payload: AiQueryPayload): Promise<ResolvedAssistantAnswer> {
  try {
    const response = await getOrchestrator().orchestrate(payload);
    // eslint-disable-next-line no-console
    console.info('[SENTINEL_AI_PROVIDER]', {
      providerUsed: response.providerUsed,
      source: response.source,
      confidence: response.confidence,
      warnings: response.warnings,
    });
    const llmStatus = await hasConfiguredLlmProvider() ? 'online' : 'offline';
    return {
      answer: response.answer,
      llmStatus,
      providerUsed: response.providerUsed,
      source: response.source,
      warnings: response.warnings,
      providersTried: response.providersTried,
      latencyMs: response.latencyMs,
    };
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw err;
    return {
      answer: routeQuery(payload),
      llmStatus: 'offline',
      providerUsed: 'knowledge_base',
      source: 'knowledge_base',
      warnings: [],
      providersTried: [],
    };
  }
}

const WELCOME_CHIPS = [
  { label: 'Sentinel là gì?',    q: 'SENTINEL là gì?' },
  { label: 'URL Scan',           q: 'URL Scan là gì và dùng thế nào?' },
  { label: 'SQL Injection',      q: 'SQL Injection là gì và cách fix?' },
  { label: 'OWASP Top 10',       q: 'OWASP Top 10 là gì?' },
  { label: 'XSS là gì?',         q: 'XSS là gì và cách fix?' },
  { label: 'Tôi hỗ trợ gì?',     q: 'Bạn có thể hỗ trợ những gì?' },
];

// ─────────────────────────────────────────────────────────────────────────────
export function AIChatWidget() {
  const { isOpen, pendingFinding, setAIChatOpen, clearAIPendingFinding, fabMode, cycleAIFabMode } = useAIStore();
  const { urlScanResult, projectScanResult } = useStore();

  const [messages, setMessages]               = useState<ExtendedAIChatMessage[]>([]);
  const [input, setInput]                     = useState('');
  const [isTyping, setIsTyping]               = useState(false);
  const [unread, setUnread]                   = useState(0);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [activeCategory, setActiveCategory]   = useState(CATEGORIES[0]);
  const [inputFocused, setInputFocused]       = useState(false);
  const [showFirstOpenTip, setShowFirstOpenTip] = useState(false);
  const [copiedMsgId, setCopiedMsgId]         = useState<string | null>(null);
  const [llmStatus, setLlmStatus]             = useState<'online' | 'offline'>('offline');
  const [expandedDebugId, setExpandedDebugId] = useState<string | null>(null);
  const [aiProviders, setAIProviders]         = useState<Record<string, AIConfigProvider>>({});
  const [aiUserDataPath, setAIUserDataPath]   = useState('');
  const [showAISettings, setShowAISettings]   = useState(false);
  const [aiKeyDrafts, setAIKeyDrafts]         = useState<Record<string, string>>({});
  const [aiConfigSaving, setAIConfigSaving]   = useState(false);
  const [aiConfigMessage, setAIConfigMessage] = useState<string | null>(null);
  // Từ khóa tìm kiếm trong panel gợi ý
  const [suggestionSearch, setSuggestionSearch] = useState('');

  const messagesEndRef       = useRef<HTMLDivElement>(null);
  const inputRef             = useRef<HTMLInputElement>(null);
  const initializedRef       = useRef(false);
  const processingFindingRef = useRef<string | null>(null);
  const typingTimeoutRef     = useRef<number | null>(null);
  const requestSeqRef        = useRef(0);
  const abortControllerRef   = useRef<AbortController | null>(null);
  const messagesRef          = useRef<ExtendedAIChatMessage[]>([]);
  // Lịch sử hội thoại để hiểu câu hỏi nối tiếp theo ngữ cảnh
  const conversationHistoryRef = useRef<{ role: 'user' | 'assistant'; content: string }[]>([]);

  const { hint: placeholderHint, visible: hintVisible } = useRotatingPlaceholder(INPUT_PLACEHOLDER_HINTS);
  const configuredProviderCount = AI_PROVIDER_OPTIONS.filter(p => aiProviders[p.id]?.configured).length;
  const hasAnyConfiguredKey = configuredProviderCount > 0;

  const refreshAIConfig = useCallback(async () => {
    try {
      const config = await fetchAIConfig();
      setAIProviders(config.providers);
      setAIUserDataPath(config.userDataPath || '');
      const configured = Object.values(config.providers).some(provider => provider.configured);
      setLlmStatus(configured ? 'online' : 'offline');
    } catch {
      setAIProviders({});
      setLlmStatus('offline');
    }
  }, []);

  // Reserve safe space so the floating AI button doesn't cover content
  useEffect(() => {
    const safe = fabMode === 'hidden' ? '16px' : '56px';
    document.documentElement.style.setProperty('--ai-fab-safe-bottom', safe);
    return () => { /* keep last value */ };
  }, [fabMode]);

  // Tự cuộn xuống cuối danh sách tin nhắn
  useEffect(() => {
    if (isOpen) messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isOpen]);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  useEffect(() => {
    void refreshAIConfig();
  }, [refreshAIConfig]);

  useEffect(() => {
    if (isOpen) void refreshAIConfig();
  }, [isOpen, refreshAIConfig]);

  // Focus ô nhập và xóa badge chưa đọc
  useEffect(() => {
    if (isOpen) { setUnread(0); setTimeout(() => inputRef.current?.focus(), 150); }
  }, [isOpen]);

  // Tip lần đầu mở (chỉ hiển thị một lần)
  useEffect(() => {
    if (!isOpen) return;
    try {
      const seen = localStorage.getItem('sentinel.ai.firstTipSeen') === '1';
      if (!seen) setShowFirstOpenTip(true);
    } catch {
      setShowFirstOpenTip(true);
    }
  }, [isOpen]);

  // Chỉ tạo tin nhắn chào mừng một lần
  const ensureWelcome = useCallback(() => {
    if (initializedRef.current) return;
    initializedRef.current = true;
    const welcomeContent = `Xin chào! Tôi là **SENTINEL AI Assistant** — trợ lý bảo mật dựa trên knowledge base OWASP cục bộ và có thể mở rộng bằng LLM khi bạn cấu hình API key.\n\nTôi được xây dựng để giúp bạn:\n\n- Giải thích chi tiết các lỗ hổng bảo mật (XSS, SQL Injection, CSRF, IDOR, SSTI, SSRF...)\n- Hướng dẫn từng bước cách sử dụng SENTINEL\n- Phân tích và đề xuất cách khắc phục từng phát hiện cụ thể\n- Giải thích các khái niệm OWASP A01–A10\n\nNhấn vào bất kỳ phát hiện nào và chọn **"Hỏi AI"** để nhận phân tích tường tận, hoặc gõ câu hỏi bên dưới.`;
    const welcome: AIChatMessage = {
      id: genMsgId(), role: 'assistant', content: welcomeContent, ts: Date.now(),
    };
    setMessages([welcome]);
    messagesRef.current = [welcome];
    conversationHistoryRef.current = [{ role: 'assistant', content: welcomeContent }];
  }, []);

  const clearTypingTimeout = useCallback(() => {
    if (typingTimeoutRef.current !== null) {
      window.clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = null;
    }
  }, []);

  const scheduleAssistantReply = useCallback((
    answer: string,
    userContent: string,
    options?: {
      findingKey?: string;
      incrementUnread?: boolean;
      providerUsed?: string;
      source?: 'knowledge_base' | 'llm' | 'synthesized';
      warnings?: string[];
      providersTried?: string[];
      latencyMs?: number;
    },
  ) => {
    clearTypingTimeout();
    setIsTyping(true);
    const delay = getTypingDelay(answer);
    typingTimeoutRef.current = window.setTimeout(() => {
      const botMsg: ExtendedAIChatMessage = {
        id: genMsgId(),
        role: 'assistant',
        content: answer,
        ts: Date.now(),
        providerUsed: options?.providerUsed,
        source: options?.source,
        warnings: options?.warnings,
        providersTried: options?.providersTried,
        latencyMs: options?.latencyMs,
      };
      setMessages(prev => [...prev, botMsg]);
      messagesRef.current = [...messagesRef.current, botMsg];
      conversationHistoryRef.current = [
        ...conversationHistoryRef.current,
        { role: 'user' as const, content: userContent },
        { role: 'assistant' as const, content: answer },
      ].slice(-HISTORY_TURNS);
      setIsTyping(false);
      if (options?.findingKey) processingFindingRef.current = null;
      if (options?.incrementUnread && !isOpen) setUnread(u => u + 1);
      typingTimeoutRef.current = null;
    }, delay);
  }, [clearTypingTimeout, isOpen]);

  const finalizeAssistantReply = useCallback((
    resolved: ResolvedAssistantAnswer,
    userContent: string,
    hasStreamed: boolean,
    msgId: string,
    options?: { findingKey?: string; incrementUnread?: boolean }
  ) => {
    if (hasStreamed) {
      setMessages(prev => prev.map(m => m.id === msgId ? {
        ...m,
        content: resolved.answer,
        providerUsed: resolved.providerUsed,
        source: resolved.source,
        warnings: resolved.warnings,
        providersTried: resolved.providersTried,
        latencyMs: resolved.latencyMs,
      } : m));
      messagesRef.current = messagesRef.current.map(m => m.id === msgId ? {
        ...m,
        content: resolved.answer,
        providerUsed: resolved.providerUsed,
        source: resolved.source,
        warnings: resolved.warnings,
        providersTried: resolved.providersTried,
        latencyMs: resolved.latencyMs,
      } : m);
      conversationHistoryRef.current = [
        ...conversationHistoryRef.current,
        { role: 'user' as const, content: userContent },
        { role: 'assistant' as const, content: resolved.answer },
      ].slice(-HISTORY_TURNS);
      if (options?.findingKey) processingFindingRef.current = null;
      if (options?.incrementUnread && !isOpen) setUnread(u => u + 1);
    } else {
      scheduleAssistantReply(resolved.answer, userContent, {
        findingKey: options?.findingKey,
        incrementUnread: options?.incrementUnread,
        providerUsed: resolved.providerUsed,
        source: resolved.source,
        warnings: resolved.warnings,
        providersTried: resolved.providersTried,
        latencyMs: resolved.latencyMs,
      });
    }
  }, [isOpen, scheduleAssistantReply]);

  // Xử lý phát hiện được gửi từ thẻ kết quả
  useEffect(() => {
    if (!pendingFinding) return;
    const findingKey = `${pendingFinding.ruleId}_${pendingFinding.title}`;
    if (processingFindingRef.current === findingKey) return;
    processingFindingRef.current = findingKey;

    ensureWelcome();
    setShowSuggestions(false);
    clearAIPendingFinding();

    const question = `Giải thích phát hiện: ${pendingFinding.title} (${pendingFinding.ruleId})`;
    const remediationPlan = pendingFinding.remediationPlan || buildRemediationPlan(pendingFinding);
    const findingCtx = {
      ruleId: pendingFinding.ruleId,
      title: pendingFinding.title,
      severity: pendingFinding.severity,
      confidence: pendingFinding.confidence,
      owaspCategory: pendingFinding.owaspCategory,
      target: pendingFinding.target,
      location: pendingFinding.location,
      remediation: pendingFinding.remediation,
      remediationPlan,
      remediationPlanText: formatRemediationPlanForPrompt({ ...pendingFinding, remediationPlan }),
      evidence: pendingFinding.evidence,
      references: pendingFinding.references,
      collector: pendingFinding.collector,
    };

    const userMsg: AIChatMessage = {
      id: genMsgId(), role: 'user', content: question, ts: Date.now(),
      findingContext: {
        ruleId: pendingFinding.ruleId,
        title: pendingFinding.title,
        severity: pendingFinding.severity,
        owaspCategory: pendingFinding.owaspCategory,
        confidence: pendingFinding.confidence,
        target: pendingFinding.target,
        location: pendingFinding.location,
        evidence: pendingFinding.evidence,
        remediation: pendingFinding.remediation,
        remediationPlan,
        references: pendingFinding.references,
        collector: pendingFinding.collector,
      },
    };

    const nextMessages = [...messagesRef.current, userMsg];
    messagesRef.current = nextMessages;
    setMessages(nextMessages);
    setIsTyping(true);
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();
    const signal = abortControllerRef.current.signal;

    const requestId = ++requestSeqRef.current;
    
    const msgId = genMsgId();
    let hasStreamed = false;
    let streamedContent = '';

    const onToken = (token: string) => {
      streamedContent += token;
      if (!hasStreamed) {
        hasStreamed = true;
        setIsTyping(false);
        const botMsg: ExtendedAIChatMessage = {
          id: msgId, role: 'assistant', content: streamedContent, ts: Date.now()
        };
        setMessages(prev => [...prev, botMsg]);
        messagesRef.current = [...messagesRef.current, botMsg];
      } else {
        setMessages(prev => prev.map(m => m.id === msgId ? { ...m, content: streamedContent } : m));
        messagesRef.current = messagesRef.current.map(m => m.id === msgId ? { ...m, content: streamedContent } : m);
      }
    };

    void (async () => {
      let resolved: ResolvedAssistantAnswer;
      try {
        const lastAsstMsg = [...messagesRef.current].reverse().find(m => m.role === 'assistant')?.content;
        resolved = await resolveAssistantAnswer({
          question,
          findingContext: findingCtx,
          lastAssistantMessage: lastAsstMsg,
          conversationHistory: conversationHistoryRef.current,
          signal,
          onToken,
        });
      } catch (err) {
        if ((err as Error).name === 'AbortError') return;
        resolved = {
          answer: routeQuery({
            question,
            findingContext: findingCtx,
            conversationHistory: conversationHistoryRef.current,
          }),
          llmStatus: 'offline',
        };
      }
      if (requestId !== requestSeqRef.current) return;
      setLlmStatus(resolved.llmStatus);
      finalizeAssistantReply(resolved, question, hasStreamed, msgId, { findingKey });
    })();
  }, [clearAIPendingFinding, ensureWelcome, pendingFinding, finalizeAssistantReply]);

  // Gửi câu hỏi mới
  const sendMessage = useCallback((question: string) => {
    const trimmed = question.trim();
    if (!trimmed || isTyping) return;
    ensureWelcome();
    setShowSuggestions(false);
    setSuggestionSearch('');

    const lastAsstMsg = [...messagesRef.current].reverse().find(m => m.role === 'assistant')?.content;
    const userMsg: AIChatMessage = { id: genMsgId(), role: 'user', content: trimmed, ts: Date.now() };
    const nextMessages = [...messagesRef.current, userMsg];
    messagesRef.current = nextMessages;
    setMessages(nextMessages);
    setIsTyping(true);
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    abortControllerRef.current = new AbortController();
    const signal = abortControllerRef.current.signal;

    const requestId = ++requestSeqRef.current;

    const msgId = genMsgId();
    let hasStreamed = false;
    let streamedContent = '';

    const onToken = (token: string) => {
      streamedContent += token;
      if (!hasStreamed) {
        hasStreamed = true;
        setIsTyping(false);
        const botMsg: ExtendedAIChatMessage = {
          id: msgId, role: 'assistant', content: streamedContent, ts: Date.now()
        };
        setMessages(prev => [...prev, botMsg]);
        messagesRef.current = [...messagesRef.current, botMsg];
      } else {
        setMessages(prev => prev.map(m => m.id === msgId ? { ...m, content: streamedContent } : m));
        messagesRef.current = messagesRef.current.map(m => m.id === msgId ? { ...m, content: streamedContent } : m);
      }
    };

    void (async () => {
      let resolved: ResolvedAssistantAnswer;
      try {
        resolved = await resolveAssistantAnswer({
          question: trimmed,
          lastAssistantMessage: lastAsstMsg,
          conversationHistory: conversationHistoryRef.current,
          signal,
          onToken,
        });
      } catch (err) {
        if ((err as Error).name === 'AbortError') return;
        resolved = {
          answer: routeQuery({
            question: trimmed,
            lastAssistantMessage: lastAsstMsg,
            conversationHistory: conversationHistoryRef.current,
          }),
          llmStatus: 'offline',
        };
      }
      if (requestId !== requestSeqRef.current) return;
      setLlmStatus(resolved.llmStatus);
      finalizeAssistantReply(resolved, trimmed, hasStreamed, msgId, { incrementUnread: true });
    })();
    setInput('');
  }, [ensureWelcome, isTyping, finalizeAssistantReply]);

  const handleSubmit = (e: React.FormEvent) => { e.preventDefault(); sendMessage(input); };
  const handleOpen   = () => { setAIChatOpen(true); ensureWelcome(); void refreshAIConfig(); };
  const handleClose  = () => { setAIChatOpen(false); setShowSuggestions(false); setShowAISettings(false); };
  
  const handleStop = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    clearTypingTimeout();
    setIsTyping(false);
  }, [clearTypingTimeout]);

  const handleClear  = () => {
    handleStop();
    requestSeqRef.current += 1;
    void refreshAIConfig();
    initializedRef.current = false;
    conversationHistoryRef.current = [];
    messagesRef.current = [];
    processingFindingRef.current = null;
    setMessages([]);
    setIsTyping(false);
    setShowSuggestions(false);
    setSuggestionSearch('');
    setTimeout(() => ensureWelcome(), 50);
  };

  useEffect(() => () => {
    requestSeqRef.current += 1;
    clearTypingTimeout();
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  }, [clearTypingTimeout]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      if (showSuggestions) { setShowSuggestions(false); return; }
      handleClose();
    }
  };

  const handleCopy = (msg: AIChatMessage) => {
    copyText(renderMd(msg.content));
    setCopiedMsgId(msg.id);
    setTimeout(() => setCopiedMsgId(null), 1800);
  };

  const handleSaveAIConfig = async () => {
    setAIConfigSaving(true);
    setAIConfigMessage(null);
    try {
      const result = await saveAIConfig(aiKeyDrafts);
      if (!result.ok) throw new Error(result.error || 'Không lưu được cấu hình AI.');
      setAIProviders(result.providers || {});
      setAIUserDataPath(result.userDataPath || aiUserDataPath);
      setAIKeyDrafts({});
      const configured = Object.values(result.providers || {}).some(provider => provider.configured);
      setLlmStatus(configured ? 'online' : 'offline');
      setAIConfigMessage('Đã lưu API key và áp dụng ngay cho AI.');
    } catch (err) {
      setAIConfigMessage((err as Error).message || 'Không lưu được cấu hình AI.');
    } finally {
      setAIConfigSaving(false);
    }
  };

  const handleRemoveAIProviderKey = async (providerId: AIProviderId) => {
    setAIConfigSaving(true);
    setAIConfigMessage(null);
    try {
      const result = await saveAIConfig({ [providerId]: '' });
      if (!result.ok) throw new Error(result.error || 'Không xóa được key.');
      setAIProviders(result.providers || {});
      setAIKeyDrafts(prev => ({ ...prev, [providerId]: '' }));
      const configured = Object.values(result.providers || {}).some(provider => provider.configured);
      setLlmStatus(configured ? 'online' : 'offline');
      setAIConfigMessage('Đã xóa API key đã lưu cho provider này.');
    } catch (err) {
      setAIConfigMessage((err as Error).message || 'Không xóa được key.');
    } finally {
      setAIConfigSaving(false);
    }
  };

  const totalFindings = (urlScanResult?.findings?.length || 0) + (projectScanResult?.findings?.length || 0);
  const conversationStarted = messages.length > 1;

  // Lọc câu hỏi gợi ý theo từ khóa tìm kiếm
  const filteredQs = QUICK_QS.filter(q => {
    if (q.category !== activeCategory) return false;
    if (!suggestionSearch.trim()) return true;
    const s = suggestionSearch.toLowerCase();
    return q.label.toLowerCase().includes(s) || q.q.toLowerCase().includes(s);
  });

  return (
    <>
      {/* ── Nút nổi mở chat ─────────────────────────────────────────── */}
      {fabMode !== 'hidden' && (
        <button
          id="ai-chat-fab"
          className={`ai-fab${isOpen ? ' ai-fab--open' : ''}${fabMode === 'dim' ? ' ai-fab--dim' : ''}`}
          onClick={isOpen ? handleClose : handleOpen}
          onContextMenu={(e) => { e.preventDefault(); cycleAIFabMode(); }}
          title={
            (isOpen ? 'Đóng AI Assistant' : 'SENTINEL AI Assistant') +
            ' • Chuột phải để: bình thường → mờ → ẩn'
          }
          aria-label="AI Security Assistant"
        >
          <span className="ai-fab-icon">
            {isOpen ? <IconClose /> : <IconShield />}
          </span>
          {!isOpen && unread > 0 && <span className="ai-fab-badge">{unread}</span>}
          {!isOpen && <span className="ai-fab-pulse" />}
        </button>
      )}
      {fabMode === 'hidden' && !isOpen && (
        <button
          className="ai-fab-restore"
          onClick={() => cycleAIFabMode()}
          title="Hiện lại nút AI"
          aria-label="Hiện lại nút AI"
        >
          AI
        </button>
      )}

      {/* ── Panel chat ───────────────────────────────────────────── */}
      {isOpen && (
        <div
          className={`ai-panel${showAISettings ? ' ai-panel--setup' : ''}`}
          id="ai-chat-panel"
          role="dialog"
          aria-label="AI Security Assistant"
        >
          {/* Phần đầu panel */}
          <div className="ai-panel-header">
            <div className="ai-panel-title">
              <div className="ai-panel-avatar">
                <IconShield />
                <span className="ai-avatar-glow" />
              </div>
              <div>
                <div className="ai-panel-name">Trợ lý bảo mật</div>
                <div className="ai-panel-sub">
                  <span className={`ai-online-dot${llmStatus === 'offline' ? ' ai-online-dot--offline' : ''}`} />
                  <span>{llmStatus === 'online' ? `LLM sẵn sàng · ${configuredProviderCount} key` : 'KB cục bộ · thiếu API key'}</span>
                  {totalFindings > 0 && (
                    <span className="ai-findings-badge">{totalFindings} kết quả</span>
                  )}
                </div>
              </div>
            </div>
            <div className="ai-header-right">
              <button
                className={`ai-config-pill${hasAnyConfiguredKey ? ' ai-config-pill--ok' : ' ai-config-pill--warn'}`}
                onClick={() => { setShowAISettings(v => !v); setAIConfigMessage(null); }}
                title="Cấu hình API key cho AI"
                type="button"
              >
                <IconSettings />
                {hasAnyConfiguredKey ? 'AI Online' : 'Cấu hình AI'}
              </button>
              <button className="ai-icon-btn" onClick={handleClear} title="Xóa lịch sử chat">
                <IconTrash />
              </button>
              <button className="ai-icon-btn ai-icon-btn--close" onClick={handleClose} title="Đóng">
                <IconClose />
              </button>
            </div>
          </div>

          {showAISettings && (
            <div className="ai-config-panel">
              <div className="ai-config-head">
                <div>
                  <div className="ai-config-title">Cấu hình API key</div>
                  <div className="ai-config-sub">
                    Key được lưu trong userData của app, áp dụng ngay sau khi lưu.
                  </div>
                </div>
                <span className={`ai-config-status${hasAnyConfiguredKey ? ' ok' : ' warn'}`}>
                  {hasAnyConfiguredKey ? `${configuredProviderCount} provider sẵn sàng` : 'Chưa có key'}
                </span>
              </div>

              <div className="ai-config-grid">
                {AI_PROVIDER_OPTIONS.map(provider => {
                  const current = aiProviders[provider.id];
                  return (
                    <label key={provider.id} className="ai-config-field">
                      <span className="ai-config-provider-row">
                        <span className="ai-config-provider-name">{provider.label}</span>
                        <span className="ai-config-provider-actions">
                          <span className={`ai-config-provider-state${current?.configured ? ' ok' : ''}`}>
                            {current?.configured ? (current.stored ? 'Đã lưu' : '.env') : 'Trống'}
                          </span>
                          {current?.stored && (
                            <button
                              type="button"
                              className="ai-config-remove"
                              onClick={() => void handleRemoveAIProviderKey(provider.id)}
                              disabled={aiConfigSaving}
                            >
                              Xóa
                            </button>
                          )}
                        </span>
                      </span>
                      <input
                        type="password"
                        value={aiKeyDrafts[provider.id] || ''}
                        onChange={e => setAIKeyDrafts(prev => ({ ...prev, [provider.id]: e.target.value }))}
                        placeholder={current?.configured ? 'Nhập key mới hoặc để trống để giữ nguyên' : 'Dán API key tại đây'}
                        autoComplete="off"
                      />
                      <span className="ai-config-hint">{provider.hint}</span>
                    </label>
                  );
                })}
              </div>

              <div className="ai-config-footer">
                <div className="ai-config-path" title={aiUserDataPath}>
                  {aiUserDataPath ? `Lưu tại: ${aiUserDataPath}` : 'Sẽ lưu trong userData của ứng dụng'}
                </div>
                <button
                  type="button"
                  className="btn-secondary ai-config-save"
                  onClick={handleSaveAIConfig}
                  disabled={aiConfigSaving || !Object.values(aiKeyDrafts).some(v => v.trim())}
                >
                  {aiConfigSaving ? 'Đang lưu...' : 'Lưu & áp dụng'}
                </button>
              </div>
              {aiConfigMessage && <div className="ai-config-message">{aiConfigMessage}</div>}
            </div>
          )}

          {!showAISettings && (
          <>
            {/* Danh sách tin nhắn */}
            <div className="ai-messages" id="ai-messages-list">
            {!hasAnyConfiguredKey && (
              <div className="ai-config-banner">
                <div>
                  <strong>AI nâng cao chưa được bật</strong>
                  <span>Ứng dụng vẫn trả lời bằng knowledge base cục bộ. Thêm Groq/Gemini/OpenRouter key để dùng LLM.</span>
                </div>
                <button type="button" className="btn-link" onClick={() => setShowAISettings(true)}>
                  Cấu hình ngay
                </button>
              </div>
            )}
            {showFirstOpenTip && !conversationStarted && !showSuggestions && !isTyping && (
              <div className="onboarding-banner" style={{ margin: '8px 10px 6px' }}>
                <div className="onboarding-banner-title">Mẹo nhanh</div>
                <div className="onboarding-banner-text">
                  Nhấn nút gợi ý để xem câu hỏi mẫu. Bạn cũng có thể nhấn “Hỏi AI” trong từng phát hiện để xem phân tích chi tiết.
                </div>
                <button
                  className="btn-link"
                  onClick={() => {
                    setShowFirstOpenTip(false);
                    try { localStorage.setItem('sentinel.ai.firstTipSeen', '1'); } catch { /* ignore */ }
                  }}
                >
                  Đã hiểu
                </button>
              </div>
            )}
            {messages.map((msg, idx) => (
              <div
                key={msg.id}
                className={`ai-msg ai-msg--${msg.role}`}
                style={{ animationDelay: `${Math.min(idx * 0.04, 0.2)}s` }}
              >
                {msg.role === 'assistant' && <BotAvatar />}
                <div className="ai-bubble">
                  {msg.findingContext && (
                    <div className="ai-finding-tag">
                      <span className={`ai-sev-dot ai-sev-dot--${msg.findingContext.severity}`} />
                      <span className="ai-finding-title">{msg.findingContext.title}</span>
                      <span className="ai-finding-owasp">{formatOwaspCategory(msg.findingContext.owaspCategory)}</span>
                    </div>
                  )}
                  <div
                    className="ai-bubble-text"
                    dangerouslySetInnerHTML={{ __html: renderMd(msg.content) }}
                  />
                  <div className="ai-bubble-footer">
                    {msg.role === 'assistant' && msg.providerUsed && (
                      <span
                        className={`ai-bubble-provider ai-bubble-provider--${
                          msg.providerUsed === 'knowledge_base' ? 'kb'
                          : msg.providerUsed === 'fallback' ? 'fallback'
                          : 'llm'
                        }`}
                      >
                        {msg.providerUsed === 'knowledge_base' ? '◇ KB'
                          : msg.providerUsed === 'fallback' ? '△ Offline'
                          : `✦ ${msg.providerUsed}`}
                        {msg.source && msg.source !== 'knowledge_base' && (
                          <span className="ai-provider-source"> · {msg.source}</span>
                        )}
                        {typeof msg.latencyMs === 'number' && msg.latencyMs > 0 && (
                          <span className="ai-provider-latency"> · {msg.latencyMs}ms</span>
                        )}
                      </span>
                    )}
                    <span className="ai-bubble-time">
                      {new Date(msg.ts).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' })}
                    </span>
                    {/* Nút hiển thị chi tiết lỗi provider */}
                    {msg.role === 'assistant' && msg.warnings && msg.warnings.filter(w => w.includes('failed') || w.includes('skipped') || w.includes('unavailable')).length > 0 && (
                      <button
                        className="ai-debug-toggle"
                        onClick={() => setExpandedDebugId(expandedDebugId === msg.id ? null : msg.id)}
                        title={expandedDebugId === msg.id ? 'Ẩn chi tiết lỗi' : 'Xem chi tiết lỗi provider'}
                      >
                        {expandedDebugId === msg.id ? '▲ Ẩn' : '△ Chi tiết'}
                      </button>
                    )}
                    {msg.role === 'assistant' && (
                      <button
                        className={`ai-copy-btn${copiedMsgId === msg.id ? ' ai-copy-btn--done' : ''}`}
                        onClick={() => handleCopy(msg)}
                        title="Sao chép câu trả lời"
                        aria-label="Copy"
                      >
                        {copiedMsgId === msg.id ? '✓' : <IconCopy />}
                      </button>
                    )}
                  </div>
                  {/* Panel chi tiết lỗi từng provider */}
                  {msg.role === 'assistant' && expandedDebugId === msg.id && msg.warnings && (
                    <div className="ai-provider-debug">
                      {msg.providersTried && msg.providersTried.length > 0 && (
                        <div className="ai-debug-row">
                          <span className="ai-debug-label">Đã thử:</span>
                          <span className="ai-debug-val">{msg.providersTried.join(' → ')}</span>
                        </div>
                      )}
                      {msg.warnings.length > 0 && (
                        <div className="ai-debug-errors">
                          {msg.warnings.map((w, i) => {
                            const isFailed = w.includes('failed') || w.includes('HTTP');
                            const isSkipped = w.includes('skipped') || w.includes('missing');
                            return (
                              <div
                                key={i}
                                className={`ai-debug-warn ai-debug-warn--${
                                  isFailed ? 'error' : isSkipped ? 'skip' : 'info'
                                }`}
                              >
                                {isFailed ? '✗' : isSkipped ? '○' : 'i'} {w}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                {msg.role === 'user' && <UserAvatar />}
              </div>
            ))}

            {/* Hiệu ứng đang trả lời */}
            {isTyping && (
              <div className="ai-msg ai-msg--assistant">
                <BotAvatar />
                <div className="ai-bubble ai-bubble--typing">
                  <span /><span /><span />
                </div>
              </div>
            )}
              <div ref={messagesEndRef} />
            </div>

            {/* Panel câu hỏi gợi ý */}
            {showSuggestions && !isTyping && (
            <div className="ai-quickqs">
              <div className="ai-quickqs-header">
                <span className="ai-quickqs-label">Câu hỏi gợi ý</span>
                <button
                  className="ai-quickqs-close"
                  onClick={() => setShowSuggestions(false)}
                  title="Ẩn gợi ý"
                >
                  <IconChevron up={false} />
                </button>
              </div>
              {/* Search box inside suggestions */}
              <div className="ai-quickqs-search-wrap">
                <input
                  className="ai-quickqs-search"
                  type="text"
                  placeholder="Tìm câu hỏi..."
                  value={suggestionSearch}
                  onChange={e => setSuggestionSearch(e.target.value)}
                  autoComplete="off"
                />
              </div>
              {/* Category tabs — hide when searching */}
              {!suggestionSearch && (
                <div className="ai-quickqs-tabs">
                  {CATEGORIES.map(cat => (
                    <button
                      key={cat}
                      className={`ai-quickqs-tab${activeCategory === cat ? ' active' : ''}`}
                      onClick={() => setActiveCategory(cat)}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              )}
              {/* Results */}
              <div className="ai-quickqs-grid">
                {(suggestionSearch
                  ? QUICK_QS.filter(q => {
                      const s = suggestionSearch.toLowerCase();
                      return q.label.toLowerCase().includes(s) || q.q.toLowerCase().includes(s);
                    })
                  : filteredQs
                ).map(({ label, q }) => (
                  <button key={q} className="ai-quickq-btn" onClick={() => sendMessage(q)}>
                    {label}
                  </button>
                ))}
                {(suggestionSearch
                  ? QUICK_QS.filter(q => {
                      const s = suggestionSearch.toLowerCase();
                      return q.label.toLowerCase().includes(s) || q.q.toLowerCase().includes(s);
                    })
                  : filteredQs).length === 0 && (
                  <p className="ai-quickqs-empty">Không tìm thấy câu hỏi phù hợp.</p>
                )}
              </div>
            </div>
            )}

            {/* Chip gợi ý trước khi hội thoại bắt đầu */}
            {!conversationStarted && !showSuggestions && !isTyping && (
            <div className="ai-quickqs ai-quickqs--welcome">
              <div className="ai-quickqs-header">
                <span className="ai-quickqs-label">Gợi ý bắt đầu</span>
              </div>
              <div className="ai-quickqs-grid">
                {WELCOME_CHIPS.map(({ label, q }) => (
                  <button key={q} className="ai-quickq-btn" onClick={() => sendMessage(q)}>
                    {label}
                  </button>
                ))}
              </div>
            </div>
            )}

            {/* Hàng nhập câu hỏi */}
            <form
            className={`ai-input-row${inputFocused ? ' ai-input-row--focused' : ''}`}
            onSubmit={handleSubmit}
            >
            <button
              type="button"
              id="ai-suggestions-toggle"
              className={`ai-suggestions-toggle${showSuggestions ? ' active' : ''}`}
              onClick={() => setShowSuggestions(v => !v)}
              title={showSuggestions ? 'Ẩn câu hỏi gợi ý' : 'Hiện câu hỏi gợi ý'}
              aria-label="Toggle suggestions"
            >
              <IconLightbulb active={showSuggestions} />
            </button>

            {/* Vùng nhập với placeholder động */}
            <div className="ai-input-wrapper">
              <input
                ref={inputRef}
                id="ai-chat-input"
                className="ai-input"
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                onFocus={() => setInputFocused(true)}
                onBlur={() => setInputFocused(false)}
                onKeyDown={handleKeyDown}
                placeholder=" "
                disabled={isTyping}
                autoComplete="off"
                maxLength={500}
              />
              {/* Placeholder động hiển thị khi ô nhập đang trống */}
              {!input && (
                <span
                  className={`ai-input-ghost${hintVisible ? ' ai-input-ghost--visible' : ''}`}
                  aria-hidden="true"
                >
                  Ví dụ: {placeholderHint}
                </span>
              )}
            </div>

            {isTyping ? (
              <button
                type="button"
                className="ai-send-btn ai-send-btn--stop"
                onClick={handleStop}
                aria-label="Dừng"
              >
                <IconStop />
              </button>
            ) : (
              <button
                id="ai-chat-send"
                className={`ai-send-btn${input.trim() && !isTyping ? ' ai-send-btn--ready' : ''}`}
                type="submit"
                disabled={!input.trim()}
                aria-label="Gửi"
              >
                <IconSend />
              </button>
            )}
            </form>
          </>
          )}
        </div>
      )}
    </>
  );
}
