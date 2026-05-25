/**
 * sentinelAI.ts — Tang goi LLM truc tiep (Direct LLM Caller)
 *
 * Đây là tầng dự phòng được gọi khi LLMRouter (qua hybridOrchestrator) không
 * khả dụng, hoặc khi cần một lệnh gọi đơn giản không qua pipeline đầy đủ.
 *
 * NÂNG CẤP v2:
 *  - SYSTEM_PROMPT mo rong va chi tiet hon
 *  - scoreAnswer() cải tiến: nhận biết câu trả lời né tránh, thiếu nội dung
 *  - buildPrompt(): thêm hướng dẫn output structure
 *  - targetScore(): ngưỡng chất lượng thực tế hơn
 *  - max_tokens tăng lên 2048 mặc định
 *  - callOpenAiCompatible: thêm temperature 0.3 để câu trả lời phong phú hơn
 *  - Model list cập nhật: ưu tiên model mới hơn và miễn phí hơn
 */

import { HISTORY_TURNS } from '../aiRouter.js';
import { sanitizePrompt } from './sanitizer.js';

type ChatRole = 'user' | 'assistant';

export interface SentinelHistoryItem {
  role: ChatRole;
  content: string;
}

export interface SentinelAskPayload {
  question: string;
  conversationHistory?: SentinelHistoryItem[];
  lastAssistantMessage?: string;
  findingContext?: Record<string, unknown>;
}

export interface SentinelAnswer {
  answer: string;
  confidence: number;
  providerUsed: string;
  modelUsed: string;
  providersTried: string[];
  warnings: string[];
  latencyMs: number;
  llmStatus: 'online' | 'offline';
  debug: SentinelDebugInfo;
}

export interface SentinelDebugInfo {
  providerUsed: string;
  modelUsed: string;
  latencyMs: number;
  confidence: number;
  providersTried: string[];
  warningCount: number;
  configuredProviderCount: number;
}

type ProviderId = 'groq' | 'gemini' | 'openrouter' | 'together' | 'huggingface';

interface ProviderProfile {
  id: ProviderId;
  apiKeyEnv: string;
  models: string[];
  endpoint: string;
  timeoutMs: number;
  openAiCompatible: boolean;
}

type AiFetch = (payload: {
  providerId: ProviderId;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}) => Promise<{ ok: boolean; status: number; body: string; headers?: Record<string, string>; error?: string }>;

interface CandidateAnswer {
  answer: string;
  confidence: number;
  providerUsed: string;
  modelUsed: string;
}

function buildDebugInfo(
  answer: Pick<SentinelAnswer, 'providerUsed' | 'modelUsed' | 'latencyMs' | 'confidence'>,
  providersTried: string[],
  warnings: string[],
  configuredProviderCount: number,
): SentinelDebugInfo {
  return {
    providerUsed: answer.providerUsed,
    modelUsed: answer.modelUsed,
    latencyMs: answer.latencyMs,
    confidence: answer.confidence,
    providersTried,
    warningCount: warnings.length,
    configuredProviderCount,
  };
}

// NÂNG CẤP: Groq đứng đầu (nhanh nhất + miễn phí), Gemini thứ 2
const DEFAULT_PROVIDER_ORDER: ProviderId[] = ['groq', 'gemini', 'openrouter', 'together', 'huggingface'];

// NÂNG CẤP: Cập nhật danh sách model với các model mới hơn, mạnh hơn
const DEFAULT_MODELS: Record<ProviderId, string[]> = {
  groq: [
    'llama-3.3-70b-versatile',
    'llama-3.1-8b-instant',
    'llama3-8b-8192',
  ],
  gemini: [
    'gemini-2.0-flash',
    'gemini-1.5-flash',
    'gemini-2.0-flash-lite',
  ],
  openrouter: [
    'meta-llama/llama-3.3-70b-instruct:free',
    'meta-llama/llama-3.1-8b-instruct:free',
    'mistralai/mistral-7b-instruct:free',
  ],
  together: [
    'meta-llama/Llama-3.3-70B-Instruct-Turbo-Free',
    'Qwen/Qwen2.5-72B-Instruct-Turbo',
  ],
  huggingface: [
    'Qwen/Qwen2.5-72B-Instruct',
    'mistralai/Mistral-7B-Instruct-v0.3',
  ],
};

// NÂNG CẤP: System prompt chi tiết hơn, hướng dẫn cụ thể hơn
const SYSTEM_PROMPT = [
  'Bạn là SENTINEL AI — chuyên gia bảo mật web và OWASP cấp cao, tích hợp trong SENTINEL OWASP Security Workbench.',
  '',
  '**QUY TẮC BẮT BUỘC:**',
  '1. Luôn trả lời bằng tiếng Việt chuyên nghiệp, tự nhiên, có dấu đầy đủ (trừ khi được yêu cầu khác). Không trả lời kiểu tiếng Việt không dấu.',
  '1b. Khi chuyển sang ý độc lập, phải xuống đoạn bằng một dòng trống. Không dồn nhiều câu không bổ trợ nhau vào cùng một đoạn dài.',
  '2. KHÔNG BAO GIỜ nói "Tôi không có đủ thông tin" hay "Câu hỏi này khá phức tạp" mà không giải thích.',
  '3. KHÔNG viết câu trả lời quá ngắn (dưới 150 từ) với câu hỏi kỹ thuật.',
  '4. Với câu hỏi về lỗ hổng: giải thích cơ chế + ví dụ PoC minh họa (không phải exploit thực tế) + cách khắc phục.',
  '5. Với câu hỏi so sánh: dùng bảng hoặc danh sách có cấu trúc rõ ràng.',
  '6. Với câu hỏi "là gì": định nghĩa + ví dụ thực tế + tầm quan trọng.',
  '7. Với câu hỏi "cách khắc phục": liệt kê từng bước, kèm code snippet nếu phù hợp.',
  '',
  '**DINH DANG:**',
  '- Dùng Markdown: ## tiêu đề, **in đậm**, `code`, danh sách -.',
  '- Emoji vừa phải: ⚠️ 🔴 ✅ 🛡️ để highlight ý chính.',
  '- Code snippet: dùng ```language ... ``` khi có ví dụ code.',
  '- Ưu tiên đoạn ngắn 1-2 câu. Mỗi bước/hành động nên nằm ở dòng riêng hoặc bullet riêng.',
  '',
  '**GIỚI HẠN AN TOÀN:**',
  '- KHÔNG cung cấp payload exploit có thể chạy ngay để tấn công thực tế.',
  '- Chỉ dùng PoC minh họa ngắn gọn để giáo dục phòng thủ.',
].join('\n');



function readEnv(name: string): string {
  switch (name) {
    case 'VITE_LLM_HISTORY_TURNS': return (import.meta.env.VITE_LLM_HISTORY_TURNS ?? '').trim();
    case 'VITE_GROQ_MODELS': return (import.meta.env.VITE_GROQ_MODELS ?? '').trim();
    case 'VITE_GEMINI_MODELS': return (import.meta.env.VITE_GEMINI_MODELS ?? '').trim();
    case 'VITE_OPENROUTER_MODELS': return (import.meta.env.VITE_OPENROUTER_MODELS ?? '').trim();
    case 'VITE_TOGETHER_MODELS': return (import.meta.env.VITE_TOGETHER_MODELS ?? '').trim();
    case 'VITE_HF_MODELS': return (import.meta.env.VITE_HF_MODELS ?? '').trim();
    default: return '';
  }
}

function getAiFetch(): AiFetch | null {
  return (globalThis as { owaspWorkbench?: { aiFetch?: AiFetch } }).owaspWorkbench?.aiFetch ?? null;
}

function isProviderAvailable(provider: ProviderProfile): boolean {
  return Boolean(getAiFetch() || readEnv(provider.apiKeyEnv));
}

function splitCsv(raw: string, fallback: string[]): string[] {
  const items = raw
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
  return items.length ? items : fallback;
}

function createProviderProfiles(): ProviderProfile[] {
  return [
    {
      id: 'groq',
      apiKeyEnv: 'GROQ_API_KEY',
      models: splitCsv(readEnv('VITE_GROQ_MODELS'), DEFAULT_MODELS.groq),
      endpoint: 'https://api.groq.com/openai/v1/chat/completions',
      timeoutMs: Number(readEnv('VITE_GROQ_TIMEOUT_MS') || '15000'),
      openAiCompatible: true,
    },
    {
      id: 'gemini',
      apiKeyEnv: 'GEMINI_API_KEY',
      models: splitCsv(readEnv('VITE_GEMINI_MODELS'), DEFAULT_MODELS.gemini),
      endpoint: 'https://generativelanguage.googleapis.com/v1beta/models',
      timeoutMs: Number(readEnv('VITE_GEMINI_TIMEOUT_MS') || '20000'),
      openAiCompatible: false,
    },
    {
      id: 'openrouter',
      apiKeyEnv: 'OPENROUTER_API_KEY',
      models: splitCsv(readEnv('VITE_OPENROUTER_MODELS'), DEFAULT_MODELS.openrouter),
      endpoint: 'https://openrouter.ai/api/v1/chat/completions',
      timeoutMs: Number(readEnv('VITE_OPENROUTER_TIMEOUT_MS') || '20000'),
      openAiCompatible: true,
    },
    {
      id: 'together',
      apiKeyEnv: 'TOGETHER_API_KEY',
      models: splitCsv(readEnv('VITE_TOGETHER_MODELS'), DEFAULT_MODELS.together),
      endpoint: 'https://api.together.xyz/v1/chat/completions',
      timeoutMs: Number(readEnv('VITE_TOGETHER_TIMEOUT_MS') || '20000'),
      openAiCompatible: true,
    },
    {
      id: 'huggingface',
      apiKeyEnv: 'HF_API_KEY',
      models: splitCsv(readEnv('VITE_HF_MODELS'), DEFAULT_MODELS.huggingface),
      endpoint: 'https://router.huggingface.co/novita/v3/openai/chat/completions',
      timeoutMs: Number(readEnv('VITE_HF_TIMEOUT_MS') || '30000'),
      openAiCompatible: true,
    },
  ];
}

function getProviderOrder(): ProviderId[] {
  const configured = splitCsv(readEnv('VITE_LLM_PROVIDER_PRIORITY'), DEFAULT_PROVIDER_ORDER);
  const valid = configured.filter((id): id is ProviderId =>
    id === 'groq' || id === 'gemini' || id === 'openrouter' || id === 'together' || id === 'huggingface',
  );
  return valid.length ? valid : DEFAULT_PROVIDER_ORDER;
}

// NÂNG CẤP: buildPrompt thêm hướng dẫn cấu trúc đầu ra dựa trên loại câu hỏi
function buildPrompt(payload: SentinelAskPayload): string {
  const sections: string[] = [];
  const q = payload.question.trim();

  sections.push(`User question:\n${q}`);

  if (payload.findingContext && Object.keys(payload.findingContext).length > 0) {
    sections.push(`Finding context (JSON):\n${JSON.stringify(payload.findingContext, null, 2)}`);
  }

  if (payload.lastAssistantMessage?.trim()) {
    sections.push(`Last assistant message:\n${payload.lastAssistantMessage.trim()}`);
  }

  if (payload.conversationHistory && payload.conversationHistory.length > 0) {
    const history = payload.conversationHistory
      .slice(-HISTORY_TURNS)
      .map(item => `${item.role.toUpperCase()}: ${item.content}`)
      .join('\n');
    sections.push(`Recent conversation:\n${history}`);
  }

  // Huong dan output theo loai cau hoi
  const qLower = q.toLowerCase();
  const instructions = ['Hướng dẫn trả lời:'];
  instructions.push('- Luôn dùng tiếng Việt có dấu đầy đủ trong toàn bộ câu trả lời.');

  if (qLower.includes('tai sao') || qLower.includes('why') || qLower.includes('co che')) {
    instructions.push(
      '- Giải thích NGUYÊN NHÂN và CƠ CHẾ kỹ thuật.',
      '- Bao gồm ví dụ minh họa thực tế.',
      '- Nêu rõ tác động và hậu quả.',
    );
  } else if (qLower.includes('so sanh') || qLower.includes('compare') || qLower.includes('khac nhau')) {
    instructions.push(
      '- Tạo bảng so sánh hoặc danh sách rõ ràng.',
      '- Nêu điểm giống nhau và khác nhau cụ thể.',
      '- Cho ví dụ khi nào dùng cái nào.',
    );
  } else if (qLower.includes('fix') || qLower.includes('khac phuc') || qLower.includes('phong')) {
    instructions.push(
      '- Liệt kê các bước khắc phục theo thứ tự ưu tiên.',
      '- Kèm code snippet minh họa nếu phù hợp.',
      '- Đề cập cả server-side và client-side nếu liên quan.',
    );
  } else if (qLower.includes('la gi') || qLower.includes('what is') || qLower.includes('dinh nghia')) {
    instructions.push(
      '- Định nghĩa rõ ràng, súc tích.',
      '- Ví dụ tấn công thực tế minh họa.',
      '- Cách phát hiện và phòng chống.',
    );
  } else {
    instructions.push(
      '- Trả lời đầy đủ, chi tiết, có cấu trúc.',
      '- Không kết thúc câu trả lời đột ngột.',
    );
  }

  instructions.push('- KHÔNG trả lời chung chung; phải có thông tin kỹ thuật cụ thể.');
  sections.push(instructions.join('\n'));

  return sections.join('\n\n');
}

function isUnsafeOffensiveRequest(question: string): boolean {
  const q = question.toLowerCase();
  const markers = [
    'reverse shell',
    'sqlmap command',
    'drop database',
    'hack website',
    'chi tiết tấn công',
    'executable exploit',
    'metasploit module',
    'create malware',
    'ransomware',
  ];
  return markers.some(m => q.includes(m));
}

function offensiveRefusal(): SentinelAnswer {
  const configuredProviderCount = createProviderProfiles()
    .filter(isProviderAvailable)
    .length;

  return {
    answer:
      '🛡️ Mình không thể hỗ trợ hướng dẫn tấn công hoặc cung cấp payload khai thác thực tế.\n\n' +
      'Nếu bạn muốn, mình có thể giúp theo hướng **phòng thủ**:\n' +
      '- Cách phát hiện lỗ hổng trong code\n' +
      '- Harden cấu hình server/ứng dụng\n' +
      '- Checklist bảo mật OWASP\n' +
      '- Review security best practices',
    confidence: 0.98,
    providerUsed: 'policy',
    modelUsed: 'policy',
    providersTried: ['policy'],
    warnings: ['Blocked offensive request'],
    latencyMs: 0,
    llmStatus: 'offline',
    debug: buildDebugInfo(
      { providerUsed: 'policy', modelUsed: 'policy', latencyMs: 0, confidence: 0.98 },
      ['policy'],
      ['Blocked offensive request'],
      configuredProviderCount,
    ),
  };
}

function normalizeWhitespace(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
}

// NÂNG CẤP: scoreAnswer cải tiến đáng kể
function scoreAnswer(question: string, answer: string): number {
  if (!answer.trim()) return 0;

  const text = answer.toLowerCase();
  const len  = answer.length;

  // Phát hiện câu trả lời né tránh -> điểm rất thấp
  const evasiveMarkers = [
    'tôi không có đủ thông tin',
    'câu hỏi này khá phức tạp',
    'toi khong co du thong tin',
    'cau hoi nay kha phuc tap',
    'i am an ai language model',
    'i cannot provide information',
    'as an ai, i',
    'i don\'t have',
    'không thể cung cấp thông tin',
    'khong the cung cap thong tin',
  ];
  if (evasiveMarkers.some(m => text.includes(m)) && len < 400) {
    return 0.10;
  }

  let score = 0.20;

  // Diem theo do dai
  if (len > 80)   score += 0.08;
  if (len > 200)  score += 0.10;
  if (len > 450)  score += 0.10;
  if (len > 800)  score += 0.08;
  if (len > 1200) score += 0.05;

  // Điểm nội dung bảo mật
  if (text.includes('owasp'))   score += 0.06;
  if (text.includes('cwe-'))    score += 0.05;
  if (text.includes('```'))     score += 0.08;
  if (text.includes('##'))      score += 0.04;
  if (text.includes('- '))      score += 0.03;
  if (
    text.includes('vi du') || text.includes('example') ||
    text.includes('minh hoa') || text.includes('chang han')
  ) score += 0.07;
  if (
    text.includes('buoc') || text.includes('step') ||
    text.includes('1.') || text.includes('1)')
  ) score += 0.05;
  if (
    text.includes('khac phuc') || text.includes('fix') ||
    text.includes('remediat') || text.includes('phong ngua') ||
    text.includes('ngan chan')
  ) score += 0.08;
  if (
    text.includes('co che') || text.includes('mechanism') ||
    text.includes('tai sao') || text.includes('nguyen nhan')
  ) score += 0.06;

  // Penalty
  if (text.includes('toi la ai') || text.includes('i am an ai language model')) score -= 0.15;
  if (text.includes('khong biet') && len < 120) score -= 0.10;
  if (question.trim().length < 15 && len > 800) score -= 0.05;
  if (text.includes('reverse shell') || text.includes('sqlmap')) score -= 0.25;

  return Math.max(0, Math.min(1, score));
}

// NÂNG CẤP: Ngưỡng chất lượng thực tế hơn
function targetScore(question: string): number {
  const q = question.toLowerCase();

  // Câu hỏi phức tạp cần câu trả lời chi tiết hơn
  if (q.includes('tai sao') || q.includes('why') || q.includes('co che') || q.includes('so sanh')) {
    return 0.52;
  }
  if (q.includes('la gi') || q.includes('what is') || q.includes('dinh nghia')) {
    return 0.46;
  }
  if (q.includes('cach fix') || q.includes('khac phuc') || q.includes('how to fix')) {
    return 0.50;
  }
  // Câu hỏi ngắn/chào hỏi
  if (question.trim().length < 20) {
    return 0.38;
  }
  return 0.48;
}

function buildHeaders(provider: ProviderProfile, apiKey: string): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${apiKey}`,
  };
  if (provider.id === 'openrouter') {
    headers['HTTP-Referer'] = 'https://sentinel.local';
    headers['X-Title'] = 'SENTINEL OWASP Assistant';
  }
  return headers;
}

interface OpenAiMessage {
  role: 'system' | 'user';
  content: string;
}

interface OpenAiLikeChoice {
  message?: {
    content?: string | Array<{ type?: string; text?: string }>;
  };
}

interface OpenAiLikeResponse {
  choices?: OpenAiLikeChoice[];
}

function extractOpenAiContent(data: OpenAiLikeResponse): string {
  const content = data.choices?.[0]?.message?.content;
  if (!content) return '';
  if (typeof content === 'string') return content;
  return content
    .map(item => (item.type === 'text' ? item.text ?? '' : ''))
    .join('')
    .trim();
}

async function callOpenAiCompatible(
  provider: ProviderProfile,
  apiKey: string,
  model: string,
  userPrompt: string,
): Promise<string> {
  const aiFetch = getAiFetch();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), provider.timeoutMs);

  // NÂNG CẤP: max_tokens tăng lên 2048 mặc định
  const body = {
    model,
    temperature: 0.3,
    max_tokens: Number(readEnv('VITE_LLM_MAX_OUTPUT_TOKENS') || '2048'),
    messages: [
      { role: 'system', content: SYSTEM_PROMPT } satisfies OpenAiMessage,
      { role: 'user',   content: userPrompt    } satisfies OpenAiMessage,
    ],
  };

  try {
    let data: OpenAiLikeResponse;
    if (aiFetch) {
      const response = await aiFetch({
        providerId: provider.id,
        url: provider.endpoint,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        timeoutMs: provider.timeoutMs,
      });
      if (!response.ok) {
        throw new Error(`${provider.id}:${model} HTTP ${response.status}`);
      }
      data = JSON.parse(response.body || '{}') as OpenAiLikeResponse;
    } else {
      const response = await fetch(provider.endpoint, {
        method: 'POST',
        headers: buildHeaders(provider, apiKey),
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`${provider.id}:${model} HTTP ${response.status}`);
      }
      data = await response.json() as OpenAiLikeResponse;
    }
    return normalizeWhitespace(extractOpenAiContent(data));
  } finally {
    clearTimeout(timer);
  }
}

interface GeminiApiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{ text?: string }>;
    };
  }>;
  error?: { message?: string; code?: number };
}

async function callGemini(
  provider: ProviderProfile,
  apiKey: string,
  model: string,
  userPrompt: string,
): Promise<string> {
  const aiFetch = getAiFetch();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), provider.timeoutMs);
  const url = aiFetch
    ? `${provider.endpoint}/${model}:generateContent`
    : `${provider.endpoint}/${model}:generateContent?key=${apiKey}`;
  const body = JSON.stringify({
    system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
    contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
    generationConfig: {
      temperature: 0.3,
      maxOutputTokens: Number(readEnv('VITE_LLM_MAX_OUTPUT_TOKENS') || '2048'),
    },
  });

  try {
    let data: GeminiApiResponse;
    if (aiFetch) {
      const response = await aiFetch({
        providerId: provider.id,
        url,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        timeoutMs: provider.timeoutMs,
      });

      if (!response.ok) {
        const errText = response.body;
        let detail = `HTTP ${response.status}`;
        try {
          const parsed = JSON.parse(errText) as GeminiApiResponse;
          if (parsed?.error?.message) detail = `HTTP ${response.status}: ${parsed.error.message}`;
        } catch { /* ignore */ }
        throw new Error(`gemini:${model} ${detail}`);
      }
      data = JSON.parse(response.body || '{}') as GeminiApiResponse;
    } else {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errText = await response.text().catch(() => '');
        let detail = `HTTP ${response.status}`;
        try {
          const parsed = JSON.parse(errText) as GeminiApiResponse;
          if (parsed?.error?.message) detail = `HTTP ${response.status}: ${parsed.error.message}`;
        } catch { /* ignore */ }
        throw new Error(`gemini:${model} ${detail}`);
      }
      data = await response.json() as GeminiApiResponse;
    }

    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
    return normalizeWhitespace(text);
  } finally {
    clearTimeout(timer);
  }
}

async function callProviderModel(
  provider: ProviderProfile,
  apiKey: string,
  model: string,
  userPrompt: string,
): Promise<string> {
  if (provider.id === 'gemini') {
    return callGemini(provider, apiKey, model, userPrompt);
  }
  // HuggingFace cung dung OpenAI-compatible endpoint moi
  return callOpenAiCompatible(provider, apiKey, model, userPrompt);
}

function fallbackAnswer(warnings: string[], latencyMs: number, tried: string[] = []): SentinelAnswer {
  const configuredProviderCount = createProviderProfiles()
    .filter(isProviderAvailable)
    .length;

  return {
    answer:
      '⚠️ **Các API AI hiện không khả dụng hoặc hết quota.**\n\n' +
      'Bạn vẫn có thể sử dụng knowledge base offline để hỏi về OWASP Top 10 và bảo mật web cơ bản.\n\n' +
      '**Để kích hoạt AI đầy đủ**, hãy kiểm tra API key trong file `.env`:\n' +
      '- `GROQ_API_KEY` - Groq (nhanh nhất, miễn phí tại console.groq.com)\n' +
      '- `GEMINI_API_KEY` - Google Gemini (aistudio.google.com)\n' +
      '- `OPENROUTER_API_KEY` - OpenRouter (openrouter.ai)\n' +
      '- `TOGETHER_API_KEY` - Together AI\n' +
      '- `HF_API_KEY` - HuggingFace',
    confidence: 0.20,
    providerUsed: 'fallback',
    modelUsed: 'fallback',
    providersTried: tried,
    warnings,
    latencyMs,
    llmStatus: 'offline',
    debug: buildDebugInfo(
      { providerUsed: 'fallback', modelUsed: 'fallback', latencyMs, confidence: 0.20 },
      tried,
      warnings,
      configuredProviderCount,
    ),
  };
}

export async function askSentinelAI(payload: SentinelAskPayload): Promise<SentinelAnswer> {
  const start    = Date.now();
  const question = payload.question.trim();
  const providerProfiles = createProviderProfiles();
  const configuredProviderCount = providerProfiles
    .filter(isProviderAvailable)
    .length;

  if (!question) {
    const latencyMs = Date.now() - start;
    return {
    answer: 'Bạn hãy nhập câu hỏi cụ thể hơn để mình hỗ trợ chính xác nhé.',
      confidence: 0.20,
      providerUsed: 'validation',
      modelUsed: 'validation',
      providersTried: ['validation'],
      warnings: ['Empty question'],
      latencyMs,
      llmStatus: 'offline',
      debug: buildDebugInfo(
        { providerUsed: 'validation', modelUsed: 'validation', latencyMs, confidence: 0.20 },
        ['validation'],
        ['Empty question'],
        configuredProviderCount,
      ),
    };
  }

  if (isUnsafeOffensiveRequest(question)) {
    const blocked  = offensiveRefusal();
    const latencyMs = Date.now() - start;
    return {
      ...blocked,
      latencyMs,
      llmStatus: 'offline',
      debug: buildDebugInfo(
        { providerUsed: 'policy', modelUsed: 'policy', latencyMs, confidence: blocked.confidence },
        blocked.providersTried,
        blocked.warnings,
        configuredProviderCount,
      ),
    };
  }

  const warnings: string[] = [];
  const tried: string[]    = [];
  const providerOrder      = getProviderOrder();
  const profileById        = new Map(providerProfiles.map(p => [p.id, p]));
  const requestedMaxInputTokens = Number(readEnv('VITE_LLM_MAX_INPUT_TOKENS') || '2500');
  const enrichedPrompt     = buildPrompt(payload);
  const sanitized          = sanitizePrompt(enrichedPrompt, requestedMaxInputTokens);
  warnings.push(...sanitized.warnings);

  let best: CandidateAnswer | null = null;
  const minScore = targetScore(question);

  for (const providerId of providerOrder) {
    const provider = profileById.get(providerId);
    if (!provider) continue;

    const apiKey = readEnv(provider.apiKeyEnv);
    if (!apiKey && !getAiFetch()) {
      warnings.push(`${provider.id} skipped (missing ${provider.apiKeyEnv})`);
      continue;
    }

    for (const model of provider.models) {
      const attemptId = `${provider.id}:${model}`;
      tried.push(attemptId);
      try {
        const answer     = await callProviderModel(provider, apiKey, model, sanitized.prompt);
        const confidence = scoreAnswer(question, answer);

        if (!best || confidence > best.confidence) {
          best = { answer, confidence, providerUsed: provider.id, modelUsed: model };
        }

        // Du tot -> tra ve ngay
        if (confidence >= minScore) {
          const latencyMs = Date.now() - start;
          return {
            answer,
            confidence,
            providerUsed: provider.id,
            modelUsed: model,
            providersTried: tried,
            warnings,
            latencyMs,
            llmStatus: 'online',
            debug: buildDebugInfo(
              { providerUsed: provider.id, modelUsed: model, latencyMs, confidence },
              tried,
              warnings,
              configuredProviderCount,
            ),
          };
        }
      } catch (error) {
        warnings.push(`${attemptId} failed: ${(error as Error).message}`);
      }
    }
  }

  // Tra ve best-effort neu co
  if (best) {
    warnings.push('Returned best-effort answer (below quality threshold)');
    const latencyMs = Date.now() - start;
    return {
      answer: best.answer,
      confidence: best.confidence,
      providerUsed: best.providerUsed,
      modelUsed: best.modelUsed,
      providersTried: tried,
      warnings,
      latencyMs,
      llmStatus: 'online',
      debug: buildDebugInfo(
        {
          providerUsed: best.providerUsed,
          modelUsed: best.modelUsed,
          latencyMs,
          confidence: best.confidence,
        },
        tried,
        warnings,
        configuredProviderCount,
      ),
    };
  }

  return fallbackAnswer(warnings, Date.now() - start, tried);
}
