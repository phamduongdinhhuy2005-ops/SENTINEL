/**
 * LLM Router — Điều phối đa nhà cung cấp (Multi-Provider Orchestrator)
 *
 * Lớp thứ 2 của hệ thống AI kết hợp.
 * Trách nhiệm:
 *  - Chọn nhà cung cấp khỏe nhất (tốt nhất) hiện có
 *  - Thử lại với thuật toán backoff đối với các lỗi tạm thời
 *  - Kiểm tra chéo câu trả lời từ hai nhà cung cấp khi độ tin cậy thấp
 *  - Lưu cache các phản hồi với TTL có thể cấu hình được
 *  - Trả về đối tượng AiResponse chuẩn mực
 *
 * NÂNG CẤP v2:
 *  - System prompt mở rộng, hướng dẫn chi tiết hơn để trả lời câu hỏi khó
 *  - Prompt builder thêm explicit output structure cho từng loại câu hỏi
 *  - Token limits tăng đáng kể theo profile câu hỏi
 *  - Confidence estimation cải tiến: nhận biết câu trả lời trốn tránh
 *  - queryWithConsensus: chọn câu trả lời dài nhất+chất lượng nhất thay vì chỉ overlap
 */

import { AiQueryPayload, HISTORY_TURNS } from '../aiRouter.js';
import { retrieveKnowledgeContext } from '../contextRetriever.js';
import { assessAnswerQuality } from './answerQuality.js';
import { AnswerCache } from './answerCache.js';
import { crossCheck } from './crossChecker.js';
import { ProviderMetricsTracker } from './metricsTracker.js';
import { withRetry } from './retry.js';
import { sanitizePrompt } from './sanitizer.js';
import {
  AiResponse,
  DEFAULT_ROUTER_CONFIG,
  LLMProvider,
  ProviderError,
  RouterConfig,
} from './types';

// ── System prompt nâng cấp ─────────────────────────────────────────────────────────
// NÂNG CẤP: Thêm hướng dẫn cấu trúc câu trả lời và phong cách rõ ràng hơn
const SECURITY_SYSTEM_PROMPT = `Bạn là SENTINEL AI — chuyên gia bảo mật web và OWASP cấp cao, tích hợp trong SENTINEL OWASP Security Workbench.

**XỬ LÝ NGỮ CẢNH (CONTEXT HANDLING):**
- BẠN PHẢI đọc kỹ "Finding context (JSON)" (nếu được cung cấp) để phân tích trực tiếp vào vấn đề người dùng đang gặp phải. Hãy nhắc đến file code cụ thể, dòng lỗi, hoặc URL/tham số được đề cập trong JSON.
- Đọc "Recent conversation" để giữ liền mạch trò chuyện (ví dụ người dùng hỏi "vậy cách fix nó là gì?", "nó" ở đây lấy từ lịch sử).
- Nếu có "Structured remediation plan", PHẢI dùng nó để nêu file/URL, khoảng dòng, đoạn cần sửa từ đâu sang đâu. Nếu thiếu line/snippet thì nói rõ scanner chưa xác định được dòng chính xác.

**QUY TẮC BẮT BUỘC:**
1. LUÔN LUÔN trả lời bằng tiếng Việt chuyên nghiệp, tự nhiên và sát với ngữ cảnh.
1a. Tiếng Việt PHẢI có dấu đầy đủ. Không được trả lời kiểu không dấu như "lo hong", "bao mat", "cach khac phuc".
1b. Khi chuyển sang ý độc lập, PHẢI xuống đoạn bằng một dòng trống. Không dồn nhiều câu không bổ trợ nhau vào cùng một đoạn dài.
2. KHÔNG BAO GIỜ trả lời chung chung. Nếu có "Finding context", phải dựa vào nó để phân tích thay vì giải thích lý thuyết suông.
3. Với câu hỏi kỹ thuật: PHẢI giải thích cơ chế hoạt động, ví dụ tấn công minh họa (PoC giáo dục), và các bước khắc phục cụ thể.
4. Với câu hỏi "cách fix": PHẢI cho đủ bước, kèm code snippet sửa lỗi nếu có thể.
5. KHÔNG cung cấp payload exploit thực tế có thể chạy để tấn công; chỉ dùng PoC minh họa giáo dục.
6. Mọi đề xuất sửa code/config phải kèm cảnh báo rằng đây là gợi ý tham khảo, cần rà soát và kiểm thử kỹ trước khi áp dụng.

**ĐỊNH DẠNG:**
- Dùng Markdown: tiêu đề ##/###, danh sách -, **in đậm** cho thuật ngữ quan trọng.
- Dùng \`code block\` cho tên hàm, URL, tham số, snippet code.
- Emoji vừa phải để highlight ý chính (⚠️ 🔴 ✅ 🛡️).
- Câu trả lời chi tiết nhưng đi thẳng vào trọng tâm, tránh dài dòng không cần thiết.
- Ưu tiên đoạn ngắn 1-2 câu. Mỗi bước/hành động nên nằm ở dòng riêng hoặc bullet riêng.

**THÔNG TIN VỀ DỰ ÁN SENTINEL V2 (THÔNG TIN NỀN TẢNG CỦA BẠN):**
- SENTINEL v2 là một nền tảng phân tích bảo mật (Security Workbench) toàn diện, chuyên rà quét và quản lý lỗ hổng ứng dụng.
- Cấu trúc hệ thống có các tính năng cốt lõi:
  + **URL Scan (DAST)**: Quét động các lỗ hổng bảo mật trên ứng dụng web đang chạy.
  + **Project Scan / Source Code Analysis (SAST)**: Phân tích mã nguồn tĩnh để tìm ra các vi phạm bảo mật từ sớm.
  + **Findings**: Bảng điều khiển quản lý toàn bộ các lỗ hổng phát hiện được (phân loại theo mức độ Critical, High, Medium, Low và OWASP Top 10).
  + **Reports**: Tính năng xuất báo cáo kiểm định bảo mật chuyên nghiệp (PDF, HTML, JSON) dành cho khách hàng hoặc đội Dev.
  + **AI Orchestration**: Đây chính là BẠN! Một mạng lưới AI đa mô hình (Multi-Provider: Groq, Gemini, OpenRouter, Together, HuggingFace) giúp phân tích tự động, giải thích nguyên nhân và đưa ra giải pháp sửa lỗi cho từng lỗ hổng một cách siêu tốc và thông minh.
- Nếu người dùng hỏi "Dự án này làm gì?", "Sentinel là gì?", hoặc "Bạn có thể làm gì?", BẠN PHẢI sử dụng các thông tin trên để trả lời đầy đủ, chi tiết, tự hào về khả năng bảo mật và phân tích mã nguồn của nền tảng này.

**KIẾN TRÚC & THUẬT TOÁN (DÙNG ĐỂ TRẢ LỜI CÁC CÂU HỎI CHUYÊN SÂU VỀ DỰ ÁN):**
- **Luồng hoạt động (Workflow)**: Người dùng cấu hình mục tiêu (URL hoặc Source Code) -> Scanner engine thực hiện phân tích -> Phát hiện lỗ hổng (Findings) -> AI phân tích ngữ cảnh (Context) & hướng dẫn sửa lỗi (Remediation) -> Xuất báo cáo (Reports).
- **Thuật toán rà quét (Scanner Algorithms)**:
  + *DAST (URL Scan)*: Gửi các HTTP request chứa payload giả lập tấn công (như \`<script>\`, \`' OR 1=1\`) vào parameter/header, sau đó phân tích response body/status để xác định lỗ hổng (XSS, SQLi, SSRF...).
  + *SAST (Code Scan)*: Quét chuỗi (Regex) và phân tích cây cú pháp (AST) để tìm hàm nguy hiểm (như \`eval()\`), secret key bị lộ, hoặc lỗi logic trong code.
- **Hệ thống AI Orchestration (Lõi của bạn)**:
  + *Circuit Breaker & Fallback*: Tự động theo dõi sức khỏe API. Nếu Provider A lỗi (Timeout, 429 Rate Limit, 404), tự động chuyển qua Provider B mà người dùng không hề hay biết.
  + *Cross-Checking (Kiểm tra chéo)*: Với các câu hỏi học thuật phức tạp, Router gọi nhiều LLM cùng lúc, dùng thuật toán **Jaccard Similarity** đo lường sự đồng thuận giữa các đáp án, tính toán Confidence Score dựa trên độ dài và chất lượng từ khóa bảo mật, từ đó chọn câu trả lời xuất sắc nhất.

**PHẠM VI CHUYÊN MÔN:**
- Lỗ hổng OWASP Top 10 (2021): A01–A10 bao gồm XSS, SQLi, CSRF, IDOR, SSRF, SSTI, Path Traversal, JWT, OAuth, CORS, CSP, Rate Limiting, Supply Chain, Deserialization, v.v.
- Security hardening, DevSecOps, CI/CD Security.`;



// ── Phân loại câu hỏi ─────────────────────────────────────────────────────────────
interface ScoredProvider {
  provider: LLMProvider;
  score: number;
}

interface CandidateAnswer {
  providerId: string;
  answer: string;
  quality: number;
}

// NÂNG CẤP: Thêm profile 'complex' cho câu hỏi nhiều chiều
type QuestionProfile = 'greeting' | 'short' | 'security' | 'complex' | 'academic';

function normalizeForMatch(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\w\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const ACADEMIC_TERMS = [
  'OWASP', 'CWE', 'CVSS', 'RFC', 'NIST', 'ISO',
  'tiêu chuẩn', 'chuẩn', 'học thuật', 'nghiên cứu', 'bài báo', 'tài liệu',
  'trích dẫn', 'tham khảo', 'phương pháp', 'thuật toán', 'benchmark', 'formal',
  'chuyên sâu', 'tổng quan', 'khảo sát', 'so sánh', 'đánh giá', 'phân tích',
  'kiến trúc', 'mô hình', 'thực nghiệm', 'lý thuyết', 'định nghĩa', 'khái niệm',
];

const SECURITY_TERMS = [
  'SENTINEL', 'bảo mật', 'an toàn thông tin', 'lỗ hổng', 'tấn công',
  'xác thực', 'ủy quyền', 'mã hóa', 'chữ ký', 'chứng chỉ',
  'OWASP', 'XSS', 'SQL Injection', 'SQLi', 'CSRF', 'SSRF', 'SSTI',
  'IDOR', 'JWT', 'OAuth', 'token', 'session', 'cookie', 'header',
  'CORS', 'CSP', 'HSTS', 'SRI', 'rate limit', 'brute force',
  'vulnerability', 'threat', 'risk', 'scan', 'quét', 'finding',
];

// NÂNG CẤP: Từ khóa câu hỏi phức tạp (nhiều chiều)
const COMPLEX_TERMS = [
  'tại sao', 'why', 'so sánh', 'compare', 'khác nhau', 'difference',
  'cách hoạt động', 'how does', 'mechanism', 'cơ chế', 'chi tiết',
  'giải thích', 'explain', 'phân tích', 'analyze', 'ví dụ', 'example',
  'khi nào', 'when', 'như thế nào', 'how', 'tại sao lại', 'reason',
  'ảnh hưởng', 'impact', 'hậu quả', 'consequence', 'nguy hiểm', 'risk',
];

const ACADEMIC_TERMS_NORM = ACADEMIC_TERMS.map(normalizeForMatch);
const SECURITY_TERMS_NORM = SECURITY_TERMS.map(normalizeForMatch);
const COMPLEX_TERMS_NORM  = COMPLEX_TERMS.map(normalizeForMatch);

const ACADEMIC_MIN_WORDS = 14;
const COMPLEX_MIN_WORDS  = 8;

// NÂNG CẤP: Token limits tăng đáng kể cho mỗi profile
const TOKEN_CAPS: Record<QuestionProfile, { min: number; max: number }> = {
  greeting: { min: 200,  max: 400  },
  short:    { min: 600,  max: 1200 },
  security: { min: 1000, max: 2048 },
  complex:  { min: 1200, max: 2048 },
  academic: { min: 1500, max: 2048 },
};

function hasAnyTerm(text: string, terms: string[]): boolean {
  return terms.some(t => text.includes(t));
}

// NÂNG CẤP: Prompt builder thêm hướng dẫn output structure theo profile
function buildContextAwarePrompt(payload: AiQueryPayload, profile: QuestionProfile): string {
  const sections: string[] = [];
  const retrieved = retrieveKnowledgeContext(payload);
  sections.push(`User question:\n${payload.question.trim()}`);

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

  if (retrieved.items.length > 0) {
    sections.push(
      `Trusted SENTINEL context. Use these as grounding facts. If the context is insufficient, state what is missing instead of guessing.\n${retrieved.summary}`,
    );
  }

  // NÂNG CẤP: Hướng dẫn output cụ thể theo profile và bám sát ngữ cảnh
  const instructions: string[] = ['Hướng dẫn trả lời:'];

  if (payload.findingContext && Object.keys(payload.findingContext).length > 0) {
    instructions.push('- BẠN ĐANG PHÂN TÍCH MỘT LỖ HỔNG CỤ THỂ. Bắt buộc phải sử dụng dữ liệu trong "Finding context (JSON)" (tên file, dòng code, payload, rule name) để chỉ đích danh lỗi và cách sửa trực tiếp vào file đó.');
    instructions.push('- Phần đề xuất vá lỗi phải nêu: file/URL cần kiểm tra, khoảng dòng nếu có, sửa từ pattern/đoạn nào sang hướng sửa nào, cách verify sau khi sửa, và disclaimer tham khảo.');
  }

  instructions.push('- Luôn viết tiếng Việt có dấu đầy đủ trong phần giải thích, cảnh báo và hướng dẫn khắc phục.');

  if (payload.conversationHistory && payload.conversationHistory.length > 0) {
    instructions.push('- Tham khảo "Recent conversation" để giữ liền mạch ngữ cảnh (hiểu đúng các từ "nó", "file này", "lỗi trên" đang ám chỉ điều gì).');
  }

  if (profile === 'academic' || profile === 'complex') {
    instructions.push(
      '- Trả lời CHI TIẾT, có cấu trúc rõ ràng với các mục ## hoặc ### nếu cần.',
      '- Giải thích cơ chế kỹ thuật, nguyên nhân gốc rễ (root cause).',
      '- Cung cấp ít nhất 1 ví dụ minh họa thực tế.',
      '- Liệt kê đầy đủ các bước khắc phục / phòng chống.',
      '- KHÔNG kết thúc câu trả lời quá sớm; hoàn thành đủ ý trước khi dừng.',
    );
  } else if (profile === 'security') {
    instructions.push(
      '- Trả lời đầy đủ, tự nhiên, thấu hiểu ngữ cảnh.',
      '- Nếu câu hỏi về lỗ hổng: giải thích cơ chế + cách khai thác (PoC giáo dục) + cách fix.',
      '- Nếu câu hỏi về cách fix: liệt kê từng bước cụ thể, kèm code nếu phù hợp.',
    );
  } else {
    instructions.push(
      '- Trả lời trực tiếp, rõ ràng, tự nhiên.',
      '- Đủ thông tin để người dùng hiểu ngay.',
    );
  }

  sections.push(instructions.join('\n'));

  return sections.join('\n\n');
}

function buildConfiguredProviderReader(): (() => Promise<Set<string> | null>) {
  let cache: { expiresAt: number; value: Set<string> | null } | null = null;

  return async () => {
    const now = Date.now();
    if (cache && cache.expiresAt > now) return cache.value;

    const bridge = (globalThis as {
      owaspWorkbench?: {
        getAIProviders?: () => Promise<Record<string, { configured: boolean }>>;
      };
    }).owaspWorkbench;

    if (!bridge?.getAIProviders) {
      cache = { expiresAt: now + 5_000, value: null };
      return null;
    }

    try {
      const providers = await bridge.getAIProviders();
      const configured = new Set(
        Object.entries(providers)
          .filter(([, status]) => status.configured)
          .map(([id]) => id),
      );
      cache = { expiresAt: now + 10_000, value: configured };
      return configured;
    } catch {
      cache = { expiresAt: now + 5_000, value: null };
      return null;
    }
  };
}

const readConfiguredProviders = buildConfiguredProviderReader();

export class LLMRouter {
  private readonly providers: Map<string, LLMProvider>;
  private readonly metrics: ProviderMetricsTracker;
  private readonly cache: AnswerCache;
  private readonly config: RouterConfig;

  constructor(
    providers: LLMProvider[],
    metrics: ProviderMetricsTracker,
    config: Partial<RouterConfig> = {},
  ) {
    this.config    = { ...DEFAULT_ROUTER_CONFIG, ...config };
    this.metrics   = metrics;
    this.cache     = new AnswerCache(this.config.cacheTtlMs, this.config.cacheMaxSize);
    this.providers = new Map(providers.map(p => [p.id, p]));
  }

  // ── Lựa chọn nhà cung cấp ──────────────────────────────────────────────────────

  private async rankProviders(): Promise<ScoredProvider[]> {
    const w = this.config.selectionWeights;
    const ranked: ScoredProvider[] = [];
    const configuredProviders = await readConfiguredProviders();

    const prioritised = this.config.providerPriority
      .map(id => this.providers.get(id))
      .filter((p): p is LLMProvider => p !== undefined);

    for (const p of this.providers.values()) {
      if (!prioritised.includes(p)) prioritised.push(p);
    }

    for (const provider of prioritised) {
      if (configuredProviders && !configuredProviders.has(provider.id)) continue;
      if (this.metrics.isCircuitOpen(provider.id)) continue;

      const health = await provider.health();
      if (health.circuitOpen) continue;

      const quota = await provider.estimateCostOrQuota();
      const normalizedQuota = quota === 0 ? 0 : Math.min(1, quota / 15_000);

      const latencyScore  = Math.max(0, 1 - health.avgLatencyMs / 15_000);
      const errorPenalty  = health.recentErrorRate;

      const score =
        w.health    * health.score      +
        w.quota     * normalizedQuota   +
        w.latency   * latencyScore      +
        w.errorRate * (1 - errorPenalty);

      ranked.push({ provider, score });
    }

    return ranked.sort((a, b) => b.score - a.score);
  }

  // ── Gọi một nhà cung cấp với cơ chế retry ────────────────────────────────────────
  private async callProvider(
    provider: LLMProvider,
    prompt: string,
    maxTokens: number,
    options?: { signal?: AbortSignal; onToken?: (token: string) => void; stream?: boolean },
  ): Promise<string> {
    return withRetry(
      () => provider.generate(prompt, {
        systemPrompt:  SECURITY_SYSTEM_PROMPT,
        maxTokens,
        timeoutMs:     this.config.timeoutMs,
        signal:        options?.signal,
        onToken:       options?.onToken,
        stream:        options?.stream,
      }),
      {
        maxRetries:   this.config.maxRetries,
        baseDelayMs:  this.config.retryBaseDelayMs,
        maxDelayMs:   this.config.retryMaxDelayMs,
        shouldRetry:  (err) => {
          const kind = (err as ProviderError).kind;
          return kind === 'server_error' || kind === 'timeout' || kind === 'rate_limit';
        },
      },
    );
  }

  // ── NÂNG CẤP: Ước lượng độ tin cậy cải tiến ────────────────────────────────────
  // Phát hiện câu trả lời trốn tránh hoặc quá ngắn
  private estimateConfidence(answer: string, question?: string): number {
    if (!answer || answer.trim().length < 30) return 0.10;

    const text = answer.toLowerCase();

    // Phát hiện câu trả lời né tránh / vô nghĩa
    const evasiveMarkers = [
      'tôi không có đủ thông tin',
      'câu hỏi này khá phức tạp',
      'i am an ai language model',
      'i cannot provide',
      'as an ai',
      'tôi không thể',
      'tôi xin lỗi',
      'không thể trả lời',
    ];
    if (evasiveMarkers.some(m => text.includes(m)) && answer.length < 300) {
      return 0.15;
    }

    // Scoring dựa trên độ dài + nội dung
    let score = 0.30;
    const len = answer.length;

    if (len > 100)  score += 0.10;
    if (len > 300)  score += 0.12;
    if (len > 600)  score += 0.10;
    if (len > 1000) score += 0.08;

    // Bonus cho nội dung kỹ thuật bảo mật
    if (text.includes('owasp'))        score += 0.06;
    if (text.includes('cwe-'))         score += 0.05;
    if (text.includes('```'))          score += 0.08;
    if (text.includes('##'))           score += 0.04;
    if (text.includes('ví dụ') || text.includes('example')) score += 0.06;
    if (text.includes('bước') || text.includes('step'))     score += 0.06;
    if (
      text.includes('khắc phục') || text.includes('fix') ||
      text.includes('remediat') || text.includes('phòng')
    ) score += 0.07;

    // Penalty nếu câu trả lời quá ngắn so với câu hỏi phức tạp
    if (question && question.length > 60 && len < 200) score -= 0.15;

    return Math.max(0.10, Math.min(0.95, score));
  }

  private getQuestionProfile(question: string): QuestionProfile {
    const norm = normalizeForMatch(question);
    if (!norm) return 'short';

    const hasAcademic = hasAnyTerm(norm, ACADEMIC_TERMS_NORM);
    const hasSecurity = hasAnyTerm(norm, SECURITY_TERMS_NORM);
    const hasComplex  = hasAnyTerm(norm, COMPLEX_TERMS_NORM);
    const wordCount   = norm.split(' ').filter(Boolean).length;
    const isShort     = wordCount <= 4;

    // Chào hỏi không cần nhiều token
    if (isShort && !hasSecurity && !hasAcademic && !hasComplex) return 'greeting';

    // Academic: có từ học thuật hoặc câu hỏi bảo mật dài
    if (hasAcademic || (hasSecurity && wordCount >= ACADEMIC_MIN_WORDS)) return 'academic';

    // Complex: câu hỏi phức tạp nhiều chiều
    if (hasComplex && wordCount >= COMPLEX_MIN_WORDS) return 'complex';

    // Security: câu hỏi bảo mật thông thường
    if (hasSecurity) return 'security';

    return 'short';
  }

  private selectMaxOutputTokens(profile: QuestionProfile): number {
    const cap = TOKEN_CAPS[profile];
    const configured = this.config.maxOutputTokens;
    return Math.max(cap.min, Math.min(cap.max, configured));
  }

  private tokenizeForSimilarity(text: string): Set<string> {
    return new Set(
      text
        .toLowerCase()
        .replace(/[^\w\s]/g, ' ')
        .split(/\s+/)
        .filter(w => w.length >= 3),
    );
  }

  private jaccardSimilarity(a: Set<string>, b: Set<string>): number {
    if (a.size === 0 && b.size === 0) return 1;
    let intersection = 0;
    for (const t of a) if (b.has(t)) intersection++;
    const union = a.size + b.size - intersection;
    return union === 0 ? 0 : intersection / union;
  }

  // NÂNG CẤP: pickConsensus ưu tiên câu trả lời dài + chất lượng cao hơn
  private pickConsensus(answers: CandidateAnswer[]) {
    if (answers.length === 1) {
      return { chosen: answers[0], agreement: 1, confidence: answers[0].quality };
    }

    const tokens = answers.map(a => this.tokenizeForSimilarity(a.answer));
    let bestIdx   = 0;
    let bestScore = -1;
    let bestAgreement = 0;

    for (let i = 0; i < answers.length; i++) {
      let sum = 0;
      for (let j = 0; j < answers.length; j++) {
        if (i === j) continue;
        sum += this.jaccardSimilarity(tokens[i], tokens[j]);
      }
      const avg = sum / Math.max(1, answers.length - 1);

      // NÂNG CẤP: Kết hợp overlap + quality score + length bonus
      const lengthBonus = Math.min(0.15, answers[i].answer.length / 5000);
      const score = avg * 0.5 + answers[i].quality * 0.35 + lengthBonus * 0.15;

      if (score > bestScore) {
        bestScore     = score;
        bestIdx       = i;
        bestAgreement = avg;
      }
    }

    const confidence = Math.min(0.92, answers[bestIdx].quality * 0.7 + bestAgreement * 0.3);
    return { chosen: answers[bestIdx], agreement: bestAgreement, confidence };
  }

  private async queryWithConsensus(
    question: string,
    ranked: ScoredProvider[],
    prompt: string,
    warnings: string[],
    start: number,
    maxTokens: number,
    cacheContext?: string,
    signal?: AbortSignal,
  ): Promise<AiResponse> {
    const providersTried: string[] = [];
    const candidates = ranked.slice(0, Math.min(ranked.length, 3));

    const settled = await Promise.allSettled(
      candidates.map(c => this.callProvider(c.provider, prompt, maxTokens, { signal })),
    );

    const answers: CandidateAnswer[] = [];
    settled.forEach((res, idx) => {
      const providerId = candidates[idx].provider.id;
      providersTried.push(providerId);
      if (res.status === 'fulfilled') {
        const text = res.value?.trim() ?? '';
        if (text) {
          answers.push({
            providerId,
            answer: text,
            quality: this.estimateConfidence(text, question),
          });
        } else {
          warnings.push(`${providerId} returned empty answer`);
        }
      } else {
        const reason = res.reason instanceof Error ? res.reason.message : String(res.reason);
        warnings.push(`${providerId} failed: ${reason}`);
      }
    });

    if (answers.length === 0) {
      return this.buildErrorResponse('All providers failed', providersTried, start, warnings);
    }

    if (answers.length === 1) {
      this.cache.set(question, {
        answer:       answers[0].answer,
        confidence:   answers[0].quality,
        providerUsed: answers[0].providerId,
        crossChecked: false,
      }, cacheContext);
      return {
        answer:         answers[0].answer,
        confidence:     answers[0].quality,
        providersTried,
        providerUsed:   answers[0].providerId,
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'llm',
      };
    }

    const consensus   = this.pickConsensus(answers);
    const lowAgreement = consensus.agreement < 0.15;
    if (lowAgreement) warnings.push('Low agreement across providers; using highest quality answer');

    this.cache.set(question, {
      answer:       consensus.chosen.answer,
      confidence:   consensus.confidence,
      providerUsed: consensus.chosen.providerId,
      crossChecked: true,
    }, cacheContext);

    return {
      answer:         consensus.chosen.answer,
      confidence:     consensus.confidence,
      providersTried,
      providerUsed:   consensus.chosen.providerId,
      crossChecked:   true,
      warnings,
      latencyMs:      Date.now() - start,
      source:         'synthesized',
    };
  }

  private applyQualityGate(response: AiResponse, payload: AiQueryPayload): AiResponse {
    if (response.source === 'knowledge_base') return response;

    const retrieved = retrieveKnowledgeContext(payload);
    const quality = assessAnswerQuality(response.answer, payload, retrieved);
    const warnings = [
      ...response.warnings,
      `Kiểm tra grounding ${quality.ok ? 'đạt' : 'cần rà soát'} (${quality.score.toFixed(2)})`,
      ...quality.warnings.map(w => `Quality: ${w}`),
      ...(retrieved.sourceIds.length ? [`Context sources: ${retrieved.sourceIds.join(', ')}`] : []),
    ];

    if (quality.ok) {
      return {
        ...response,
        confidence: Math.min(0.95, Math.max(response.confidence, quality.score)),
        warnings,
      };
    }

    const reliabilityNote =
      '\n\n---\n**Ghi chú độ tin cậy:** Câu trả lời này chưa bám đủ mạnh vào dữ liệu hiện có của SENTINEL. Hãy ưu tiên kiểm tra lại bằng chứng/phát hiện và dùng phần khắc phục như hướng dẫn tham khảo.';

    return {
      ...response,
      answer: response.answer.includes('Ghi chú độ tin cậy')
        ? response.answer
        : `${response.answer}${reliabilityNote}`,
      confidence: Math.min(response.confidence, quality.score),
      warnings,
    };
  }

  // ── Phương thức truy vấn chính ───────────────────────────────────────────────────────

  async query(payload: AiQueryPayload): Promise<AiResponse> {
    const question = payload.question;
    const start    = Date.now();
    const cacheContext = this.buildCacheContext(payload);

    // ── 0. Cache hit ──────────────────────────────────────────────────────────
    const cached = this.cache.get(question, cacheContext);
    if (cached) {
      return this.applyQualityGate({
        answer:         cached.answer,
        confidence:     cached.confidence,
        providersTried: [cached.providerUsed],
        providerUsed:   cached.providerUsed,
        crossChecked:   cached.crossChecked,
        warnings:       ['Served from cache'],
        latencyMs:      Date.now() - start,
        source:         'llm',
      }, payload);
    }

    // ── 1. Phân loại câu hỏi & build prompt ──────────────────────────────────
    const profile   = this.getQuestionProfile(question);
    const maxTokens = this.selectMaxOutputTokens(profile);

    const rawPrompt = buildContextAwarePrompt(payload, profile);
    const { prompt, warnings } = sanitizePrompt(rawPrompt, this.config.maxInputTokens);
    const providersTried: string[] = [];

    // ── 2. Xếp hạng nhà cung cấp ─────────────────────────────────────────────
    const ranked = await this.rankProviders();
    if (ranked.length === 0) {
      return this.buildErrorResponse('No LLM providers available', providersTried, start, warnings);
    }

    // ── 3. Academic & Complex: dùng consensus từ nhiều provider ───────────────
    if (profile === 'academic' || profile === 'complex') {
      const response = await this.queryWithConsensus(question, ranked, prompt, warnings, start, maxTokens, cacheContext, payload.signal);
      return this.applyQualityGate(response, payload);
    }

    // ── 4. Security & Short: gọi tuần tự, lấy provider tốt nhất ──────────────
    let primaryAnswer   = '';
    let primaryProvider = '';
    let primaryError: unknown = null;

    const canStream = Boolean(payload.onToken) && !this.config.crossCheckEnabled;
    const streamOptions = canStream ? { onToken: payload.onToken, stream: true, signal: payload.signal } : { signal: payload.signal };

    for (const { provider } of ranked) {
      try {
        primaryAnswer   = await this.callProvider(provider, prompt, maxTokens, streamOptions);
        primaryProvider = provider.id;
        providersTried.push(provider.id);
        break;
      } catch (err) {
        primaryError = err;
        providersTried.push(provider.id);
        warnings.push(`${provider.id} failed: ${(err as Error).message}`);
      }
    }

    if (!primaryAnswer) {
      return this.buildErrorResponse(
        `All providers failed: ${(primaryError as Error)?.message ?? 'unknown error'}`,
        providersTried, start, warnings,
      );
    }

    const initialConfidence = this.estimateConfidence(primaryAnswer, question);

    // ── 5. Cross-check nếu confidence thấp ───────────────────────────────────
    const shouldCrossCheck =
      this.config.crossCheckEnabled &&
      initialConfidence < this.config.crossCheckThreshold &&
      ranked.length >= 2;

    if (!shouldCrossCheck) {
      this.cache.set(question, {
        answer:       primaryAnswer,
        confidence:   initialConfidence,
        providerUsed: primaryProvider,
        crossChecked: false,
      }, cacheContext);
      return this.applyQualityGate({
        answer:         primaryAnswer,
        confidence:     initialConfidence,
        providersTried,
        providerUsed:   primaryProvider,
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'llm',
      }, payload);
    }

    // Tìm provider thứ 2
    const secondCandidate = ranked.find(r => r.provider.id !== primaryProvider);
    let finalAnswer     = primaryAnswer;
    let finalProvider   = primaryProvider;
    let finalConfidence = initialConfidence;
    let crossChecked    = false;

    if (secondCandidate) {
      try {
        const secondAnswer = await this.callProvider(secondCandidate.provider, prompt, maxTokens, { signal: payload.signal });
        providersTried.push(secondCandidate.provider.id);

        const result    = crossCheck(primaryAnswer, secondAnswer);
        finalAnswer     = result.chosenAnswer;
        finalConfidence = result.confidence;
        finalProvider   = result.chosenFrom === 'secondary'
          ? secondCandidate.provider.id
          : result.chosenFrom === 'synthesized'
            ? 'synthesized'
            : primaryProvider;
        crossChecked    = true;
        warnings.push(`Cross-check: ${result.rationale}`);
      } catch (err) {
        warnings.push(`Secondary provider ${secondCandidate.provider.id} failed: ${(err as Error).message}`);
      }
    }

    this.cache.set(question, {
      answer:       finalAnswer,
      confidence:   finalConfidence,
      providerUsed: finalProvider,
      crossChecked,
    }, cacheContext);

    return this.applyQualityGate({
      answer:         finalAnswer,
      confidence:     finalConfidence,
      providersTried,
      providerUsed:   finalProvider,
      crossChecked,
      warnings,
      latencyMs:      Date.now() - start,
      source:         crossChecked ? 'synthesized' : 'llm',
    }, payload);
  }

  // ── Factory tạo thông báo lỗi ─────────────────────────────────────────────────
  private buildErrorResponse(
    message: string,
    providersTried: string[],
    start: number,
    warnings: string[],
  ): AiResponse {
    return {
      answer:
        '⚠️ **AI service temporarily unavailable.**\n\n' +
        'All external AI providers are currently unreachable. ' +
        'The local knowledge base is still available — try rephrasing your question.\n\n' +
        `*Technical detail: ${message}*`,
      confidence:     0,
      providersTried,
      providerUsed:   'none',
      crossChecked:   false,
      warnings:       [...warnings, message],
      latencyMs:      Date.now() - start,
      source:         'llm',
    };
  }

  // ── Observability ──────────────────────────────────────────────────────────────
  getMetricsSnapshot() {
    return this.metrics.snapshot();
  }

  getCacheSize(): number {
    return this.cache.size;
  }

  private buildCacheContext(payload: AiQueryPayload): string | undefined {
    const parts: string[] = [];
    if (payload.lastAssistantMessage?.trim()) {
      parts.push(`assistant:${payload.lastAssistantMessage.trim()}`);
    }
    if (payload.conversationHistory && payload.conversationHistory.length > 0) {
      const tail = payload.conversationHistory.slice(-2)
        .map(item => `${item.role}:${item.content}`)
        .join('\n');
      if (tail) parts.push(tail);
    }
    if (payload.findingContext && Object.keys(payload.findingContext).length > 0) {
      parts.push(`finding:${JSON.stringify(payload.findingContext)}`);
    }
    return parts.length ? parts.join('\n') : undefined;
  }
}
