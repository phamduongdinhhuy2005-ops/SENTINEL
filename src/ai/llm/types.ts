/**
 * Giao dien nha cung cap LLM & Cac kieu du lieu dung chung
 *
 * Dinh nghia hop dong ma moi adapter cua nha cung cap phai trien khai,
 * cùng với đối tượng phản hồi chuẩn trả về cho người gọi.
 */

// ── Trạng thái sức khỏe nhà cung cấp ───────────────────────────────────────────────────
export interface ProviderHealth {
  /** Diem so 0–1; 1 = hoan toan khoe manh */
  score: number;
  /** Uoc luong han muc con lai (don vi tuy y, tuy thuoc vao nha cung cap) */
  remainingQuota: number;
  /** Do tre trung binh tinh bang ms tu cac lenh goi gan day */
  avgLatencyMs: number;
  /** Tỷ lệ lỗi trong N lệnh gọi gần nhất (0–1) */
  recentErrorRate: number;
  /** Trạng thái ngắt mạch (circuit-breaker) có đang mở hay không */
  circuitOpen: boolean;
}

// ── Truu tuong hoa nha cung cap ───────────────────────────────────────────────────────
export interface LLMProvider {
  /** Dinh danh duy nhat, vi du: "groq", "together", "huggingface" */
  readonly id: string;
  /** Nhãn hiển thị cho người dùng đọc */
  readonly label: string;
  /** Nhà cung cấp này có hỗ trợ đầu ra dạng JSON gốc hay không */
  readonly supportsJsonMode: boolean;

  /**
   * Tao phan hoi cho `prompt`.
   * @param prompt - Chuoi prompt da duoc lam sach.
   * @param options - Cac tuy chon ghi de (maxTokens, systemPrompt, jsonMode).
   * @returns Phản hồi dạng văn bản thô.
   * @throws {ProviderError} khi có lỗi cấp API.
   */
  generate(prompt: string, options?: GenerateOptions): Promise<string>;

  /**
   * Kiem tra nhanh trang thai hoat dong / han muc.
   * Nên nhẹ nhàng — lý tưởng nhất là một lệnh gọi siêu dữ liệu rẻ hoặc được cache.
   */
  health(): Promise<ProviderHealth>;

  /**
   * Tra ve uoc luong han muc con lai.
   * Có thể trả về Infinity khi hạn mức không xác định hoặc không giới hạn.
   */
  estimateCostOrQuota(): Promise<number>;
}

// ── Tuy chon tao phan hoi ───────────────────────────────────────────────────────────
export interface GenerateOptions {
  maxTokens?: number;
  systemPrompt?: string;
  jsonMode?: boolean;
  /** Ghi de thoi gian cho o cap do request tinh bang ms */
  timeoutMs?: number;
  /** AbortSignal để hủy request đang chạy */
  signal?: AbortSignal;
  /** Streaming token callback (neu nha cung cap ho tro) */
  onToken?: (token: string) => void;
  /** Bat streaming khi co onToken */
  stream?: boolean;
}

// ── Loi tu nha cung cap ───────────────────────────────────────────────────────────
export type ProviderErrorKind =
  | 'rate_limit'      // 429
  | 'server_error'    // 5xx
  | 'timeout'
  | 'auth_error'      // 401/403
  | 'bad_request'     // 400
  | 'unknown';

export class ProviderError extends Error {
  constructor(
    public readonly kind: ProviderErrorKind,
    public readonly providerId: string,
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

// ── Phản hồi AI chuẩn mực ─────────────────────────────────────────────────────
export interface AiResponse {
  /** Câu trả lời cuối cùng trả về cho người dùng */
  answer: string;
  /** Diem do tin cay tu 0–1 */
  confidence: number;
  /** Tat ca cac nha cung cap da duoc thu */
  providersTried: string[];
  /** Nhà cung cấp có câu trả lời cuối cùng được sử dụng */
  providerUsed: string;
  /** Đã thực hiện kiểm tra chéo hay chưa */
  crossChecked: boolean;
  /** Các cảnh báo không nghiêm trọng (ví dụ: "nhà cung cấp X quá hạn, dùng dự phòng") */
  warnings: string[];
  /** Tong do tre thuc te tinh bang ms */
  latencyMs: number;
  /** Lop nguon cung cap: 'knowledge_base' | 'llm' | 'synthesized' */
  source: 'knowledge_base' | 'llm' | 'synthesized';
}

// ── Cấu hình bộ định tuyến ─────────────────────────────────────────────────────────────
export interface RouterConfig {
  /**
   * ID cua cac nha cung cap theo thu tu uu tien.
   * Bo dinh tuyen se thu cac nha cung cap co muc uu tien cao hon truoc,
   * tuy thuoc vao diem suc khoe.
   */
  providerPriority: string[];

  /** Trong so dung trong diem lua chon nha cung cap (moi cai trong khoang 0–1) */
  selectionWeights: {
    health: number;
    quota: number;
    latency: number;
    errorRate: number;
  };

  /** Thoi gian toi da cho mot lenh goi nha cung cap, ms */
  timeoutMs: number;

  /** So lan thu lai mot lenh goi that bai truoc khi chuyen sang nha cung cap tiep theo */
  maxRetries: number;

  /** Do tre co so cho thuat toan back-off cap so nhan, ms */
  retryBaseDelayMs: number;

  /** Gioi han do tre back-off toi da, ms */
  retryMaxDelayMs: number;

  /**
   * So lan that bai lien tiep de ngat mach (circuit breaker).
   * Khi bi ngat, nha cung cap se bi bo qua trong `circuitResetMs`.
   */
  circuitBreakerThreshold: number;

  /** Thoi gian duy tri trang thai ngat mach truoc khi thu lai, ms */
  circuitResetMs: number;

  /** Thời gian sống (TTL) cho các câu trả lời được cache, ms */
  cacheTtlMs: number;

  /** Số lượng mục tối đa trong cache */
  cacheMaxSize: number;

  /**
   * Điểm tin cậy tối thiểu từ một nhà cung cấp để bỏ qua kiểm tra chéo.
   * Duoi nguong nay, nha cung cap thu hai cung se duoc truy van.
   */
  crossCheckThreshold: number;

  /**
   * Cho phép hoặc vô hiệu hóa kiểm tra chéo.
   * Co the duoc bat/tat theo moi truong thong qua bien moi truong.
   */
  crossCheckEnabled: boolean;

  /** So luong token toi da gui den nha cung cap (bao ve dau vao) */
  maxInputTokens: number;

  /** So luong token toi da yeu cau tu nha cung cap (bao ve dau ra) */
  maxOutputTokens: number;
}

// ── Cấu hình mặc định ─────────────────────────────────────────────────────────────
// NÂNG CẤP: maxOutputTokens tăng từ 512 -> 2048 để có câu trả lời đầy đủ hơn
// NÂNG CẤP: maxInputTokens tăng từ 1500 -> 2500 để gửi nhiều ngữ cảnh hơn
// NÂNG CẤP: timeoutMs tăng từ 12s -> 20s để nhà cung cấp có đủ thời gian trả lời
// NÂNG CẤP: crossCheckThreshold giảm từ 0.65 -> 0.55 để kích hoạt cross-check ít thường xuyên hơn (tiết kiệm quota)
// NÂNG CẤP: circuitBreakerThreshold tăng từ 5 -> 6 để ít bị ngắt mạch hơn
export const DEFAULT_ROUTER_CONFIG: RouterConfig = {
  providerPriority: ['groq', 'gemini', 'openrouter', 'together', 'huggingface'],
  selectionWeights: { health: 0.35, quota: 0.25, latency: 0.25, errorRate: 0.15 },
  timeoutMs: 20_000,
  maxRetries: 2,
  retryBaseDelayMs: 400,
  retryMaxDelayMs: 5_000,
  circuitBreakerThreshold: 6,
  circuitResetMs: 90_000,
  cacheTtlMs: 10 * 60_000,
  cacheMaxSize: 300,
  crossCheckThreshold: 0.55,
  crossCheckEnabled: true,
  maxInputTokens: 2_500,
  maxOutputTokens: 2_048,
};
