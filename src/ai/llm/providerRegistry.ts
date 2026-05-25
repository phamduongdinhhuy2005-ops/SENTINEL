/**
 * Provider Registry (Nơi đăng ký nhà cung cấp)
 *
 * Tạo và kết nối tất cả các nhà cung cấp cùng với LLM router.
 * Gọi hàm `buildLLMRouter()` một lần khi khởi động ứng dụng và truyền nó vào `initOrchestrator()`.
 *
 * NÂNG CẤP v2:
 *  - Thứ tự ưu tiên mặc định: Groq -> Gemini -> OpenRouter -> Together -> HuggingFace
 *    (Groq miễn phí, nhanh nhất; Gemini có Flash miễn phí)
 *  - readEnvConfig đọc thêm VITE_LLM_MAX_OUTPUT_TOKENS để sync với sentinelAI
 *
 * Để thêm một nhà cung cấp mới:
 *   1. Tạo một class implement LLMProvider trong thư mục providers/
 *   2. Import class đó vào đây và thêm vào mảng `providers`
 *   3. Thêm id của nó vào VITE_LLM_PROVIDER_PRIORITY trong file .env
 */

import { LLMRouter } from './llmRouter.js';
import { ProviderMetricsTracker } from './metricsTracker.js';
import { GeminiProvider } from './providers/geminiProvider.js';
import { GroqProvider } from './providers/groqProvider.js';
import { HuggingFaceProvider } from './providers/huggingfaceProvider.js';
import { OpenRouterProvider } from './providers/openrouterProvider.js';
import { TogetherProvider } from './providers/togetherProvider.js';
import { DEFAULT_ROUTER_CONFIG, RouterConfig } from './types';

/** Đọc các cấu hình ghi đè (tùy chọn) từ biến môi trường Vite */
function readEnvConfig(): Partial<RouterConfig> {
  const cfg: Partial<RouterConfig> = {};

  if (import.meta.env.VITE_LLM_PROVIDER_PRIORITY) {
    cfg.providerPriority = import.meta.env.VITE_LLM_PROVIDER_PRIORITY.split(',').map((s: string) => s.trim());
  }
  if (import.meta.env.VITE_LLM_TIMEOUT_MS) {
    cfg.timeoutMs = Number(import.meta.env.VITE_LLM_TIMEOUT_MS);
  }
  if (import.meta.env.VITE_LLM_MAX_RETRIES) {
    cfg.maxRetries = Number(import.meta.env.VITE_LLM_MAX_RETRIES);
  }
  if (import.meta.env.VITE_LLM_CACHE_TTL_MS) {
    cfg.cacheTtlMs = Number(import.meta.env.VITE_LLM_CACHE_TTL_MS);
  }
  if (import.meta.env.VITE_LLM_CROSS_CHECK_ENABLED !== undefined) {
    cfg.crossCheckEnabled = import.meta.env.VITE_LLM_CROSS_CHECK_ENABLED !== 'false';
  }
  if (import.meta.env.VITE_LLM_CROSS_CHECK_THRESHOLD) {
    cfg.crossCheckThreshold = Number(import.meta.env.VITE_LLM_CROSS_CHECK_THRESHOLD);
  }
  if (import.meta.env.VITE_LLM_MAX_INPUT_TOKENS) {
    cfg.maxInputTokens = Number(import.meta.env.VITE_LLM_MAX_INPUT_TOKENS);
  }
  if (import.meta.env.VITE_LLM_MAX_OUTPUT_TOKENS) {
    cfg.maxOutputTokens = Number(import.meta.env.VITE_LLM_MAX_OUTPUT_TOKENS);
  }

  return cfg;
}

/**
 * Xây dựng và trả về một LLMRouter đã được kết nối đầy đủ.
 * Thứ tự provider: Groq -> Gemini -> OpenRouter -> Together -> HuggingFace
 * Các nhà cung cấp không có API key sẽ có điểm sức khỏe (health score) = 0 và tự động bị bỏ qua.
 */
export function buildLLMRouter(): LLMRouter {
  const config  = { ...DEFAULT_ROUTER_CONFIG, ...readEnvConfig() };
  const metrics = new ProviderMetricsTracker(
    config.circuitBreakerThreshold,
    config.circuitResetMs,
  );

  // NÂNG CẤP: Groq đặt đầu tiên (nhanh, miễn phí, quota tốt)
  const providers = [
    new GroqProvider(metrics),
    new GeminiProvider(metrics),
    new OpenRouterProvider(metrics),
    new TogetherProvider(metrics),
    new HuggingFaceProvider(metrics),
  ];

  return new LLMRouter(providers, metrics, config);
}
