/**
 * Hybrid AI Orchestrator (Điều phối AI lai)
 *
 * Triển khai kiến trúc 3 lớp (3-layer architecture):
 *   Lớp 1 -> Knowledge Base (FAQ ngoại tuyến, phản hồi ngay lập tức, ưu tiên cao nhất)
 *   Lớp 2 -> LLM đa nhà cung cấp (API bên ngoài, dùng dự phòng)
 *   Lớp 3 -> Trình kiểm tra chéo / tổng hợp (trình xác minh được tích hợp vào LLMRouter)
 *
 * NÂNG CẤP v2:
 *  - KB_MIN_LENGTH tăng từ 80 -> 200: KB cần câu trả lời đủ dài mới không cần LLM
 *  - Thêm logic HYBRID: kết hợp KB + LLM khi KB trả lời được những câu hỏi phức tạp
 *  - Phát hiện câu hỏi "cần giải thích sâu" để luôn gọi LLM
 *  - OOS_MARKERS mở rộng để bắt chính xác hơn
 *  - Fallback graceful: không hiển thị lỗi thô với user
 */

import { AiQueryPayload, routeQuery } from '../aiRouter.js';
import { LLMRouter } from './llmRouter.js';
import { AiResponse } from './types';

// ── Nguong cai tien ─────────────────────────────────────────────────────────────────

/**
 * NÂNG CẤP: Tăng từ 80 -> 200.
 * KB cần có câu trả lời đủ chất lượng (ít nhất 200 ký tự) mới được xem là "tốt".
 * Điều này khiến các câu hỏi phức tạp được escalate sang LLM thường xuyên hơn.
 */
const KB_MIN_LENGTH = 200;

/**
 * Độ dài KB tối thiểu cho câu hỏi đơn giản (chào hỏi, liệt kê topic, v.v.)
 * Các câu trả lời này không cần LLM.
 */
const KB_SHORT_ANSWER_MIN = 50;

/** Marker nhận biết câu trả lời nằm ngoài phạm vi KB hoặc là fallback */
const OOS_MARKERS = [
  'Ngoài phạm vi hỗ trợ',
  'Chưa có trong knowledge base',
  'Tôi là AI assistant **chuyên về bảo mật web**',
  '⚠️ **AI service temporarily unavailable.**',
  'Câu hỏi này nằm ngoài',
  'không thuộc phạm vi',
];

/** Marker nhận biết đây là câu trả lời đơn giản từ KB (không cần LLM bổ sung) */
const SIMPLE_KB_MARKERS = [
  '## Tôi hỗ trợ những chủ đề nào',
  '## Tôi là SENTINEL AI Assistant',
  'Xin chào!',
  'Cảm ơn bạn',
  'Rất vui',
];

/** Từ khóa gợi ý câu hỏi cần giải thích sâu -> luôn dùng LLM */
const DEEP_EXPLAIN_MARKERS = [
  'tai sao', 'why', 'co che', 'mechanism', 'hoat dong nhu the nao',
  'how does', 'chi tiet', 'phan tich sau', 'so sanh', 'compare',
  'khac nhau', 'difference', 'vi du thuc te', 'real example',
  'cach khai thac', 'how to exploit', 'demonstrate', 'giai thich ky',
];

function stripDiacritics(text: string): string {
  return text.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
}

function isOOSResponse(text: string): boolean {
  const norm = stripDiacritics(text);
  return OOS_MARKERS.some(m => norm.includes(stripDiacritics(m)));
}

function isSimpleKBResponse(text: string): boolean {
  const norm = stripDiacritics(text);
  return SIMPLE_KB_MARKERS.some(m => norm.includes(stripDiacritics(m)));
}

function needsDeepExplanation(question: string): boolean {
  const q = stripDiacritics(question);
  return DEEP_EXPLAIN_MARKERS.some(m => q.includes(stripDiacritics(m)));
}

// ── Orchestrator ───────────────────────────────────────────────────────────────────
export class HybridOrchestrator {
  private readonly llmRouter: LLMRouter | null;

  constructor(llmRouter: LLMRouter | null = null) {
    this.llmRouter = llmRouter;
  }

  /**
   * Diem truy cap chinh.
   *
   * Logic uu tien (v2):
   * 1. KB trả lời câu đơn giản (chào/list topics) -> trả về ngay, không cần LLM.
   * 2. Cau hoi "can giai thich sau" -> bo qua KB, di thang LLM.
   * 3. KB có câu trả lời đủ dài (>200 ký tự) và không phải OOS -> trả về từ KB.
   *    (Tuy chon: neu co LLM va cau tra loi ngan-vua, them context tu LLM)
   * 4. KB OOS hoac qua ngan -> dung LLM lam nguon chinh.
   * 5. Neu LLM cung that bai -> tra ve KB du chat luong kem.
   */
  async orchestrate(payload: AiQueryPayload): Promise<AiResponse> {
    const start    = Date.now();
    const warnings: string[] = [];
    const question = payload.question ?? '';

    // ── Lớp 1a: Câu trả lời KB ─────────────────────────────────────────────────
    const kbAnswer = routeQuery(payload);

    // Neu KB tra ve cau don gian (chao hoi, liet ke, v.v.) -> dung luon
    if (isSimpleKBResponse(kbAnswer) && kbAnswer.length >= KB_SHORT_ANSWER_MIN) {
      return {
        answer:         kbAnswer,
        confidence:     0.90,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings:       [],
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    // ── Lop 1b: Bo qua KB neu can giai thich sau ─────────────────────────────
    const skipKB = needsDeepExplanation(question) || kbAnswer === '' || isOOSResponse(kbAnswer);

    // ── Lop 1c: KB du tot -> tra ve tu KB ─────────────────────────────────────
    if (!skipKB && kbAnswer.length >= KB_MIN_LENGTH) {
      // Neu LLM co san va cau tra loi KB vua phai (200-600 ky tu), bo sung them tu LLM
      const shouldEnrichWithLLM = this.llmRouter !== null && kbAnswer.length < 600;

      if (!shouldEnrichWithLLM) {
        return {
          answer:         kbAnswer,
          confidence:     0.90,
          providersTried: ['knowledge_base'],
          providerUsed:   'knowledge_base',
          crossChecked:   false,
          warnings:       [],
          latencyMs:      Date.now() - start,
          source:         'knowledge_base',
        };
      }

      try {
        const enrichPayload = { ...payload, onToken: undefined };
        const llmResponse = await this.llmRouter!.query(enrichPayload);
        if (llmResponse.confidence >= 0.50 && !llmResponse.answer.includes('temporarily unavailable')) {
          const enriched = `${kbAnswer}\n\n---\n**🤖 Bo sung tu AI:**\n\n${llmResponse.answer}`;
          return {
            ...llmResponse,
            answer:         enriched,
            confidence:     Math.max(0.85, llmResponse.confidence),
            providersTried: ['knowledge_base', ...llmResponse.providersTried],
            warnings:       [...llmResponse.warnings, ...warnings],
            latencyMs:      Date.now() - start,
            source:         'synthesized',
          };
        }
      } catch {
        // Neu LLM that bai khi enrich, van tra ve KB
      }

      return {
        answer:         kbAnswer,
        confidence:     0.88,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    // ── Lớp 2: LLM làm nguồn chính ──────────────────────────────────────────────
    if (!this.llmRouter) {
      // Không có LLM -> dùng KB bất kể chất lượng
      return {
        answer:         isOOSResponse(kbAnswer) || kbAnswer.length < 20
          ? 'Câu hỏi này chưa có trong knowledge base. Vui lòng thử cấu hình API key (Gemini/Groq/OpenRouter) để nhận câu trả lời từ AI.'
          : kbAnswer,
        confidence:     0.35,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings:       ['LLM tier not configured; using knowledge base only'],
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }

    try {
      const llmResponse = await this.llmRouter.query(payload);

      // Nếu LLM trả về câu trả lời tệ nhưng KB có nội dung hữu ích -> kết hợp
      if (
        llmResponse.confidence < 0.30 &&
        kbAnswer.length > 60 &&
        !isOOSResponse(kbAnswer)
      ) {
        warnings.push('LLM confidence low; supplementing with knowledge base');
        return {
          ...llmResponse,
          answer:   `${kbAnswer}\n\n---\n*Thêm từ AI (confidence thấp):*\n\n${llmResponse.answer}`,
          warnings: [...llmResponse.warnings, ...warnings],
          latencyMs: Date.now() - start,
          source:   'synthesized',
        };
      }

      return {
        ...llmResponse,
        warnings:  [...llmResponse.warnings, ...warnings],
        latencyMs: Date.now() - start,
      };
    } catch (err) {
      warnings.push(`LLM tier error: ${(err as Error).message}`);

      // Graceful fallback về KB
      const fallbackAnswer = isOOSResponse(kbAnswer) || kbAnswer.length < 20
        ? '⚠️ Dịch vụ AI tạm thời không khả dụng và câu hỏi này chưa có trong knowledge base. Vui lòng thử lại sau hoặc hỏi câu khác.'
        : kbAnswer;

      return {
        answer:         fallbackAnswer,
        confidence:     isOOSResponse(kbAnswer) ? 0.10 : 0.45,
        providersTried: ['knowledge_base'],
        providerUsed:   'knowledge_base',
        crossChecked:   false,
        warnings,
        latencyMs:      Date.now() - start,
        source:         'knowledge_base',
      };
    }
  }
}

// ── Singleton factory ──────────────────────────────────────────────────────────
let _instance: HybridOrchestrator | null = null;

export function getOrchestrator(): HybridOrchestrator {
  if (!_instance) _instance = new HybridOrchestrator(null);
  return _instance;
}

/**
 * Goi ham nay mot lan khi khoi dong ung dung de dua LLM router (voi cac nha cung cap that) vao su dung.
 * Co the goi nhieu lan an toan — luon thay the instance cu.
 */
export function initOrchestrator(llmRouter: LLMRouter): void {
  _instance = new HybridOrchestrator(llmRouter);
}

/**
 * Trinh bao boc tuong thich nguoc: tra ve chuoi van ban thuan.
 */
export async function orchestrateToString(payload: AiQueryPayload): Promise<string> {
  return (await getOrchestrator().orchestrate(payload)).answer;
}
