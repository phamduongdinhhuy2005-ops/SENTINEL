import type { Finding, RemediationPlan } from '../types';

const DISCLAIMER = 'Đề xuất này được tạo tự động từ bằng chứng của SENTINEL, chỉ mang tính tham khảo. Hãy đọc kỹ code, chạy kiểm thử và rà soát tác động bảo mật/nghiệp vụ trước khi sửa dự án.';

function parseLine(text: string): number | undefined {
  const match =
    text.match(/(?:line|dòng|dong)\s*(?:nghi\s*v[aấ]n)?\s*:?\s*(\d+)/i) ||
    text.match(/^\s*>\s*(\d+)\s*\|/m) ||
    text.match(/:(\d+)(?::\d+)?$/);
  if (!match) return undefined;
  const line = Number.parseInt(match[1], 10);
  return Number.isFinite(line) && line > 0 ? line : undefined;
}

function isUrl(value: string): boolean {
  return /^https?:\/\//i.test(value);
}

function firstCodeLikeEvidence(finding: Finding): string | undefined {
  return finding.evidence.find(item =>
    /(?:req\.|request\.|sequelize\.query|fetch\(|axios|yaml\.load|console\.log|Set-Cookie|Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|Server:|X-Powered-By)/i.test(item)
  );
}

function buildSuggestedChange(finding: Finding): RemediationPlan['suggestedChange'] {
  const rule = finding.ruleId;
  const evidence = firstCodeLikeEvidence(finding);

  if (/SQLI|NOSQLI/i.test(rule)) {
    return {
      from: evidence || 'Query nhận input trực tiếp từ request hoặc nối chuỗi SQL.',
      to: 'Đổi sang parameterized query/bind parameters, validate schema đầu vào và chỉ allowlist field được phép truy vấn.',
      language: 'text',
    };
  }
  if (/IDOR|ACCESS/i.test(rule)) {
    return {
      from: evidence || 'Truy vấn tài nguyên theo id từ request mà chưa ràng buộc owner/quyền.',
      to: 'Ràng buộc truy vấn theo user hiện tại, ví dụ `WHERE id = :id AND userId = req.user.id`, hoặc gọi authorization policy trước khi trả dữ liệu.',
      language: 'text',
    };
  }
  if (/REDIRECT/i.test(rule)) {
    return {
      from: evidence || 'Redirect/URL allowlist đang kiểm tra bằng string matching.',
      to: 'Parse bằng `new URL()`, chỉ cho phép relative path hoặc hostname nằm trong allowlist chính xác.',
      language: 'javascript',
    };
  }
  if (/SSRF/i.test(rule)) {
    return {
      from: evidence || 'Server gửi request tới URL có thể chịu ảnh hưởng từ user input.',
      to: 'Parse URL, allowlist scheme/host, resolve DNS và chặn private/loopback/metadata IP trước khi request.',
      language: 'text',
    };
  }
  if (/HDR|HSTS|CSP|SVR/i.test(rule)) {
    return {
      from: evidence || 'Response header hiện tại thiếu hoặc lộ thông tin nhạy cảm.',
      to: 'Thêm/sửa header trong middleware hoặc reverse proxy. Ví dụ cấu hình HSTS/CSP và xóa `Server`/`X-Powered-By` nếu không cần.',
      language: 'text',
    };
  }
  if (/COOKIE|SESS/i.test(rule)) {
    return {
      from: evidence || 'Cookie/session chưa có đủ thuộc tính bảo vệ.',
      to: 'Set cookie với `HttpOnly`, `Secure`, `SameSite=Lax/Strict`, timeout hợp lý và rotate session sau login.',
      language: 'text',
    };
  }
  if (/YAML|DESER|XXE/i.test(rule)) {
    return {
      from: evidence || 'Parser/deserializer đang xử lý dữ liệu không tin cậy bằng mode không an toàn.',
      to: 'Dùng safe parser/schema hạn chế, tắt external entity/unsafe tags và validate schema sau khi parse.',
      language: 'text',
    };
  }

  return finding.remediation
    ? { to: finding.remediation, language: 'text' }
    : undefined;
}

export function buildRemediationPlan(finding: Finding): RemediationPlan {
  const target = finding.target || '';
  const location = finding.location || '';
  const filePath = finding.collector === 'source' && !isUrl(target)
    ? target || (!isUrl(location) ? location : undefined)
    : undefined;
  const url = isUrl(target) ? target : isUrl(location) ? location : undefined;
  const line = parseLine(location) || parseLine(finding.evidence.join('\n'));
  const suggestedChange = buildSuggestedChange(finding);

  const locationHint = filePath
    ? line
      ? `Kiểm tra file ${filePath}, khoảng dòng ${line}.`
      : `Kiểm tra file ${filePath}. Scanner chưa xác định được dòng chính xác, hãy tìm theo bằng chứng hoặc mẫu lỗi bên dưới.`
    : url
      ? `Kiểm tra endpoint ${url}, vị trí runtime: ${location || 'response/request'}. Nếu dự án có mã nguồn, tìm route/controller/middleware sinh ra response này.`
      : `Kiểm tra vị trí: ${location || target || 'chưa xác định rõ từ bằng chứng'}.`;

  const steps = [
    locationHint,
    finding.evidence.length
      ? `Đối chiếu bằng chứng: ${finding.evidence.slice(0, 2).join(' | ')}`
      : 'Tái hiện lại phát hiện trong môi trường kiểm thử để xác nhận đúng ngữ cảnh.',
    suggestedChange?.from
      ? `Sửa từ: ${suggestedChange.from}`
      : 'Xác định đoạn code/config sinh ra phát hiện trước khi sửa.',
    suggestedChange
      ? `Đề xuất sửa thành: ${suggestedChange.to}`
      : `Áp dụng khuyến nghị: ${finding.remediation || 'bổ sung kiểm soát bảo mật phù hợp.'}`,
    'Chạy lại unit test, integration test và quét lại bằng SENTINEL để xác nhận phát hiện đã giảm hoặc biến mất.',
  ];

  return {
    summary: finding.remediation || 'Cần xác minh bằng chứng và áp dụng biện pháp khắc phục phù hợp.',
    confidenceNote: DISCLAIMER,
    filePath,
    lineStart: line,
    lineEnd: line,
    url,
    locationHint,
    steps,
    suggestedChange,
  };
}

export function formatRemediationPlanForPrompt(finding: Finding): string {
  const plan = finding.remediationPlan || buildRemediationPlan(finding);
  return [
    `Location hint: ${plan.locationHint}`,
    plan.filePath ? `File: ${plan.filePath}${plan.lineStart ? `:${plan.lineStart}` : ''}` : '',
    plan.url ? `URL: ${plan.url}` : '',
    plan.suggestedChange?.from ? `Suggested change from: ${plan.suggestedChange.from}` : '',
    plan.suggestedChange?.to ? `Suggested change to: ${plan.suggestedChange.to}` : '',
    `Disclaimer: ${plan.confidenceNote}`,
  ].filter(Boolean).join('\n');
}
