export const OWASP_2025_CATEGORIES: Record<string, string> = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable & Outdated Components',
  A07: 'Identification & Authentication Failures',
  A08: 'Software & Data Integrity Failures',
  A09: 'Security Logging & Monitoring Failures',
  A10: 'Server-Side Request Forgery',
};

export type ScanCoverageItem = {
  id: string;
  name: string;
  summary: string;
};

export const URL_SCAN_COVERAGE: ScanCoverageItem[] = [
  { id: 'A01', name: OWASP_2025_CATEGORIES.A01, summary: 'IDOR, ép duyệt đường dẫn, bỏ qua xác thực và leo thang đặc quyền.' },
  { id: 'A02', name: OWASP_2025_CATEGORIES.A02, summary: 'HTTPS/TLS, cờ cookie, dấu hiệu mã hóa yếu và dữ liệu nhạy cảm trên đường truyền.' },
  { id: 'A03', name: OWASP_2025_CATEGORIES.A03, summary: 'XSS, SQLi, command injection, SSTI, XXE và mẫu LDAP/XPath injection.' },
  { id: 'A04', name: OWASP_2025_CATEGORIES.A04, summary: 'Heuristic rà soát bề mặt tấn công và thiết kế bảo mật.' },
  { id: 'A05', name: OWASP_2025_CATEGORIES.A05, summary: 'Trang mặc định, directory listing, lộ GraphQL/API và lộ phiên bản.' },
  { id: 'A07', name: OWASP_2025_CATEGORIES.A07, summary: 'Liệt kê tài khoản, session fixation, luồng đặt lại mật khẩu và dấu hiệu MFA/OAuth/session.' },
  { id: 'A08', name: OWASP_2025_CATEGORIES.A08, summary: 'Deserialization và các dấu hiệu toàn vẹn ở phía response.' },
  { id: 'A10', name: OWASP_2025_CATEGORIES.A10, summary: 'Kiểm tra SSRF hiện nằm trong luồng quét URL.' },
];

export const PROJECT_SCAN_COVERAGE: ScanCoverageItem[] = [
  { id: 'A02', name: OWASP_2025_CATEGORIES.A02, summary: 'Mẫu hashing/cipher/JWT/TLS yếu trong mã nguồn và file cấu hình.' },
  { id: 'A03', name: OWASP_2025_CATEGORIES.A03, summary: 'Mẫu mã nguồn dễ bị injection và heuristic về validate/escape dữ liệu.' },
  { id: 'A04', name: OWASP_2025_CATEGORIES.A04, summary: 'Thiếu threat model, thiếu thiết kế chống abuse/rate limit và authorization-by-design yếu.' },
  { id: 'A05', name: OWASP_2025_CATEGORIES.A05, summary: 'Dấu hiệu cấu hình sai trong config, API, framework và mẫu lộ mặc định.' },
  { id: 'A06', name: OWASP_2025_CATEGORIES.A06, summary: 'Rủi ro phiên bản npm/NuGet/framework, lockfile và vệ sinh dependency.' },
  { id: 'A08', name: OWASP_2025_CATEGORIES.A08, summary: 'SRI, config/data không tin cậy, deserialization và toàn vẹn pipeline CI/CD.' },
  { id: 'A09', name: OWASP_2025_CATEGORIES.A09, summary: 'Dữ liệu nhạy cảm trong log và mức bao phủ structured logging.' },
];

export function normalizeOwaspCategory(category?: string): string {
  const raw = String(category || '').trim().toUpperCase();
  const match = raw.match(/^A(\d{1,2})$/);
  if (!match) return raw || 'OTHER';
  return `A${match[1].padStart(2, '0')}`;
}

export function getOwaspCategoryName(category?: string): string {
  return OWASP_2025_CATEGORIES[normalizeOwaspCategory(category)] || 'Khác / Rule tùy chỉnh';
}

export function formatOwaspCategory(category?: string): string {
  const normalized = normalizeOwaspCategory(category);
  return `${normalized} - ${getOwaspCategoryName(normalized)}`;
}
