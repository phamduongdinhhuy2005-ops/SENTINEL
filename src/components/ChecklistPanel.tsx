import React, { useEffect, useMemo, useState } from 'react';
import { useStore } from '../store/useStore';
import { Finding } from '../types';
import { normalizeOwaspCategory, OWASP_2025_CATEGORIES } from '../utils/owasp';
import { SentenceText } from './SentenceText';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const OWASP_CATS = Object.entries(OWASP_2025_CATEGORIES).map(([id, name]) => ({
  id,
  name,
  desc: {
    A01: 'Kiểm soát truy cập, IDOR, forced browsing, privilege escalation.',
    A02: 'Mã hóa, TLS, cookie flags, dữ liệu nhạy cảm và secret.',
    A03: 'SQLi, XSS, command injection và các lỗi xử lý input.',
    A04: 'Thiết kế thiếu threat model, abuse case, rate limit hoặc deny-by-default.',
    A05: 'Cấu hình sai, debug/default endpoint, CORS, headers và exposure.',
    A06: 'Dependency, framework, runtime cũ hoặc có CVE.',
    A07: 'Authentication, session, reset password, JWT, MFA.',
    A08: 'Supply-chain, CI/CD, integrity, deserialization, update trust.',
    A09: 'Logging, audit trail, monitoring và alerting.',
    A10: 'SSRF và request tới tài nguyên nội bộ/metadata.',
  }[id] || '',
}));

export const CONTEXT_ITEM_DETAILS: Record<string, { todos: string[]; recommend: string }> = {
  'ctx-node-deps': {
    todos: ['Chạy npm audit trong CI', 'Cập nhật dependency có mức nghiêm trọng/cao', 'Ghim lockfile và rà soát package mới'],
    recommend: 'Dùng Dependabot hoặc Snyk để tự động cảnh báo rủi ro dependency.',
  },
  'ctx-node-secrets': {
    todos: ['Tìm secret hardcode trong mã nguồn và .env', 'Không commit .env', 'Rotate key nếu đã lộ trong build/log/git'],
    recommend: 'Secret đã đi vào git hoặc build artifact nên được xem là đã bị lộ.',
  },
  'ctx-web-cors': {
    todos: ['Dùng danh sách origin được phép rõ ràng', 'Không dùng wildcard với credentials', 'Kiểm thử CORS trên endpoint có xác thực'],
    recommend: 'Tránh phản hồi lại Origin header nếu chưa validate trước.',
  },
  'ctx-java-actuator': {
    todos: ['Khóa /actuator/env và /heapdump', 'Chỉ mở health/info khi cần', 'Đặt xác thực cho endpoint quản trị'],
    recommend: 'Actuator trên production nên được giới hạn bằng Spring Security và network policy.',
  },
  'ctx-php-debug': {
    todos: ['Đặt APP_DEBUG=false', 'Tắt display_errors', 'Chặn debugbar/telescope public'],
    recommend: 'Debug mode có thể lộ stack trace, query và thông tin xác thực.',
  },
  'ctx-generic-design': {
    todos: ['Rà soát ranh giới xác thực/phân quyền', 'Kiểm tra validate input', 'Lập kế hoạch sửa theo mức độ rủi ro'],
    recommend: 'Dùng Checklist này như backlog bảo mật nhỏ sau mỗi lần quét.',
  },
};

export function sevColor(sev: string | null): string {
  if (sev === 'critical') return 'var(--crit)';
  if (sev === 'high') return 'var(--high)';
  if (sev === 'medium') return 'var(--med)';
  if (sev === 'low') return 'var(--low)';
  return 'var(--text-3)';
}

export function sevBg(sev: string | null): string {
  if (sev === 'critical') return 'var(--crit-bg)';
  if (sev === 'high') return 'var(--high-bg)';
  if (sev === 'medium') return 'var(--med-bg)';
  if (sev === 'low') return 'var(--low-bg)';
  return 'var(--bg-input)';
}

export function sevLabel(sev: string | null): string {
  if (sev === 'critical') return 'Nghiêm trọng';
  if (sev === 'high') return 'Cao';
  if (sev === 'medium') return 'Trung bình';
  if (sev === 'low') return 'Thấp';
  return 'Chưa rõ';
}

export function buildChecklistFromFindings(findings: Finding[]) {
  const byCategory: Record<string, Finding[]> = {};
  for (const finding of findings) {
    const category = normalizeOwaspCategory(finding.owaspCategory || (finding as Finding & { category?: string }).category);
    byCategory[category] = [...(byCategory[category] || []), finding];
  }

  return OWASP_CATS.map((cat) => {
    const categoryFindings = byCategory[cat.id] || [];
    const severity = categoryFindings.reduce<string | null>((acc, finding) => {
      if (!acc) return finding.severity;
      return SEV_ORDER[finding.severity] > SEV_ORDER[acc] ? finding.severity : acc;
    }, null);
    return {
      ...cat,
      count: categoryFindings.length,
      severity,
      findings: categoryFindings
        .slice()
        .sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity])
        .slice(0, 3),
    };
  });
}

interface ChecklistItemProps {
  id: string;
  label: string;
  hideCompleted: boolean;
  todos?: string[];
  recommend?: string;
  severity?: string | null;
  meta?: string;
}

export const ChecklistItem: React.FC<ChecklistItemProps> = ({
  id, label, hideCompleted, todos, recommend, severity = null, meta,
}) => {
  const { checkedChecklistItems, toggleChecklistItem } = useStore();
  const [expanded, setExpanded] = useState(false);
  const checked = checkedChecklistItems.includes(id);
  const hasDetails = Boolean(todos?.length || recommend);

  if (hideCompleted && checked) return null;

  return (
    <div className={`chk-item-expandable ${checked ? 'chk-item-done' : ''}`} style={{ borderLeftColor: sevColor(severity) }}>
      <div className="chk-item-row">
        <label className="chk-item-label-wrap">
          <input
            type="checkbox"
            checked={checked}
            onChange={() => toggleChecklistItem(id)}
            className="chk-checkbox-input"
          />
          <span className="chk-item-icon" aria-hidden="true" />
          <span className={`chk-item-text ${checked ? 'chk-item-text-done' : ''}`}>
            {label}
            {meta && <span className="chk-item-meta">{meta}</span>}
          </span>
        </label>
        {hasDetails && (
          <button
            type="button"
            className={`chk-expand-btn ${expanded ? 'open' : ''}`}
            onClick={() => setExpanded((v) => !v)}
            title={expanded ? 'Thu gọn' : 'Xem chi tiết'}
          >
            {'>'}
          </button>
        )}
      </div>
      {expanded && hasDetails && (
        <div className="chk-item-detail">
          {todos && todos.length > 0 && (
            <div className="chk-detail-section">
              <div className="chk-detail-label">Việc cần làm</div>
              <ul className="chk-todo-list">
                {todos.map((todo, index) => (
                  <li key={index} className="chk-todo-item">
                    <SentenceText text={todo} />
                  </li>
                ))}
              </ul>
            </div>
          )}
          {recommend && (
            <div className="chk-detail-section">
              <div className="chk-detail-label">Khuyến nghị</div>
              <div className="chk-recommend-text"><SentenceText text={recommend} /></div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const ChecklistPanel: React.FC = () => {
  const {
    loadChecklist,
    projectScanResult,
    urlScanResult,
    urlInput,
    getCombinedFindings,
  } = useStore();
  const [hideCompleted, setHideCompleted] = useState(false);

  useEffect(() => {
    loadChecklist();
  }, [loadChecklist]);

  const hasProjectScan = Boolean(projectScanResult);
  const hasUrlScan = Boolean(urlScanResult);
  const combinedFindings = getCombinedFindings();
  const items = useMemo(() => buildChecklistFromFindings(combinedFindings), [combinedFindings]);
  const covered = items.filter((item) => item.count > 0).length;
  const total = items.length;
  const urlTarget = urlScanResult?.scannedUrl || urlInput || '';
  const techStack = Array.from(new Set([
    ...(projectScanResult?.metadata?.techStack || []),
    ...(urlScanResult?.metadata?.techStack || []),
  ]));

  const hasNode = techStack.some((item) => ['Node.js', 'React', 'Next.js', 'Express.js', 'Electron', 'Vite'].includes(item));
  const hasJava = techStack.some((item) => ['Java', 'Spring Boot'].includes(item));
  const hasPHP = techStack.some((item) => ['PHP', 'Laravel'].includes(item));

  if (!hasProjectScan && !hasUrlScan) {
    return (
      <div className="checklist-empty-card">
        <div className="empty-state-title">Chưa có Checklist</div>
        <div className="empty-state-steps">
          <div className="empty-state-step">
            <span className="empty-state-step-num">1</span>
            <span>Chạy Quét Website hoặc Quét Mã Nguồn</span>
          </div>
          <div className="empty-state-step">
            <span className="empty-state-step-num">2</span>
            <span>Checklist sẽ gom phát hiện thành việc cần xử lý</span>
          </div>
        </div>
      </div>
    );
  }

  const sourceLabel = hasProjectScan && hasUrlScan
    ? 'Quét Website + Quét Mã Nguồn'
    : hasUrlScan
      ? 'Quét Website'
      : 'Quét Mã Nguồn';

  return (
    <div className="checklist-left-stack">
      <div className="checklist-source-card">
        <div className="checklist-source-label">Nguồn dữ liệu</div>
        <div className="checklist-source-title">{sourceLabel}</div>
        {urlTarget && hasUrlScan && <div className="checklist-source-target">{urlTarget}</div>}
      </div>

      <div className="section">
        <div className="section-label">OWASP Top 10</div>
        <div className="chk-coverage">
          <div className="chk-coverage-hdr">
            <span>Độ bao phủ</span>
            <span className="chk-coverage-frac">{covered}/{total}</span>
          </div>
          <div className="chk-coverage-track">
            <div className="chk-coverage-fill" style={{ width: `${(covered / total) * 100}%` }} />
          </div>
          <div className="chk-coverage-label">{covered === 0 ? 'Chưa có danh mục nào có phát hiện.' : `${covered} danh mục cần rà soát.`}</div>
        </div>

        <div className="checklist-grid-adv">
          {items.map((cat) => (
            <div
              key={cat.id}
              className={`chk-item ${cat.count > 0 ? 'chk-item-hit' : ''}`}
              style={{ borderColor: cat.count > 0 ? `${sevColor(cat.severity)}66` : undefined, background: cat.count > 0 ? sevBg(cat.severity) : undefined }}
            >
              <div className="chk-item-header">
                <span className="chk-id" style={{ color: cat.count > 0 ? sevColor(cat.severity) : undefined }}>{cat.id}</span>
                {cat.count > 0
                  ? <span className="chk-badge" style={{ color: sevColor(cat.severity), borderColor: `${sevColor(cat.severity)}66` }}>{cat.count}</span>
                  : <span className="chk-pass">OK</span>}
              </div>
              <div className="chk-name">{cat.name}</div>
              <div className="chk-desc">{cat.desc}</div>
              {cat.severity && <div className="chk-sev" style={{ color: sevColor(cat.severity) }}>{sevLabel(cat.severity)}</div>}
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="chk-section-header">
          <div className="section-label" style={{ marginBottom: 0 }}>Theo công nghệ</div>
          <button type="button" className="btn-checklist-toggle" onClick={() => setHideCompleted((v) => !v)}>
            {hideCompleted ? 'Hiện tất cả' : 'Ẩn đã xong'}
          </button>
        </div>
        <div className="checklist-tech-stack">
          {techStack.length > 0
            ? techStack.map((tech) => <span key={tech} className="checklist-tech-chip">{tech}</span>)
            : <span className="checklist-muted">Chưa nhận diện được công nghệ.</span>}
        </div>
        <div className="chk-items-list">
          {hasNode && (
            <>
              <ChecklistItem id="ctx-node-deps" label="Kiểm tra dependency Node.js" hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['ctx-node-deps']} />
              <ChecklistItem id="ctx-node-secrets" label="Kiểm tra secret trong mã nguồn và build" hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['ctx-node-secrets']} />
              <ChecklistItem id="ctx-web-cors" label="Rà soát CORS và ranh giới API" hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['ctx-web-cors']} />
            </>
          )}
          {hasJava && <ChecklistItem id="ctx-java-actuator" label="Khóa Spring Actuator và endpoint quản trị" hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['ctx-java-actuator']} />}
          {hasPHP && <ChecklistItem id="ctx-php-debug" label="Tắt debug tooling trên production" hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['ctx-php-debug']} />}
          <ChecklistItem id="ctx-generic-design" label="Rà soát cấu hình bảo mật tổng quát" hideCompleted={hideCompleted} {...CONTEXT_ITEM_DETAILS['ctx-generic-design']} />
        </div>
      </div>

      <button
        className="btn-secondary"
        type="button"
        style={{ width: '100%' }}
        onClick={() => window.owaspWorkbench?.openDocs?.('https://owasp.org/Top10/2025/')}
      >
        Mở tài liệu OWASP
      </button>
    </div>
  );
};
