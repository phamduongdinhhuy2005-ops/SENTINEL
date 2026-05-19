import React, { useEffect, useState } from 'react';
import { useAIStore } from '../store/useAIStore';
import { useStore } from '../store/useStore';
import { Finding } from '../types';
import { formatOwaspCategory } from '../utils/owasp';
import { buildRemediationPlan } from '../utils/remediationPlan';
import { ReportExportButton } from './ReportExportButton';
import { RiskDashboard } from './RiskDashboard';

const confClass = (c: string) => c === 'high' ? 'conf-high' : c === 'medium' ? 'conf-medium' : 'conf-low';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const CONF_ORDER: Record<Finding['confidence'], number> = { high: 90, medium: 65, low: 35, potential: 20 };
type FindingStatus = 'new' | 'triaged' | 'in-progress' | 'mitigated';
const findingKey = (f: Finding): string => `${f.ruleId}::${f.target || f.location}::${f.title}`;

type GroupedFinding = Finding & { groupedCount?: number; groupedItems?: Finding[] };

const confidencePercent = (confidence: Finding['confidence']): number => CONF_ORDER[confidence] || 35;

const collectorLabel = (collector: Finding['collector']): string => {
  if (collector === 'active-fuzzer') return 'Active test: scanner đã gửi payload để thử khai thác có kiểm soát.';
  if (collector === 'source') return 'Source scan: scanner đọc mã nguồn/config để tìm pattern rủi ro.';
  return 'URL scan: scanner kiểm tra response, header và endpoint công khai.';
};

const confidenceHelp = (confidence: Finding['confidence']): string => {
  if (confidence === 'high') return 'Khoảng 90%: bằng chứng khớp signature rõ ràng hoặc đã có bước xác minh nội dung. Nên ưu tiên kiểm tra và sửa.';
  if (confidence === 'medium') return 'Khoảng 65%: có dấu hiệu đáng tin nhưng vẫn cần mở evidence để xác minh đúng ngữ cảnh ứng dụng.';
  if (confidence === 'potential') return 'Khoảng 20%: mới là tín hiệu tiềm năng; cần tái hiện thủ công trước khi kết luận.';
  return 'Khoảng 35%: heuristic yếu; dùng như gợi ý review, không xem là kết luận cuối cùng.';
};

const categoryGuide = (finding: Finding): { checked: string; why: string; next: string } => {
  const rule = finding.ruleId;
  if (rule.includes('DIRLIST')) {
    return {
      checked: 'Đã probe endpoint và xác minh nội dung giống directory listing.',
      why: 'Directory listing có thể làm lộ file nội bộ, backup hoặc tài liệu không nên public.',
      next: 'Mở URL trong target, xác nhận file nào đang public, rồi tắt listing hoặc thêm xác thực.',
    };
  }
  if (rule.includes('CONFIG-EXPOSURE')) {
    return {
      checked: 'Đã probe endpoint cấu hình và xác minh response JSON có trường config.',
      why: 'Config public có thể lộ thông tin deployment, domain, tính năng và endpoint nội bộ.',
      next: 'Kiểm tra endpoint có cần public không; nếu không, bật authorization phía server.',
    };
  }
  if (finding.owaspCategory === 'A01') {
    return {
      checked: 'Đã tìm endpoint/tài nguyên có vẻ truy cập được mà không thấy auth gate rõ ràng.',
      why: 'Broken Access Control có thể cho phép xem hoặc sửa dữ liệu ngoài quyền.',
      next: 'Xác minh với user chưa đăng nhập và user quyền thấp; thêm authorization phía server.',
    };
  }
  if (finding.owaspCategory === 'A02') {
    return {
      checked: 'Đã kiểm tra header, cookie, file nhạy cảm và dấu hiệu cấu hình bảo mật yếu.',
      why: 'Cấu hình sai hoặc thiếu bảo vệ có thể làm lộ dữ liệu và tăng khả năng bị tấn công.',
      next: 'Đối chiếu evidence, sửa cấu hình server/app, sau đó quét lại để xác nhận.',
    };
  }
  if (finding.owaspCategory === 'A03') {
    return {
      checked: 'Đã tìm dấu hiệu injection qua response, payload active hoặc pattern trong source.',
      why: 'Injection có thể dẫn đến đọc/sửa dữ liệu trái phép hoặc thực thi lệnh.',
      next: 'Tái hiện bằng payload an toàn, sau đó dùng parameterized query và validate input.',
    };
  }
  if (finding.owaspCategory === 'A05') {
    return {
      checked: 'Đã kiểm tra endpoint debug, listing và cấu hình public.',
      why: 'Misconfiguration thường làm lộ thông tin hệ thống và mở thêm đường tấn công.',
      next: 'Tắt debug/listing trên production và giới hạn truy cập endpoint nhạy cảm.',
    };
  }
  return {
    checked: 'Đã chạy rule tương ứng và thu thập evidence bên dưới.',
    why: 'Finding này cần được xác minh theo evidence và ngữ cảnh ứng dụng.',
    next: 'Đọc evidence, tái hiện nếu cần, sửa theo remediation rồi quét lại.',
  };
};

const ConfidenceInline: React.FC<{ confidence: Finding['confidence'] }> = ({ confidence }) => {
  const pct = confidencePercent(confidence);
  return (
    <div className="confidence-inline" title={`Độ tin cậy khoảng ${pct}%`}>
      <div className="confidence-inline-top">
        <span>Tin cậy</span>
        <strong>{pct}%</strong>
      </div>
      <div className="confidence-inline-track">
        <div className={`confidence-inline-fill ${confClass(confidence)}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
};

const CoverageNotes: React.FC<{ notes?: string[]; mode: 'url-scan' | 'project-scan' }> = ({ notes, mode }) => {
  const visibleNotes = (notes || []).filter(Boolean).slice(0, 4);
  const [open, setOpen] = useState(false);
  if (visibleNotes.length === 0) return null;
  const summary = mode === 'url-scan'
    ? 'URL Scan kiểm tra header, response và endpoint công khai; chưa bao phủ đăng nhập, vai trò và luồng nghiệp vụ.'
    : 'Project Scan đọc source, config và dependency; chưa xác minh runtime, exploit thực tế hoặc dữ liệu production.';
  const scopeLabel = mode === 'url-scan' ? 'URL Scan' : 'Project Scan';

  return (
    <div className={`coverage-notes ${open ? 'is-open' : 'is-collapsed'}`}>
      <div className="coverage-notes-head">
        <div className="coverage-notes-title-row">
          <span className="coverage-notes-badge">{scopeLabel}</span>
          <div>
            <div className="coverage-notes-title">Lưu ý về phạm vi phát hiện</div>
            <div className="coverage-notes-summary">{summary}</div>
          </div>
        </div>
        <button
          type="button"
          className="coverage-notes-toggle"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
        >
          {open ? 'Thu gọn' : 'Mở rộng'}
        </button>
      </div>

      <div className="coverage-notes-content">
        <ul className="coverage-notes-list">
          {visibleNotes.map((note, index) => (
            <li key={index}>{note}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

function groupFindings(findings: Finding[]): GroupedFinding[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = [
      finding.ruleId,
      finding.owaspCategory,
      finding.severity,
      finding.confidence,
      finding.collector,
    ].join('::');
    groups.set(key, [...(groups.get(key) || []), finding]);
  }

  return Array.from(groups.values()).map((items) => {
    if (items.length === 1) return items[0];
    const first = items[0];
    const targets = items
      .map((item) => item.target || item.location)
      .filter(Boolean);
    const evidence = [
      `Grouped ${items.length} findings with the same rule and risk type.`,
      ...targets.slice(0, 12).map((target, index) => `${index + 1}. ${target}`),
      targets.length > 12 ? `...and ${targets.length - 12} more locations.` : '',
      ...items.flatMap((item) => item.evidence || []).slice(0, 8),
    ].filter(Boolean);

    return {
      ...first,
      title: `${first.title} (${items.length} vị trí cùng loại)`,
      target: `${items.length} locations`,
      location: first.location || first.target,
      evidence,
      groupedCount: items.length,
      groupedItems: items,
    };
  });
}

const STATUS_VI: Record<FindingStatus, string> = {
  new: 'Mới',
  triaged: 'Đã xem xét',
  'in-progress': 'Đang xử lý',
  mitigated: 'Đã khắc phục',
};

type CodeSnippetLine = { line: string; code: string; active: boolean };

function parseEvidenceSnippet(evidence: string): CodeSnippetLine[] | null {
  if (!/(?:Doan code lien quan|Đoạn code liên quan):/i.test(evidence)) return null;
  const rawLines = evidence.split('\n').slice(1);
  const rows = rawLines
    .map((line) => {
      const match = line.match(/^([ >])\s*(\d+)\s\|\s?(.*)$/);
      if (!match) return null;
      return {
        active: match[1] === '>',
        line: match[2],
        code: match[3] || ' ',
      };
    })
    .filter((row): row is CodeSnippetLine => Boolean(row));
  return rows.length ? rows : null;
}

function renderEvidence(evidence: string, index: number): React.ReactNode {
  const snippet = parseEvidenceSnippet(evidence);
  if (snippet) {
    const activeLine = snippet.find((line) => line.active)?.line;
    return (
      <div key={index} className="detail-code-snippet">
        <div className="code-snippet-head">
          <span>Đoạn code liên quan</span>
          {activeLine && <strong>Dòng lỗi: {activeLine}</strong>}
        </div>
        <pre className="code-snippet-body">
          {snippet.map((row) => (
            <span key={`${row.line}-${row.code}`} className={`code-snippet-row${row.active ? ' is-active' : ''}`}>
              <span className="code-snippet-marker">{row.active ? '!' : ''}</span>
              <span className="code-snippet-line">{row.line}</span>
              <span className="code-snippet-code">{row.code}</span>
            </span>
          ))}
        </pre>
      </div>
    );
  }

  const lineMatch = evidence.match(/Dong nghi van:\s*(\d+)/i) || evidence.match(/Dòng nghi vấn:\s*(\d+)/i);
  if (lineMatch) {
    return (
      <div key={index} className="detail-line-callout">
        <span>Dòng cần kiểm tra</span>
        <strong>{lineMatch[1]}</strong>
      </div>
    );
  }

  return <div key={index} className="detail-evidence">{evidence}</div>;
}

// ── Finding Drawer ────────────────────────────────────────────────────────────
const FindingDrawer: React.FC<{ finding: Finding | null; onClose: () => void }> = ({ finding, onClose }) => {
  const { setAIPendingFinding, setAIChatOpen } = useAIStore();
  if (!finding) return null;

  const isFuzzer = finding.collector === 'active-fuzzer';
  const payloadLine = finding.evidence.find((e) => e.startsWith('Payload:'));
  const evidenceLines = finding.evidence.filter((e) => !e.startsWith('Payload:'));
  const guide = categoryGuide(finding);
  const remediationPlan = finding.remediationPlan || buildRemediationPlan(finding);

  return (
    <div className="finding-drawer-backdrop" onClick={onClose}>
      <aside className="finding-drawer" onClick={(e) => e.stopPropagation()}>

        {/* Head */}
        <div className="finding-drawer-head">
          <div className="finding-drawer-title-wrap">
            <span className={`sev-tag tag-${finding.severity}`}>{finding.severity}</span>
            <div className="finding-drawer-title">{finding.title}</div>
          </div>
          <button className="btn-secondary finding-drawer-close" onClick={onClose}>Đóng ✕</button>
        </div>

        {/* Meta row */}
        <div className="finding-drawer-meta">
          <span className="badge badge-cat">{formatOwaspCategory(finding.owaspCategory)}</span>
          {isFuzzer && <span className="badge badge-fuzzer">Fuzzer</span>}
          <span className="badge badge-collector">{finding.collector}</span>
          <span className={`conf-badge ${confClass(finding.confidence)}`}>
            Độ tin cậy: {confidencePercent(finding.confidence)}%
          </span>
        </div>

        {/* Detail body */}
        <div className="finding-detail">
          <section className="finding-section finding-guide finding-section-wide">
            <div>
              <div className="detail-label">Scanner đã làm gì?</div>
              <div className="guide-text">{guide.checked}</div>
            </div>
            <div>
              <div className="detail-label">Vì sao cần quan tâm?</div>
              <div className="guide-text">{guide.why}</div>
            </div>
            <div>
              <div className="detail-label">Bước tiếp theo</div>
              <div className="guide-text">{guide.next}</div>
            </div>
          </section>

          <section className="finding-section finding-section-wide">
            <div className="finding-section-title">Thông tin vị trí</div>
            <div className="finding-info-grid">
              <div>
                <div className="detail-label">Cách scanner phát hiện</div>
                <div className="detail-note">{collectorLabel(finding.collector)}</div>
              </div>
              <div>
                <div className="detail-label">Tìm thấy tại</div>
                <div className="detail-mono">{finding.location || finding.target}</div>
              </div>
              <div>
                <div className="detail-label">Mã lỗ hổng</div>
                <div className="detail-mono detail-rule-id">{finding.ruleId}</div>
              </div>
            </div>
          </section>

          {isFuzzer && payloadLine && (
            <section className="finding-section finding-section-wide">
              <div className="detail-label">Payload kiểm tra</div>
              <div className="detail-payload">{payloadLine.replace('Payload: ', '')}</div>
            </section>
          )}

          {evidenceLines.length > 0 && (
            <section className="finding-section finding-section-evidence">
              <div className="detail-label">Dữ liệu phát hiện</div>
              <div className="evidence-list">
                {evidenceLines.map((e, i) => renderEvidence(e, i))}
              </div>
            </section>
          )}

          <section className="finding-section finding-section-fix">
            <div className="detail-label">Cách khắc phục</div>
            <div className="detail-fix">{finding.remediation}</div>
          </section>

          <section className="finding-section remediation-plan finding-section-remediation">
            <div className="detail-label">Đề xuất vị trí và thay đổi cần kiểm tra</div>
            <div className="remediation-plan-note">{remediationPlan.confidenceNote}</div>
            <div className="remediation-plan-location">{remediationPlan.locationHint}</div>
            {remediationPlan.suggestedChange && (
              <div className="remediation-change">
                {remediationPlan.suggestedChange.from && (
                  <div>
                    <div className="remediation-change-label">Sửa từ</div>
                    <pre>{remediationPlan.suggestedChange.from}</pre>
                  </div>
                )}
                <div>
                  <div className="remediation-change-label">Đề xuất thành</div>
                  <pre>{remediationPlan.suggestedChange.to}</pre>
                </div>
              </div>
            )}
            <ol className="remediation-steps">
              {remediationPlan.steps.map((step, index) => (
                <li key={index}>{step}</li>
              ))}
            </ol>
          </section>

          <section className="finding-section finding-section-confidence">
            <div className="detail-label">Độ tin cậy nghĩa là gì?</div>
            <div className="confidence-meter" aria-label={`Độ tin cậy ${confidencePercent(finding.confidence)} phần trăm`}>
              <div className="confidence-meter-top">
                <span>{finding.confidence}</span>
                <strong>{confidencePercent(finding.confidence)}%</strong>
              </div>
              <div className="confidence-track">
                <div className={`confidence-fill ${confClass(finding.confidence)}`} style={{ width: `${confidencePercent(finding.confidence)}%` }} />
              </div>
            </div>
            <div className="detail-note">{confidenceHelp(finding.confidence)}</div>
          </section>

          <div className="finding-action-row finding-section-wide">
            <button
              className="btn-ask-ai"
              onClick={(e) => {
                e.stopPropagation();
                setAIPendingFinding(finding);
                setAIChatOpen(true);
              }}
            >
              Hỏi AI về lỗ hổng này
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
};

// ── Findings Table ────────────────────────────────────────────────────────────
const FindingsTable: React.FC<{
  findings: GroupedFinding[];
  scopeKey: string;
  onOpen: (f: Finding) => void;
  getStatus: (sk: string, fk: string) => FindingStatus | undefined;
  onStatusChange: (sk: string, f: Finding, s: FindingStatus) => void;
}> = ({ findings, scopeKey, onOpen, getStatus, onStatusChange }) => (
  <div className="findings-table-wrap">
    <table className="findings-table">
      <thead>
        <tr>
          <th>Mức độ</th>
          <th>Lỗ hổng</th>
          <th>Danh mục</th>
          <th>Vị trí</th>
          <th>Trạng thái</th>
          <th>Hành động</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, idx) => {
          const key = findingKey(f);
          const rowStatus = getStatus(scopeKey, key) || 'new';
          return (
            <tr key={`${key}-${idx}`} className="finding-row">
              <td>
                <div className="severity-cell">
                  <span className={`sev-tag tag-${f.severity}`}>{f.severity}</span>
                  <ConfidenceInline confidence={f.confidence} />
                </div>
              </td>
              <td>
                <div className="finding-rule">{f.ruleId}</div>
                <div className="finding-title-table">{f.title}</div>
                {!!f.groupedCount && <div className="finding-group-note">Đã gom {f.groupedCount} cảnh báo cùng loại</div>}
                <div className="finding-method">{collectorLabel(f.collector)}</div>
              </td>
              <td><span className="badge badge-cat">{formatOwaspCategory(f.owaspCategory)}</span></td>
              <td className="finding-target" title={f.location || f.target}>
                {f.location || f.target || '—'}
              </td>
              <td>
                <select
                  className={`finding-status-select status-${rowStatus}`}
                  value={rowStatus}
                  onChange={(e) => onStatusChange(scopeKey, f, e.target.value as FindingStatus)}
                >
                  {(Object.keys(STATUS_VI) as FindingStatus[]).map((s) => (
                    <option key={s} value={s}>{STATUS_VI[s]}</option>
                  ))}
                </select>
              </td>
              <td>
                <button className="btn-secondary btn-open-finding" onClick={() => onOpen(f)}>
                  Chi tiết
                </button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

// ── Results Panel ─────────────────────────────────────────────────────────────
export const ResultsPanel: React.FC = () => {
  const {
    urlScanResult, projectScanResult, error, isLoading, activeTab,
    resetUrlScanResult, resetProjectScanResult,
    setFindingStatus, getFindingStatus, clearFindingStatuses,
  } = useStore();

  const [sortBy, setSortBy]       = useState<'severity' | 'confidence'>('severity');
  const [filterSev, setFilterSev] = useState('all');
  const [searchQ, setSearchQ]     = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [showOverview, setShowOverview]       = useState(true);

  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;

  useEffect(() => {
    if (!scanResult) return;
    setShowOverview(scanResult.findings.length <= 5);
  }, [scanResult]);

  if (isLoading) return null;
  if (error) return <div className="error-bar">{error}</div>;

  // ── Empty state ──
  if (!scanResult) {
    return (
      <div className="rp-empty">
        <div className="rp-empty-steps">
          <div className="rp-empty-step">
            <div className="rp-empty-num">1</div>
            <div className="rp-empty-text">
              {activeTab === 'url'
                ? <><strong>Nhập URL</strong> website vào ô bên trái</>
                : <><strong>Chọn thư mục</strong> mã nguồn</>}
            </div>
          </div>
          <div className="rp-empty-arrow">→</div>
          <div className="rp-empty-step">
            <div className="rp-empty-num">2</div>
            <div className="rp-empty-text">
              {activeTab === 'url'
                ? <>Nhấn <strong>Bắt đầu quét URL</strong></>
                : <>Nhấn <strong>Bắt đầu phân tích</strong></>}
            </div>
          </div>
          <div className="rp-empty-arrow">→</div>
          <div className="rp-empty-step">
            <div className="rp-empty-num">3</div>
            <div className="rp-empty-text">Kết quả xuất hiện tại đây</div>
          </div>
        </div>
        <p className="rp-empty-hint">
          Cài đặt mặc định phù hợp cho hầu hết trường hợp - không cần thay đổi gì thêm.
        </p>
      </div>
    );
  }

  const { findings, metadata } = scanResult;
  const scanScopeKey = `${scanResult.mode}::${scanResult.target || scanResult.scannedUrl || 'unknown'}`.toLowerCase();
  const summary = metadata.summary;

  // ── Filter + sort ──
  const filteredFindings = findings
    .filter((f) => filterSev === 'all' || f.severity === filterSev)
    .filter((f) => !searchQ ||
      f.title.toLowerCase().includes(searchQ.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(searchQ.toLowerCase()) ||
      formatOwaspCategory(f.owaspCategory).toLowerCase().includes(searchQ.toLowerCase()));

  const visible = groupFindings(filteredFindings)
    .sort((a, b) =>
      sortBy === 'severity'
        ? SEV_ORDER[b.severity] - SEV_ORDER[a.severity]
        : confidencePercent(b.confidence) - confidencePercent(a.confidence)
    );

  const cnt = (sev: string) => summary.bySeverity?.[sev] || 0;
  const hasFilter = filterSev !== 'all' || searchQ !== '';
  const scopedStatusCount = findings.filter(f =>
    getFindingStatus(scanScopeKey, findingKey(f))
  ).length;

  return (
    <div className="results-shell density-comfort">

      {/* ── Overview toggle strip ── */}
      <div className="rp-guide">
        <div className="rp-guide-steps">
          <span className="rp-guide-pill rp-guide-pill--1">
            <span className="rp-guide-num">1</span> Xem lỗi Critical &amp; High trước
          </span>
          <span className="rp-guide-sep">→</span>
          <span className="rp-guide-pill">
            <span className="rp-guide-num">2</span> Nhấn &quot;Chi tiết&quot; để xem cách sửa
          </span>
          <span className="rp-guide-sep">→</span>
          <span className="rp-guide-pill">
            <span className="rp-guide-num">3</span> Cập nhật trạng thái xử lý
          </span>
        </div>
        <div className="rp-guide-actions">
          <ReportExportButton />
          <button
            className="btn-secondary rp-overview-btn"
            onClick={() => setShowOverview((v) => !v)}
          >
            {showOverview ? 'Ẩn tổng quan' : 'Tổng quan'}
          </button>
        </div>
      </div>

      {/* ── Risk Dashboard ── */}
      {showOverview && (
        <div style={{ flexShrink: 0 }}>
          <RiskDashboard scanResult={scanResult} />
        </div>
      )}

      <CoverageNotes notes={metadata.coverageNotes} mode={scanResult.mode} />

      {/* ── Filter bar ── */}
      <div className="filter-bar-adv" style={{ flexShrink: 0 }}>
        <div className="filter-bar-main">
          {/* Severity chips */}
          <div className="sev-filter-chips">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => (
              <button
                key={s}
                className={`sev-filter-btn sev-filter-${s} ${filterSev === s ? 'active' : ''}`}
                onClick={() => setFilterSev(s)}
              >
                {s === 'all' ? 'Tất cả' : s.charAt(0).toUpperCase() + s.slice(1)}
                {s !== 'all' && cnt(s) > 0 && (
                  <span className="sev-filter-count">{cnt(s)}</span>
                )}
              </button>
            ))}
          </div>

          <input
            type="text"
            className="search-input"
            placeholder="Tìm lỗ hổng hoặc mã rule..."
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
          />
        </div>

        <div className="filter-bar-right">
          <select
            className="filter-select filter-select-sort"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'severity' | 'confidence')}
          >
            <option value="severity">Sắp xếp: Mức độ</option>
            <option value="confidence">Sắp xếp: Độ tin cậy</option>
          </select>
          <span className="filter-count">{visible.length} nhóm / {filteredFindings.length} cảnh báo</span>

          {hasFilter && (
            <button className="btn-reset" onClick={() => { setFilterSev('all'); setSearchQ(''); }}>
              ↺ Xoá lọc
            </button>
          )}

          <button
            className="btn-reset btn-reset-status"
            disabled={scopedStatusCount === 0}
            onClick={() => clearFindingStatuses(scanScopeKey)}
            title="Đặt lại trạng thái xử lý"
          >
            ↺ Trạng thái
          </button>

          <button
            className="btn-reset btn-clear-results"
            onClick={() => {
              if (activeTab === 'url') resetUrlScanResult();
              else resetProjectScanResult();
              setSelectedFinding(null);
            }}
          >
            ✕ Xoá
          </button>
        </div>
      </div>

      {/* ── Table / empty results ── */}
      {visible.length === 0 ? (
        <div className="empty-state" style={{ minHeight: 160 }}>
          <div className="empty-icon">✓</div>
          <p>{hasFilter ? 'Không có lỗ hổng nào khớp bộ lọc.' : 'Không phát hiện vấn đề nào.'}</p>
        </div>
      ) : (
        <FindingsTable
          findings={visible}
          scopeKey={scanScopeKey}
          onOpen={setSelectedFinding}
          getStatus={getFindingStatus}
          onStatusChange={(sk, f, s) => setFindingStatus(sk, findingKey(f), s)}
        />
      )}

      <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
    </div>
  );
};
