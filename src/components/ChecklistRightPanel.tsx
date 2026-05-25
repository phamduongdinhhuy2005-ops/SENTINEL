import React, { useEffect, useMemo, useState } from 'react';
import { useStore } from '../store/useStore';
import { Finding, RemediationPlan, ScanResult } from '../types';
import { buildRemediationPlan } from '../utils/remediationPlan';
import { formatOwaspCategory } from '../utils/owasp';
import { ChecklistItem, sevBg, sevColor, sevLabel } from './ChecklistPanel';
import { localizeEvidenceText, renderEvidence } from './EvidenceRenderer';
import { SentenceText } from './SentenceText';

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const FINDINGS_PER_PAGE = 10;
const MAX_LOCATIONS_PER_GROUP = 8;

type EvidenceItem = {
  text: string;
  path?: string;
};

type FindingActionGroup = {
  id: string;
  severity: Finding['severity'];
  ruleId: string;
  label: string;
  category: string;
  collector: Finding['collector'];
  findings: Finding[];
  todos: string[];
  recommend: string;
  locations: string[];
  evidence: EvidenceItem[];
};

const DESIGN_QUESTIONS = [
  'Có threat model cho login, thanh toán, admin và thao tác destructive.',
  'Có abuse cases cho brute force, IDOR, privilege escalation và SSRF.',
  'Có trust boundary rõ ràng giữa client, API, DB và bên thứ ba.',
  'Có rate limiting/throttling cho endpoint nhạy cảm.',
  'Có default deny và least privilege cho route và dữ liệu.',
  'Có fail-safe behavior khi timeout, parse lỗi hoặc service phụ bị lỗi.',
  'Có data classification cho PII, token, credentials và secret.',
  'Có rà soát bảo mật trước khi release và ghi lại quyết định quan trọng.',
];

const DESIGN_DETAILS: Record<number, { todos: string[]; recommend: string }> = {
  0: {
    todos: ['Vẽ data flow cho luồng nhạy cảm', 'Xác định tài sản cần bảo vệ', 'Ghi threat và control tương ứng'],
    recommend: 'Bắt đầu với STRIDE cho luồng có auth/admin/payment.',
  },
  1: {
    todos: ['Viết abuse case tương ứng với user story', 'Thêm test cho IDOR/brute force', 'Gán owner cho từng control'],
    recommend: 'Checklist tốt nhất là checklist có test hoặc bằng chứng kèm theo.',
  },
  2: {
    todos: ['Đánh dấu input untrusted tại mọi boundary', 'Validate server-side', 'Review OAuth/webhook/payment integration'],
    recommend: 'Mỗi boundary nên có validation, auth, logging và error handling rõ ràng.',
  },
  3: {
    todos: ['Rate limit login/register/reset password', 'Kết hợp IP + account key', 'Cảnh báo khi có pattern bất thường'],
    recommend: 'Dùng backoff mềm thay vì lockout cứng nếu trải nghiệm người dùng quan trọng.',
  },
  4: {
    todos: ['Mặc định route phải cần auth', 'Check role/permission ở server', 'Không đưa authorization logic vào client'],
    recommend: 'Policy/guard tập trung giúp tránh bỏ sót endpoint mới.',
  },
  5: {
    todos: ['Trả generic error cho client', 'Log chi tiết ở server', 'Test timeout và malformed input'],
    recommend: 'Ưu tiên fail closed cho luồng phân quyền, thanh toán và quản trị.',
  },
  6: {
    todos: ['Không log secret/PII', 'Mã hóa dữ liệu nhạy cảm', 'Đặt retention và xóa dữ liệu hết hạn'],
    recommend: 'Secret nên nằm trong vault hoặc environment của main process, không vào renderer bundle.',
  },
  7: {
    todos: ['Đặt rà soát bảo mật trong Definition of Done', 'Ghi nhận chấp nhận rủi ro nếu chưa sửa ngay', 'Rà soát lại sau mỗi release lớn'],
    recommend: 'Dùng OWASP ASVS Level 1 làm baseline thực tế.',
  },
};

function ScanSummaryBlock({ scanResult }: { scanResult: ScanResult }) {
  const bySev = scanResult.metadata.summary.bySeverity || {};
  const byCat = scanResult.metadata.summary.byCategory || {};
  const maxCat = Math.max(1, ...Object.values(byCat));

  return (
    <>
      <div className="checklist-severity-row">
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
          const count = bySev[sev] || 0;
          return (
            <span key={sev} className="checklist-severity-pill" style={{ color: sevColor(sev), borderColor: `${sevColor(sev)}55` }}>
              {sevLabel(sev)} {count}
            </span>
          );
        })}
      </div>

      {Object.keys(byCat).length > 0 && (
        <div className="checklist-bars">
          {Object.entries(byCat).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([category, count]) => (
            <div key={category} className="rg-bar-row">
              <span className="rg-bar-cat">{category}</span>
              <div className="rg-bar-track">
                <div className="rg-bar-fill" style={{ width: `${(count / maxCat) * 100}%` }} />
              </div>
              <span className="rg-bar-n">{count}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function findingCategory(finding: Finding): string {
  return finding.owaspCategory || (finding as Finding & { category?: string }).category || 'OTHER';
}

function collectorText(collector: Finding['collector']): string {
  if (collector === 'source') return 'Quét mã nguồn';
  if (collector === 'blackbox') return 'Quét URL';
  if (collector === 'active-fuzzer') return 'Kiểm thử chủ động';
  return 'Không rõ nguồn';
}

function compactTitle(title: string): string {
  return title
    .replace(/"[^"]+"/g, 'nhiều vị trí')
    .replace(/\s+/g, ' ')
    .trim();
}

function uniqueCompact(items: string[], limit = MAX_LOCATIONS_PER_GROUP): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const item of items.map((value) => String(value || '').trim()).filter(Boolean)) {
    const key = item.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
    if (result.length >= limit) break;
  }
  return result;
}

function uniqueEvidenceItems(items: EvidenceItem[], limit = 5): EvidenceItem[] {
  const seen = new Set<string>();
  const result: EvidenceItem[] = [];
  for (const item of items) {
    const text = localizeEvidenceText(String(item.text || '').trim());
    if (!text) continue;
    const path = String(item.path || '').trim();
    const key = `${text.toLowerCase()}::${path.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ text, path });
    if (result.length >= limit) break;
  }
  return result;
}

function groupKeyForFinding(finding: Finding): string {
  const plan = finding.remediationPlan || buildRemediationPlan(finding);
  const suggested = plan.suggestedChange?.to || finding.remediation || plan.summary || '';
  return [
    finding.ruleId,
    findingCategory(finding),
    finding.severity,
    finding.collector,
    suggested.toLowerCase().replace(/\s+/g, ' ').slice(0, 180),
  ].join('||');
}

function buildActionTodos(finding: Finding, plan: RemediationPlan): string[] {
  const evidence = finding.evidence || [];
  const steps = Array.isArray(plan.steps) ? plan.steps : [];
  return [
    plan.locationHint,
    evidence.length
      ? `Đối chiếu bằng chứng: ${evidence.slice(0, 2).map(localizeEvidenceText).join(' | ')}`
      : 'Tái hiện hoặc bổ sung bằng chứng trước khi kết luận.',
    ...steps.filter((step) => step !== plan.locationHint).slice(0, 4),
  ].filter(Boolean);
}

function buildActionRecommend(finding: Finding, plan: RemediationPlan): string {
  const suggested = plan.suggestedChange?.to;
  if (suggested && suggested !== finding.remediation) return suggested;
  return finding.remediation || plan.summary || 'Lập kế hoạch khắc phục, thêm kiểm thử hồi quy và quét lại sau khi sửa.';
}

function buildFindingActions(findings: Finding[]): FindingActionGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = groupKeyForFinding(finding);
    groups.set(key, [...(groups.get(key) || []), finding]);
  }

  return Array.from(groups.values())
    .map((groupFindings) => {
      const sortedFindings = groupFindings.slice().sort((a, b) => {
        const severityDiff = SEV_ORDER[b.severity] - SEV_ORDER[a.severity];
        if (severityDiff !== 0) return severityDiff;
        return (a.location || a.target).localeCompare(b.location || b.target);
      });
      const first = sortedFindings[0];
      const plan = first.remediationPlan || buildRemediationPlan(first);
      const locations = uniqueCompact(sortedFindings.map((finding) => finding.location || finding.target));
      const evidence = uniqueEvidenceItems(sortedFindings.flatMap((finding) =>
        (finding.evidence || []).map((item) => ({
          text: item,
          path: finding.location || finding.target,
        })),
      ));
      const todos = [
        sortedFindings.length > 1
          ? `Xử lý theo nhóm ${sortedFindings.length} phát hiện cùng quy tắc hoặc cùng mẫu lỗi. Ưu tiên sửa tại chính sách, cấu hình hoặc hàm dùng chung nếu có.`
          : 'Xử lý phát hiện đơn lẻ theo bằng chứng và vị trí bên dưới.',
        ...buildActionTodos(first, plan),
      ];

      return {
        id: `finding-action-group::${groupKeyForFinding(first)}`.toLowerCase(),
        severity: first.severity,
        ruleId: first.ruleId,
        label: `${first.ruleId} - ${compactTitle(first.title)}`,
        category: findingCategory(first),
        collector: first.collector,
        findings: sortedFindings,
        todos,
        recommend: buildActionRecommend(first, plan),
        locations,
        evidence,
      };
    })
    .sort((a, b) => {
      const severityDiff = SEV_ORDER[b.severity] - SEV_ORDER[a.severity];
      if (severityDiff !== 0) return severityDiff;
      const countDiff = b.findings.length - a.findings.length;
      if (countDiff !== 0) return countDiff;
      return a.ruleId.localeCompare(b.ruleId);
    });
}

function FindingActionGroupItem({ action }: { action: FindingActionGroup }) {
  const { checkedChecklistItems, toggleChecklistItem } = useStore();
  const [expanded, setExpanded] = useState(false);
  const checked = checkedChecklistItems.includes(action.id);
  const remainingLocations = Math.max(0, action.findings.length - action.locations.length);

  return (
    <div className={`finding-action-item ${checked ? 'chk-item-done' : ''}`} style={{ borderLeftColor: sevColor(action.severity) }}>
      <div className="finding-action-row">
        <label className="finding-action-check">
          <input
            type="checkbox"
            checked={checked}
            onChange={() => toggleChecklistItem(action.id)}
            className="chk-checkbox-input"
          />
          <span className="chk-item-icon" aria-hidden="true" />
        </label>

        <div className="finding-action-main">
          <div className="finding-action-title-row">
            <span className="finding-action-sev" style={{ color: sevColor(action.severity), background: sevBg(action.severity), borderColor: `${sevColor(action.severity)}55` }}>
              {sevLabel(action.severity)}
            </span>
            <span className={`finding-action-title ${checked ? 'chk-item-text-done' : ''}`}>{action.label}</span>
          </div>
          <div className="finding-action-meta">
            <span>{formatOwaspCategory(action.category)}</span>
            <span>{collectorText(action.collector)}</span>
            <span>{action.findings.length} phát hiện</span>
            {action.locations[0] && <span className="finding-action-primary-location">{action.locations[0]}</span>}
          </div>
        </div>

        <button
          type="button"
          className={`chk-expand-btn ${expanded ? 'open' : ''}`}
          onClick={() => setExpanded((value) => !value)}
          title={expanded ? 'Thu gọn' : 'Xem chi tiết nhóm'}
        >
          {'>'}
        </button>
      </div>

      {expanded && (
        <div className="finding-action-detail">
          <div className="finding-action-detail-grid">
            <div className="chk-detail-section">
              <div className="chk-detail-label">Việc cần làm</div>
              <ul className="chk-todo-list">
                {action.todos.map((todo, index) => (
                  <li key={index} className="chk-todo-item">
                    <SentenceText text={todo} />
                  </li>
                ))}
              </ul>
            </div>

            <div className="chk-detail-section">
              <div className="chk-detail-label">Vị trí liên quan</div>
              <ul className="finding-action-location-list">
                {action.locations.map((location, index) => (
                  <li key={`${location}-${index}`}>{location}</li>
                ))}
                {remainingLocations > 0 && <li className="finding-action-more">+{remainingLocations} vị trí khác trong cùng nhóm</li>}
              </ul>
            </div>
          </div>

          {action.evidence.length > 0 && (
            <div className="chk-detail-section">
              <div className="chk-detail-label">Bằng chứng mẫu</div>
              <div className="finding-action-evidence-list">
                {action.evidence.map((item, index) => renderEvidence(item.text, index, { path: item.path }))}
              </div>
            </div>
          )}

          <div className="chk-detail-section">
            <div className="chk-detail-label">Khuyến nghị sửa chung</div>
            <div className="chk-recommend-text"><SentenceText text={action.recommend} /></div>
          </div>
        </div>
      )}
    </div>
  );
}

export const ChecklistRightPanel: React.FC = () => {
  const {
    projectScanResult,
    urlScanResult,
    checklist,
    checkedChecklistItems,
    getCombinedFindings,
  } = useStore();
  const [hideCompleted, setHideCompleted] = useState(false);
  const [findingPage, setFindingPage] = useState(1);

  const hasProjectScan = Boolean(projectScanResult);
  const hasUrlScan = Boolean(urlScanResult);
  const hasAny = hasProjectScan || hasUrlScan;
  const combinedFindings = getCombinedFindings();
  const findingActions = useMemo(() => buildFindingActions(combinedFindings), [combinedFindings]);
  const visibleFindingActions = useMemo(
    () => hideCompleted
      ? findingActions.filter((action) => !checkedChecklistItems.includes(action.id))
      : findingActions,
    [checkedChecklistItems, findingActions, hideCompleted],
  );
  const visibleFindingCount = visibleFindingActions.reduce((sum, action) => sum + action.findings.length, 0);
  const totalFindingCount = findingActions.reduce((sum, action) => sum + action.findings.length, 0);
  const findingTotalPages = Math.max(1, Math.ceil(visibleFindingActions.length / FINDINGS_PER_PAGE));
  const findingPageStart = (findingPage - 1) * FINDINGS_PER_PAGE;
  const pagedFindingActions = visibleFindingActions.slice(findingPageStart, findingPageStart + FINDINGS_PER_PAGE);
  const findingRangeStart = visibleFindingActions.length ? findingPageStart + 1 : 0;
  const findingRangeEnd = Math.min(findingPageStart + FINDINGS_PER_PAGE, visibleFindingActions.length);
  const designQuestions = checklist?.designQuestions?.length ? checklist.designQuestions : DESIGN_QUESTIONS;
  const designIds = designQuestions.map((_, index) => `design-${index}`);
  const doneCount = designIds.filter((id) => checkedChecklistItems.includes(id)).length;
  const completionRate = Math.round((doneCount / Math.max(1, designQuestions.length)) * 100);

  useEffect(() => {
    setFindingPage(1);
  }, [combinedFindings.length, hideCompleted]);

  useEffect(() => {
    setFindingPage((page) => Math.min(page, findingTotalPages));
  }, [findingTotalPages]);

  if (!hasAny) {
    return (
      <div className="rp-empty">
        <div className="rp-empty-steps">
          <div className="rp-empty-step">
            <div className="rp-empty-num">1</div>
            <div className="rp-empty-text">Chạy URL Scan hoặc Project Scan</div>
          </div>
          <div className="rp-empty-arrow">→</div>
          <div className="rp-empty-step">
            <div className="rp-empty-num">2</div>
            <div className="rp-empty-text">Checklist sẽ xuất hiện tại đây</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="checklist-shell checklist-shell-v3">
      <div className="checklist-summary-grid">
        {urlScanResult && (
          <div className="section checklist-summary-card">
            <div className="checklist-summary-head">
              <div className="section-label" style={{ marginBottom: 0 }}>URL Scan</div>
              <span className="checklist-summary-badge">runtime</span>
            </div>
            <div className="checklist-summary-target">{urlScanResult.scannedUrl || urlScanResult.finalUrl}</div>
            <ScanSummaryBlock scanResult={urlScanResult} />
          </div>
        )}

        {projectScanResult && (
          <div className="section checklist-summary-card">
            <div className="checklist-summary-head">
              <div className="section-label" style={{ marginBottom: 0 }}>Project Scan</div>
              <span className="checklist-summary-badge">Mã nguồn</span>
            </div>
            <ScanSummaryBlock scanResult={projectScanResult} />
            <div className="meta-table checklist-mini-meta">
              <div className="meta-row"><span className="meta-key">Files</span><span className="meta-val">{projectScanResult.metadata.scannedFiles ?? 0}</span></div>
              <div className="meta-row"><span className="meta-key">Config</span><span className="meta-val">{projectScanResult.metadata.configCount ?? 0}</span></div>
              <div className="meta-row"><span className="meta-key">Công nghệ</span><span className="meta-val">{projectScanResult.metadata.techStack?.join(', ') || 'Chưa rõ'}</span></div>
            </div>
          </div>
        )}

        <div className="section checklist-summary-tip">
          <span className="checklist-tip-title">Logic hiện tại: </span>
          <SentenceText
            as="span"
            text="Checklist giữ đầy đủ phát hiện từ URL Scan và Project Scan. Các mục có cùng quy tắc hoặc cùng hướng sửa sẽ được gom thành một nhóm xử lý. Nhóm có rủi ro cao hơn luôn được đưa lên trước."
          />
        </div>
      </div>

      <div className="section checklist-action-panel">
        <div className="chk-section-header checklist-review-head">
          <div>
            <div className="section-label" style={{ marginBottom: 2 }}>Việc cần xử lý từ phát hiện</div>
            <div className="checklist-muted">
              {visibleFindingActions.length} nhóm từ {visibleFindingCount} / {totalFindingCount} phát hiện, ưu tiên từ mức độ cao xuống thấp.
            </div>
          </div>
          <button type="button" className="btn-checklist-toggle" onClick={() => setHideCompleted((v) => !v)}>
            {hideCompleted ? 'Hiện đã xong' : 'Ẩn đã xong'}
          </button>
        </div>

        {findingActions.length > 0 && visibleFindingActions.length > 0 ? (
          <>
            <div className="chk-items-list">
              {pagedFindingActions.map((action) => (
                <FindingActionGroupItem
                  key={action.id}
                  action={action}
                />
              ))}
            </div>
            <div className="checklist-pagination" aria-label="Phân trang việc cần xử lý từ phát hiện">
              <button
                type="button"
                className="checklist-page-btn"
                onClick={() => setFindingPage((page) => Math.max(1, page - 1))}
                disabled={findingPage <= 1}
                title="Trang trước"
              >
                {'<'}
              </button>
              <span className="checklist-page-status">
                Nhóm {findingRangeStart}-{findingRangeEnd} / {visibleFindingActions.length}
                <span>Trang {findingPage}/{findingTotalPages}</span>
              </span>
              <button
                type="button"
                className="checklist-page-btn"
                onClick={() => setFindingPage((page) => Math.min(findingTotalPages, page + 1))}
                disabled={findingPage >= findingTotalPages}
                title="Trang sau"
              >
                {'>'}
              </button>
            </div>
          </>
        ) : findingActions.length > 0 ? (
          <div className="checklist-clean-state">
            Tất cả mục phát hiện trên trang checklist đã được đánh dấu xong.
          </div>
        ) : (
          <div className="checklist-clean-state">
            Không có phát hiện nào cần xử lý. Vẫn nên hoàn tất phần đánh giá thiết kế bên dưới.
          </div>
        )}
      </div>

      <div className="section checklist-review-panel">
        <div className="chk-section-header checklist-review-head">
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="section-label" style={{ marginBottom: 4 }}>Đánh giá thiết kế</div>
            <div className="checklist-progress-row">
              <div className="checklist-progress-track">
                <div className="checklist-progress-fill" style={{ width: `${completionRate}%` }} />
              </div>
              <span className="checklist-progress-badge">{doneCount}/{designQuestions.length} - {completionRate}%</span>
            </div>
          </div>
        </div>

        <div className="chk-items-list">
          {designQuestions.map((question, index) => (
            <ChecklistItem
              key={`design-${index}`}
              id={`design-${index}`}
              label={question}
              hideCompleted={hideCompleted}
              todos={DESIGN_DETAILS[index]?.todos}
              recommend={DESIGN_DETAILS[index]?.recommend}
            />
          ))}
        </div>
      </div>
    </div>
  );
};
