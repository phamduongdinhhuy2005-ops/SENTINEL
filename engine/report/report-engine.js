/* global module */
// engine/report/report-engine.js
// Sentinel v2 — Refactored: robust normalization, structured JSON, upgraded HTML export

'use strict';

const { redactDeep } = require('../utils/redact');

// ── Severity ordering ─────────────────────────────────────────────────────────
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * Normalize a single raw finding into a canonical shape.
 * Accepts any partial object — fills safe defaults for all missing fields.
 */
function normalizeFinding(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const sev = ['critical', 'high', 'medium', 'low'].includes(raw.severity)
    ? raw.severity : 'low';
  const conf = ['high', 'medium', 'low', 'potential'].includes(raw.confidence)
    ? raw.confidence : 'low';
  const finding = {
    ruleId:        String(raw.ruleId        || 'UNKNOWN'),
    owaspCategory: String(raw.owaspCategory || 'UNKNOWN'),
    title:         String(raw.title         || 'Untitled finding'),
    severity:      sev,
    confidence:    conf,
    target:        String(raw.target        || ''),
    location:      String(raw.location      || ''),
    evidence:      Array.isArray(raw.evidence) ? raw.evidence.map(String) : [],
    remediation:   String(raw.remediation   || ''),
    remediationPlan: raw.remediationPlan && typeof raw.remediationPlan === 'object' ? raw.remediationPlan : null,
    references:    Array.isArray(raw.references) ? raw.references.map(String) : [],
    collector:     String(raw.collector     || 'unknown'),
  };
  if (!finding.remediationPlan) finding.remediationPlan = buildFallbackRemediationPlan(finding);
  return finding;
}

function parseLineHint(text) {
  const value = String(text || '');
  const match =
    value.match(/(?:line|dòng|dong)\s*(?:nghi\s*v[aấ]n)?\s*:?\s*(\d+)/i) ||
    value.match(/^\s*>\s*(\d+)\s*\|/m) ||
    value.match(/:(\d+)(?::\d+)?$/);
  if (!match) return undefined;
  const line = Number.parseInt(match[1], 10);
  return Number.isFinite(line) && line > 0 ? line : undefined;
}

function buildFallbackRemediationPlan(finding) {
  const isUrl = /^https?:\/\//i;
  const filePath = finding.collector === 'source' && !isUrl.test(finding.target)
    ? finding.target || (!isUrl.test(finding.location) ? finding.location : '')
    : '';
  const url = isUrl.test(finding.target) ? finding.target : isUrl.test(finding.location) ? finding.location : '';
  const line = parseLineHint(finding.location) || parseLineHint(finding.evidence.join('\n'));
  const locationHint = filePath
    ? line
      ? `Kiểm tra file ${filePath}, khoảng dòng ${line}.`
      : `Kiểm tra file ${filePath}. Scanner chưa xác định được dòng chính xác, hãy tìm theo bằng chứng hoặc mẫu lỗi.`
    : url
      ? `Kiểm tra endpoint ${url}, vị trí runtime: ${finding.location || 'response/request'}.`
      : `Kiểm tra vị trí: ${finding.location || finding.target || 'chưa xác định rõ từ bằng chứng'}.`;
  const suggestedTo = finding.remediation || 'Xác minh bằng chứng và áp dụng biện pháp khắc phục phù hợp.';
  return {
    summary: suggestedTo,
    confidenceNote: 'Đề xuất này được tạo tự động từ bằng chứng của SENTINEL, chỉ mang tính tham khảo. Hãy đọc kỹ code, chạy kiểm thử và rà soát tác động trước khi sửa dự án.',
    filePath: filePath || undefined,
    lineStart: line,
    lineEnd: line,
    url: url || undefined,
    locationHint,
    steps: [
      locationHint,
      finding.evidence.length ? `Đối chiếu bằng chứng: ${finding.evidence.slice(0, 2).join(' | ')}` : 'Tái hiện phát hiện trong môi trường kiểm thử.',
      `Đề xuất sửa: ${suggestedTo}`,
      'Chạy lại test và quét lại bằng SENTINEL để xác nhận.',
    ],
    suggestedChange: { to: suggestedTo, language: 'text' },
  };
}

/**
 * Deduplicate findings: same ruleId + owaspCategory + severity + target.
 * When duplicates exist, keep the one with the most evidence.
 */
function deduplicateFindings(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = `${f.ruleId}||${f.owaspCategory}||${f.severity}||${f.target}`;
    const existing = map.get(key);
    if (!existing || f.evidence.length > existing.evidence.length) {
      map.set(key, f);
    }
  }
  return Array.from(map.values());
}

/**
 * Sort findings: severity → owaspCategory → ruleId (all stable, ascending).
 */
function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    if (sd !== 0) return sd;
    if (a.owaspCategory < b.owaspCategory) return -1;
    if (a.owaspCategory > b.owaspCategory) return 1;
    if (a.ruleId < b.ruleId) return -1;
    if (a.ruleId > b.ruleId) return 1;
    return 0;
  });
}

/**
 * Accept multiple input shapes and normalize to canonical findings array.
 * Handles: { findings }, { data: { findings } }, plain array, null/undefined.
 */
function extractFindings(input) {
  if (!input) return [];
  if (Array.isArray(input)) {
    return input.map(normalizeFinding).filter(Boolean);
  }
  const raw = input.findings || input.data?.findings || [];
  return (Array.isArray(raw) ? raw : []).map(normalizeFinding).filter(Boolean);
}

/**
 * Build summary from normalized findings array.
 */
function summarizeFindings(findings) {
  const arr = Array.isArray(findings) ? findings : [];
  const summary = { total: arr.length, byCategory: {}, bySeverity: {} };
  for (const f of arr) {
    summary.byCategory[f.owaspCategory] = (summary.byCategory[f.owaspCategory] || 0) + 1;
    summary.bySeverity[f.severity]      = (summary.bySeverity[f.severity]      || 0) + 1;
  }
  return summary;
}

// ── HTML helpers ──────────────────────────────────────────────────────────────
function escapeHtml(text) {
  return String(text ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatTimestamp(iso) {
  try {
    const d = new Date(iso);
    return `${iso} (${d.toLocaleString('vi-VN', { hour12: false })})`;
  } catch {
    return iso;
  }
}

const SEV_COLORS = {
  critical: { border: '#e05252', bg: 'rgba(224,82,82,.10)', chip: '#e05252', chipBg: 'rgba(224,82,82,.12)', chipBorder: 'rgba(224,82,82,.32)' },
  high:     { border: '#e07c32', bg: 'rgba(224,124,50,.10)', chip: '#e07c32', chipBg: 'rgba(224,124,50,.12)', chipBorder: 'rgba(224,124,50,.30)' },
  medium:   { border: '#c49a0a', bg: 'rgba(196,154,10,.09)', chip: '#b07d10', chipBg: 'rgba(196,154,10,.12)', chipBorder: 'rgba(196,154,10,.32)' },
  low:      { border: '#2da44e', bg: 'rgba(45,164,78,.08)',  chip: '#2da44e', chipBg: 'rgba(45,164,78,.10)',  chipBorder: 'rgba(45,164,78,.28)' },
};

function sevChip(sev) {
  const c = SEV_COLORS[sev] || SEV_COLORS.low;
  return `<span style="display:inline-flex;align-items:center;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;padding:2px 8px;border-radius:4px;border:1px solid ${c.chipBorder};background:${c.chipBg};color:${c.chip};letter-spacing:.04em;text-transform:uppercase">${escapeHtml(sev)}</span>`;
}

function buildSeverityBreakdownHtml(bySeverity) {
  const sevs = ['critical', 'high', 'medium', 'low'];
  return sevs.map(s => {
    const n = bySeverity[s] || 0;
    const c = SEV_COLORS[s] || SEV_COLORS.low;
    return `<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;border:1px solid ${c.chipBorder};background:${c.chipBg};margin-bottom:6px">
      <span style="font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;color:${c.chip};min-width:32px">${n}</span>
      <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:${c.chip}">${s}</span>
    </div>`;
  }).join('');
}

function buildCategoryBreakdownHtml(byCategory) {
  const entries = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return '<p style="color:#7f91a1;font-size:12px">Không có dữ liệu.</p>';
  return entries.map(([cat, n]) => `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      <span style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:#2da44e;min-width:36px">${escapeHtml(cat)}</span>
      <div style="flex:1;height:6px;background:#2b3945;border-radius:3px;overflow:hidden">
        <div style="height:100%;background:linear-gradient(90deg,#2da44e,#44c56e);border-radius:3px;width:${Math.min(100, n * 10)}%"></div>
      </div>
      <span style="font-size:11px;color:#b2c0cc;font-family:'JetBrains Mono',monospace;min-width:20px;text-align:right">${n}</span>
    </div>
  `).join('');
}

function buildFindingCardHtml(finding, idx) {
  const c = SEV_COLORS[finding.severity] || SEV_COLORS.low;
  const evidenceHtml = finding.evidence.length
    ? finding.evidence.map(e => `<li style="margin-bottom:4px;word-break:break-all;font-family:'JetBrains Mono',monospace;font-size:11px;color:#b2c0cc;line-height:1.6">${escapeHtml(e)}</li>`).join('')
    : '<li style="color:#7f91a1;font-size:11px">Không có bằng chứng.</li>';

  const refsHtml = finding.references.length
    ? finding.references.map(r => `<li><a href="${escapeHtml(r)}" style="color:#4cb3ff;font-size:11px;word-break:break-all">${escapeHtml(r)}</a></li>`).join('')
    : '';
  const plan = finding.remediationPlan;
  const planHtml = plan ? `
    <div style="margin-bottom:8px;background:rgba(76,179,255,.07);border:1px solid rgba(76,179,255,.22);border-left:3px solid #4cb3ff;border-radius:6px;padding:8px 12px">
      <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#4cb3ff;margin-bottom:4px">De xuat vi tri & thay doi</div>
      <div style="font-size:11px;color:#7f91a1;line-height:1.5;margin-bottom:6px">${escapeHtml(plan.confidenceNote || 'De xuat tu dong, can review truoc khi ap dung.')}</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#e6edf3;background:#111921;border:1px solid #2b3945;border-radius:5px;padding:6px;margin-bottom:6px">${escapeHtml(plan.locationHint || '')}</div>
      ${plan.suggestedChange?.from ? `<div style="font-size:11px;color:#b2c0cc;margin-bottom:4px"><strong>Sua tu:</strong> ${escapeHtml(plan.suggestedChange.from)}</div>` : ''}
      ${plan.suggestedChange?.to ? `<div style="font-size:11px;color:#b2c0cc"><strong>De xuat thanh:</strong> ${escapeHtml(plan.suggestedChange.to)}</div>` : ''}
    </div>` : '';

  return `
  <article id="finding-${idx}" style="background:#1b2630;border:1px solid #2b3945;border-left:3px solid ${c.border};border-radius:10px;padding:16px 18px;margin-bottom:12px;box-shadow:0 1px 4px rgba(0,0,0,.18)">
    <div style="display:flex;align-items:flex-start;gap:10px;flex-wrap:wrap;margin-bottom:8px">
      ${sevChip(finding.severity)}
      <span style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#7f91a1;background:#111921;padding:2px 7px;border-radius:4px;border:1px solid #2b3945">${escapeHtml(finding.ruleId)}</span>
      <span style="font-size:10px;padding:2px 7px;border-radius:4px;background:#151d24;border:1px solid #2b3945;color:#b2c0cc">${escapeHtml(finding.owaspCategory)}</span>
      <span style="font-size:10px;padding:2px 7px;border-radius:4px;background:#151d24;border:1px solid #2b3945;color:#7f91a1">${escapeHtml(finding.collector)}</span>
    </div>
    <h3 style="margin:0 0 6px;font-size:14px;color:#e6edf3;font-weight:600;line-height:1.4">${escapeHtml(finding.title)}</h3>
    <div style="font-size:11px;color:#7f91a1;margin-bottom:10px;font-family:'JetBrains Mono',monospace">
      ${finding.target ? `<span>🎯 ${escapeHtml(finding.target)}</span>` : ''}
      ${finding.location ? ` &nbsp;·&nbsp; <span>${escapeHtml(finding.location)}</span>` : ''}
      &nbsp;·&nbsp; Độ tin cậy: <strong style="color:#b2c0cc">${escapeHtml(finding.confidence)}</strong>
    </div>
    ${finding.evidence.length ? `
    <div style="margin-bottom:10px">
      <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#7f91a1;margin-bottom:5px">Bằng chứng</div>
      <ul style="margin:0;padding-left:16px;background:#111921;border:1px solid #2b3945;border-radius:6px;padding:8px 12px;list-style:disc">${evidenceHtml}</ul>
    </div>` : ''}
    ${finding.remediation ? `
    <div style="margin-bottom:8px;background:rgba(45,164,78,.08);border:1px solid rgba(45,164,78,.25);border-left:3px solid #2da44e;border-radius:6px;padding:8px 12px">
      <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#2da44e;margin-bottom:4px">Khắc phục</div>
      <div style="font-size:12px;color:#b2c0cc;line-height:1.5">${escapeHtml(finding.remediation)}</div>
    </div>` : ''}
    ${planHtml}
    ${refsHtml ? `<ul style="margin:0;padding-left:16px;font-size:11px">${refsHtml}</ul>` : ''}
  </article>`;
}

// ── Main export builders ──────────────────────────────────────────────────────

/**
 * buildHtmlReport(scanResult)
 * scanResult can be any shape — we normalize defensively.
 */
function buildHtmlReport(scanResult) {
  const input      = redactDeep((scanResult && typeof scanResult === 'object') ? scanResult : {});
  const rawFindings = extractFindings(input);
  const findings   = sortFindings(deduplicateFindings(rawFindings));

  // Accept summary from metadata or recompute
  const metaSummary = input.metadata?.summary;
  const summary = (metaSummary && typeof metaSummary === 'object' && typeof metaSummary.total === 'number')
    ? metaSummary
    : summarizeFindings(findings);

  const generatedAt = new Date().toISOString();
  const mode        = String(input.mode || 'unknown');
  const finalUrl    = input.finalUrl ? escapeHtml(input.finalUrl) : null;
  const pageTitle   = input.title    ? escapeHtml(input.title)   : null;
  const authSummary = input.metadata?.auth || null;

  const findingCards = findings.length
    ? findings.map((f, i) => buildFindingCardHtml(f, i + 1)).join('')
    : `<div style="background:#1b2630;border:1px solid #2b3945;border-radius:10px;padding:32px;text-align:center;color:#7f91a1;font-size:13px">✅ Không có phát hiện nào.</div>`;

  const metaRows = [
    ['Chế độ scan', mode],
    ['Mục tiêu',   input.scannedUrl || input.target || '—'],
    finalUrl ? ['URL cuối cùng', finalUrl] : null,
    typeof input.status !== 'undefined' ? ['HTTP Status', String(input.status)] : null,
    pageTitle ? ['Tiêu đề trang', input.title] : null,
    input.metadata?.scannedFiles ? ['Files quét', String(input.metadata.scannedFiles)] : null,
    input.metadata?.crawledEndpointsCount ? ['Endpoints crawled', String(input.metadata.crawledEndpointsCount)] : null,
    input.metadata?.formsDetected ? ['Forms', String(input.metadata.formsDetected)] : null,
    authSummary ? ['Auth (cookie)', authSummary.hasCookie ? 'Có' : 'Không'] : null,
    authSummary ? ['Auth (bearer)', authSummary.hasBearerToken ? 'Có' : 'Không'] : null,
  ].filter(Boolean);

  const metaHtml = metaRows.map(([k, v]) => `
    <div style="display:flex;flex-direction:column;gap:4px;border-left:2px solid #44c56e;padding-left:10px">
      <div style="font-size:9.5px;color:#7f91a1;font-weight:600;text-transform:uppercase;letter-spacing:.05em">${escapeHtml(k)}</div>
      <div style="color:#e6edf3;font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all">${escapeHtml(String(v))}</div>
    </div>`).join('');

  const techStack = Array.isArray(input.metadata?.techStack) ? input.metadata.techStack : [];
  const techHtml = techStack.length
    ? techStack.map(t => `<span style="font-size:10px;font-family:'JetBrains Mono',monospace;font-weight:700;padding:3px 8px;border-radius:4px;background:rgba(45,164,78,.15);color:#2da44e;border:1px solid rgba(45,164,78,.32);white-space:nowrap">${escapeHtml(t)}</span>`).join(' ')
    : '';

  return `<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SENTINEL — Báo cáo OWASP 2025</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html{scroll-behavior:smooth}
    body{font-family:Inter,system-ui,sans-serif;background:#0f1418;color:#e6edf3;font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased;padding:0 0 48px}
    a{color:#4cb3ff;text-underline-offset:2px}
    ul{list-style:none}
    .wrap{max-width:1080px;margin:0 auto;padding:0 20px}
    /* Header */
    .rpt-header{background:linear-gradient(135deg,#151d24 0%,#1b2630 100%);border-bottom:2px solid #44c56e;padding:28px 0 24px;margin-bottom:24px}
    .rpt-logo{display:flex;align-items:center;gap:10px;margin-bottom:12px}
    .rpt-logo-icon{width:32px;height:32px;background:#44c56e;border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:800;color:#0f1418;letter-spacing:-.02em;border:2px solid rgba(68,197,110,.4)}
    .rpt-logo-text{font-size:18px;font-weight:700;letter-spacing:.06em;color:#e6edf3}
    .rpt-logo-sub{font-size:11px;color:#7f91a1;letter-spacing:.02em}
    .rpt-title{font-size:22px;font-weight:700;color:#e6edf3;margin-bottom:4px}
    .rpt-ts{font-size:11px;color:#7f91a1;font-family:'JetBrains Mono',monospace;margin-bottom:10px}
    /* Cards */
    .card{background:#1b2630;border:1px solid #2b3945;border-radius:12px;padding:18px 20px;margin-bottom:18px;box-shadow:0 1px 4px rgba(0,0,0,.15)}
    .card-title{font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#7f91a1;margin-bottom:12px}
    /* Grid */
    .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:18px}
    .meta-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
    /* Findings header */
    .findings-hdr{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}
    .findings-count{font-size:24px;font-weight:700;color:#e6edf3;line-height:1}
    .findings-count-label{font-size:10px;color:#7f91a1;text-transform:uppercase;letter-spacing:.06em}
    /* Total badge */
    .total-badge{display:inline-flex;align-items:baseline;gap:4px;font-family:'JetBrains Mono',monospace}
    .total-n{font-size:40px;font-weight:700;color:#e6edf3;line-height:1}
    .total-label{font-size:12px;color:#7f91a1}
    /* Responsive */
    @media(max-width:700px){
      .grid-2{grid-template-columns:1fr}
      .rpt-title{font-size:18px}
      .wrap{padding:0 12px}
    }
    /* Print */
    @media print{
      body{background:#fff;color:#000}
      .card{border:1px solid #ccc;background:#fff}
    }
  </style>
</head>
<body>

<header class="rpt-header">
  <div class="wrap">
    <div class="rpt-logo">
      <div class="rpt-logo-icon">S</div>
      <div>
        <div class="rpt-logo-text">SENTINEL</div>
        <div class="rpt-logo-sub">OWASP 2025 Security Workbench</div>
      </div>
    </div>
    <h1 class="rpt-title">Báo cáo bảo mật OWASP 2025</h1>
    <div class="rpt-ts">Thời điểm tạo: ${escapeHtml(formatTimestamp(generatedAt))}</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <span style="font-size:11px;background:rgba(68,197,110,.12);border:1px solid rgba(68,197,110,.3);border-radius:5px;padding:3px 10px;color:#44c56e;font-family:'JetBrains Mono',monospace;font-weight:700">${escapeHtml(mode)}</span>
      ${techHtml ? `<div style="display:flex;gap:5px;flex-wrap:wrap">${techHtml}</div>` : ''}
    </div>
  </div>
</header>

<div class="wrap">

  <!-- Metadata -->
  <div class="card">
    <div class="card-title">📋 Thông tin quét</div>
    <div class="meta-grid">${metaHtml}</div>
  </div>

  <!-- Summary -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">📊 Tổng hợp theo mức độ</div>
      <div style="display:flex;align-items:center;gap:18px;margin-bottom:14px">
        <div class="total-badge">
          <span class="total-n">${summary.total}</span>
          <span class="total-label">phát hiện</span>
        </div>
      </div>
      ${buildSeverityBreakdownHtml(summary.bySeverity || {})}
    </div>
    <div class="card">
      <div class="card-title">📁 Tổng hợp theo danh mục OWASP</div>
      ${buildCategoryBreakdownHtml(summary.byCategory || {})}
    </div>
  </div>

  <!-- Findings list -->
  <div class="card" style="padding:18px 20px">
    <div class="findings-hdr">
      <div>
        <div class="findings-count">${findings.length}</div>
        <div class="findings-count-label">Phát hiện (sắp xếp theo mức độ)</div>
      </div>
    </div>
    ${findingCards}
  </div>

</div><!-- /.wrap -->
</body>
</html>`;
}

/**
 * buildJsonReport(scanResult)
 * Returns a deterministic, pretty-printed JSON string with a clear schema.
 */
function buildJsonReport(scanResult) {
  const input      = redactDeep((scanResult && typeof scanResult === 'object') ? scanResult : {});
  const rawFindings = extractFindings(input);
  const findings   = sortFindings(deduplicateFindings(rawFindings));

  const metaSummary = input.metadata?.summary;
  const summary = (metaSummary && typeof metaSummary === 'object' && typeof metaSummary.total === 'number')
    ? metaSummary
    : summarizeFindings(findings);

  const report = {
    schemaVersion: '2.0.0',
    generatedAt:   new Date().toISOString(),
    tool: {
      name:    'Sentinel',
      version: '2.0.0',
      standard: 'OWASP Top 10 2025',
    },
    scan: {
      mode:              String(input.mode || 'unknown'),
      target:            String(input.scannedUrl || input.target || ''),
      finalUrl:          String(input.finalUrl   || ''),
      httpStatus:        typeof input.status === 'number' ? input.status : null,
      pageTitle:         String(input.title       || ''),
    },
    metadata: {
      scannedFiles:          input.metadata?.scannedFiles          ?? null,
      crawledEndpointsCount: input.metadata?.crawledEndpointsCount ?? null,
      formsDetected:         input.metadata?.formsDetected         ?? null,
      linksDetected:         input.metadata?.linksDetected         ?? null,
      packageJsonFound:      input.metadata?.packageJsonFound      ?? null,
      csprojCount:           input.metadata?.csprojCount           ?? null,
      configCount:           input.metadata?.configCount           ?? null,
      techStack:             Array.isArray(input.metadata?.techStack) ? input.metadata.techStack : [],
      allowMethods:          Array.isArray(input.metadata?.allowMethods) ? input.metadata.allowMethods : [],
      auth: input.metadata?.auth ? {
        hasCookie:      Boolean(input.metadata.auth.hasCookie),
        hasBearerToken: Boolean(input.metadata.auth.hasBearerToken),
      } : null,
      cspAnalysis: input.metadata?.cspAnalysis ?? null,
      attackSurface: input.metadata?.attackSurface ?? null,
    },
    summary: {
      total:      summary.total      || 0,
      byCategory: summary.byCategory || {},
      bySeverity: summary.bySeverity || {},
    },
    findings: findings.map(f => ({
      ruleId:        f.ruleId,
      owaspCategory: f.owaspCategory,
      title:         f.title,
      severity:      f.severity,
      confidence:    f.confidence,
      target:        f.target,
      location:      f.location,
      evidence:      f.evidence,
      remediation:   f.remediation,
      remediationPlan: f.remediationPlan,
      references:    f.references,
      collector:     f.collector,
    })),
  };

  return JSON.stringify(report, null, 2);
}

/**
 * getSuggestedFilename(scanResult, format)
 */
function getSuggestedFilename(scanResult, format = 'html') {
  const input = (scanResult && typeof scanResult === 'object') ? scanResult : {};
  const base  = input.mode === 'project-scan' ? 'sentinel-project-scan' : 'sentinel-url-scan';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${base}-${stamp}.${format}`;
}

module.exports = {
  // Core utilities
  normalizeFinding,
  deduplicateFindings,
  sortFindings,
  extractFindings,
  summarizeFindings,
  // Report builders
  buildHtmlReport,
  buildJsonReport,
  getSuggestedFilename,
  // Escape helper (exported for tests)
  escapeHtml,
};
