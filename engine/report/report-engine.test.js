// engine/report/report-engine.test.js
// Tests: happy path + edge cases for HTML and JSON export

import { describe, it, expect } from 'vitest';
import {
  normalizeFinding,
  deduplicateFindings,
  sortFindings,
  extractFindings,
  summarizeFindings,
  buildHtmlReport,
  buildJsonReport,
  getSuggestedFilename,
  escapeHtml,
} from './report-engine.js';

// ── Fixtures ──────────────────────────────────────────────────────────────────
const makeF = (overrides = {}) => ({
  ruleId: 'A01-TEST-001',
  owaspCategory: 'A01',
  title: 'Test finding',
  severity: 'medium',
  confidence: 'high',
  target: 'https://example.com',
  location: '/login',
  evidence: ['evidence line 1'],
  remediation: 'Fix it',
  references: ['https://owasp.org'],
  collector: 'blackbox',
  ...overrides,
});

const FULL_SCAN = {
  ok: true,
  mode: 'url-scan',
  scannedUrl: 'https://example.com',
  finalUrl: 'https://example.com/',
  status: 200,
  title: 'Example',
  findings: [
    makeF({ severity: 'critical', ruleId: 'A01-CRIT-001' }),
    makeF({ severity: 'high',     ruleId: 'A02-HIGH-001', owaspCategory: 'A02' }),
    makeF({ severity: 'medium',   ruleId: 'A03-MED-001',  owaspCategory: 'A03' }),
    makeF({ severity: 'low',      ruleId: 'A04-LOW-001',  owaspCategory: 'A04' }),
  ],
  metadata: {
    summary: { total: 4, byCategory: { A01: 1, A02: 1, A03: 1, A04: 1 }, bySeverity: { critical: 1, high: 1, medium: 1, low: 1 } },
    crawledEndpointsCount: 5,
    formsDetected: 2,
    techStack: ['Next.js', 'Nginx'],
    auth: { hasCookie: true, hasBearerToken: false },
  },
};

// ── normalizeFinding ──────────────────────────────────────────────────────────
describe('normalizeFinding', () => {
  it('normalizes a complete finding', () => {
    const f = normalizeFinding(makeF());
    expect(f.ruleId).toBe('A01-TEST-001');
    expect(f.severity).toBe('medium');
    expect(f.evidence).toEqual(['evidence line 1']);
  });

  it('fills safe defaults for missing fields', () => {
    const f = normalizeFinding({});
    expect(f.ruleId).toBe('UNKNOWN');
    expect(f.title).toBe('Untitled finding');
    expect(f.severity).toBe('low');
    expect(f.confidence).toBe('low');
    expect(f.evidence).toEqual([]);
    expect(f.references).toEqual([]);
  });

  it('returns null for non-object input', () => {
    expect(normalizeFinding(null)).toBeNull();
    expect(normalizeFinding(undefined)).toBeNull();
    expect(normalizeFinding('string')).toBeNull();
  });

  it('coerces invalid severity to low', () => {
    const f = normalizeFinding(makeF({ severity: 'extreme' }));
    expect(f.severity).toBe('low');
  });

  it('handles special characters in title/evidence', () => {
    const f = normalizeFinding(makeF({ title: '<script>alert(1)</script>', evidence: ['<img src=x>'] }));
    expect(f.title).toBe('<script>alert(1)</script>'); // raw stored, escape happens at render
    expect(f.evidence[0]).toBe('<img src=x>');
  });
});

// ── deduplicateFindings ───────────────────────────────────────────────────────
describe('deduplicateFindings', () => {
  it('removes exact duplicates keeping most evidence', () => {
    const f1 = normalizeFinding(makeF({ evidence: ['e1'] }));
    const f2 = normalizeFinding(makeF({ evidence: ['e1', 'e2', 'e3'] }));
    const result = deduplicateFindings([f1, f2]);
    expect(result).toHaveLength(1);
    expect(result[0].evidence).toHaveLength(3);
  });

  it('keeps distinct findings', () => {
    const f1 = normalizeFinding(makeF({ ruleId: 'A01-001' }));
    const f2 = normalizeFinding(makeF({ ruleId: 'A02-001', owaspCategory: 'A02' }));
    expect(deduplicateFindings([f1, f2])).toHaveLength(2);
  });

  it('handles empty array', () => {
    expect(deduplicateFindings([])).toEqual([]);
  });
});

// ── sortFindings ──────────────────────────────────────────────────────────────
describe('sortFindings', () => {
  it('sorts by severity: critical first', () => {
    const findings = [
      normalizeFinding(makeF({ severity: 'low' })),
      normalizeFinding(makeF({ severity: 'critical' })),
      normalizeFinding(makeF({ severity: 'medium' })),
      normalizeFinding(makeF({ severity: 'high' })),
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0].severity).toBe('critical');
    expect(sorted[1].severity).toBe('high');
    expect(sorted[2].severity).toBe('medium');
    expect(sorted[3].severity).toBe('low');
  });

  it('sorts by owaspCategory within same severity', () => {
    const findings = [
      normalizeFinding(makeF({ owaspCategory: 'A05', ruleId: 'X' })),
      normalizeFinding(makeF({ owaspCategory: 'A01', ruleId: 'Y' })),
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0].owaspCategory).toBe('A01');
    expect(sorted[1].owaspCategory).toBe('A05');
  });

  it('sorts by ruleId within same severity+category', () => {
    const findings = [
      normalizeFinding(makeF({ ruleId: 'A01-002' })),
      normalizeFinding(makeF({ ruleId: 'A01-001' })),
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0].ruleId).toBe('A01-001');
    expect(sorted[1].ruleId).toBe('A01-002');
  });

  it('does not mutate original array', () => {
    const arr = [normalizeFinding(makeF({ severity: 'low' })), normalizeFinding(makeF({ severity: 'critical' }))];
    const copy = [...arr];
    sortFindings(arr);
    expect(arr[0].severity).toBe(copy[0].severity);
  });
});

// ── extractFindings ───────────────────────────────────────────────────────────
describe('extractFindings', () => {
  it('extracts from { findings: [] }', () => {
    const result = extractFindings({ findings: [makeF()] });
    expect(result).toHaveLength(1);
  });

  it('extracts from plain array', () => {
    expect(extractFindings([makeF(), makeF({ ruleId: 'X' })])).toHaveLength(2);
  });

  it('extracts from { data: { findings: [] } }', () => {
    expect(extractFindings({ data: { findings: [makeF()] } })).toHaveLength(1);
  });

  it('returns empty for null', () => {
    expect(extractFindings(null)).toEqual([]);
  });

  it('returns empty for empty findings', () => {
    expect(extractFindings({ findings: [] })).toEqual([]);
  });

  it('filters out invalid findings', () => {
    const result = extractFindings({ findings: [makeF(), null, 'bad', undefined] });
    expect(result).toHaveLength(1);
  });
});

// ── summarizeFindings ─────────────────────────────────────────────────────────
describe('summarizeFindings', () => {
  it('summarizes by category and severity', () => {
    const findings = [
      normalizeFinding(makeF({ severity: 'critical', owaspCategory: 'A01' })),
      normalizeFinding(makeF({ severity: 'high',     owaspCategory: 'A01' })),
      normalizeFinding(makeF({ severity: 'medium',   owaspCategory: 'A02' })),
    ];
    const s = summarizeFindings(findings);
    expect(s.total).toBe(3);
    expect(s.byCategory.A01).toBe(2);
    expect(s.byCategory.A02).toBe(1);
    expect(s.bySeverity.critical).toBe(1);
    expect(s.bySeverity.high).toBe(1);
    expect(s.bySeverity.medium).toBe(1);
  });

  it('handles empty array', () => {
    const s = summarizeFindings([]);
    expect(s.total).toBe(0);
    expect(s.byCategory).toEqual({});
    expect(s.bySeverity).toEqual({});
  });

  it('handles non-array gracefully', () => {
    const s = summarizeFindings(null);
    expect(s.total).toBe(0);
  });
});

// ── escapeHtml ────────────────────────────────────────────────────────────────
describe('escapeHtml', () => {
  it('escapes all dangerous chars', () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
    expect(escapeHtml("O'Reilly & Sons")).toBe('O&#39;Reilly &amp; Sons');
  });

  it('handles null/undefined safely', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });

  it('handles numbers', () => {
    expect(escapeHtml(42)).toBe('42');
  });
});

// ── buildJsonReport ───────────────────────────────────────────────────────────
describe('buildJsonReport', () => {
  it('returns valid JSON', () => {
    expect(() => JSON.parse(buildJsonReport(FULL_SCAN))).not.toThrow();
  });

  it('has correct schemaVersion and tool', () => {
    const parsed = JSON.parse(buildJsonReport(FULL_SCAN));
    expect(parsed.schemaVersion).toBe('2.0.0');
    expect(parsed.tool.name).toBe('Sentinel');
    expect(parsed.tool.standard).toBe('OWASP Top 10 2025');
  });

  it('findings are sorted critical first', () => {
    const parsed = JSON.parse(buildJsonReport(FULL_SCAN));
    expect(parsed.findings[0].severity).toBe('critical');
    expect(parsed.findings[parsed.findings.length - 1].severity).toBe('low');
  });

  it('findings use camelCase keys consistently', () => {
    const parsed = JSON.parse(buildJsonReport(FULL_SCAN));
    const f = parsed.findings[0];
    expect(f).toHaveProperty('ruleId');
    expect(f).toHaveProperty('owaspCategory');
    expect(f).toHaveProperty('remediation');
    expect(f).not.toHaveProperty('rule_id');
    expect(f).not.toHaveProperty('owasp_category');
  });

  it('handles empty scanResult gracefully', () => {
    const parsed = JSON.parse(buildJsonReport({}));
    expect(parsed.findings).toEqual([]);
    expect(parsed.summary.total).toBe(0);
  });

  it('handles null scanResult', () => {
    const parsed = JSON.parse(buildJsonReport(null));
    expect(parsed.findings).toEqual([]);
  });

  it('handles missing metadata', () => {
    const parsed = JSON.parse(buildJsonReport({ findings: [makeF()] }));
    expect(parsed.summary.total).toBe(1);
    expect(parsed.metadata.techStack).toEqual([]);
  });

  it('handles special characters in finding fields', () => {
    const parsed = JSON.parse(buildJsonReport({ findings: [makeF({ title: '<b>xss</b> & "injection"' })] }));
    expect(parsed.findings[0].title).toBe('<b>xss</b> & "injection"');
  });

  it('pretty-prints with 2-space indent', () => {
    const json = buildJsonReport({ findings: [] });
    const lines = json.split('\n');
    expect(lines.length).toBeGreaterThan(1);
    // Check indentation is 2 spaces
    const indented = lines.find(l => l.startsWith('  '));
    expect(indented).toBeTruthy();
  });

  it('has generatedAt as valid ISO date', () => {
    const parsed = JSON.parse(buildJsonReport(FULL_SCAN));
    expect(() => new Date(parsed.generatedAt)).not.toThrow();
    expect(parsed.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('mixed severity findings sorted correctly', () => {
    const mixed = {
      findings: [
        makeF({ severity: 'low',      ruleId: 'R-LOW' }),
        makeF({ severity: 'critical', ruleId: 'R-CRIT' }),
        makeF({ severity: 'medium',   ruleId: 'R-MED', owaspCategory: 'A02' }),
        makeF({ severity: 'high',     ruleId: 'R-HIGH', owaspCategory: 'A03' }),
      ],
    };
    const parsed = JSON.parse(buildJsonReport(mixed));
    const sevs = parsed.findings.map(f => f.severity);
    expect(sevs).toEqual(['critical', 'high', 'medium', 'low']);
  });
});

// ── buildHtmlReport ───────────────────────────────────────────────────────────
describe('buildHtmlReport', () => {
  it('returns a string containing DOCTYPE', () => {
    expect(buildHtmlReport(FULL_SCAN)).toContain('<!DOCTYPE html>');
  });

  it('escapes special characters in findings', () => {
    const r = buildHtmlReport({ findings: [makeF({ title: '<script>alert(1)</script>' })] });
    expect(r).not.toContain('<script>alert(1)</script>');
    expect(r).toContain('&lt;script&gt;');
  });

  it('shows "Không có phát hiện nào" when findings are empty', () => {
    const r = buildHtmlReport({ findings: [] });
    expect(r).toContain('Không có phát hiện nào');
  });

  it('handles null input gracefully', () => {
    expect(() => buildHtmlReport(null)).not.toThrow();
    const r = buildHtmlReport(null);
    expect(r).toContain('<!DOCTYPE html>');
  });

  it('handles missing metadata', () => {
    expect(() => buildHtmlReport({ findings: [makeF()] })).not.toThrow();
  });

  it('contains target URL in output', () => {
    const r = buildHtmlReport(FULL_SCAN);
    expect(r).toContain('example.com');
  });

  it('shows all severity levels in the report', () => {
    const r = buildHtmlReport(FULL_SCAN);
    expect(r).toContain('critical');
    expect(r).toContain('high');
    expect(r).toContain('medium');
    expect(r).toContain('low');
  });

  it('displays finding count correctly', () => {
    const r = buildHtmlReport(FULL_SCAN);
    expect(r).toContain('4');
  });

  it('escapes ampersand in evidence', () => {
    const r = buildHtmlReport({ findings: [makeF({ evidence: ['foo & bar'] })] });
    expect(r).toContain('foo &amp; bar');
  });

  it('handles finding with no evidence', () => {
    expect(() => buildHtmlReport({ findings: [makeF({ evidence: [] })] })).not.toThrow();
  });

  it('handles finding with no remediation', () => {
    expect(() => buildHtmlReport({ findings: [makeF({ remediation: '' })] })).not.toThrow();
  });

  it('is responsive (contains @media)', () => {
    expect(buildHtmlReport(FULL_SCAN)).toContain('@media');
  });
});

// ── getSuggestedFilename ──────────────────────────────────────────────────────
describe('getSuggestedFilename', () => {
  it('returns html extension by default', () => {
    expect(getSuggestedFilename({}, 'html')).toMatch(/\.html$/);
  });

  it('returns json extension for json format', () => {
    expect(getSuggestedFilename({}, 'json')).toMatch(/\.json$/);
  });

  it('uses project-scan in name for project mode', () => {
    expect(getSuggestedFilename({ mode: 'project-scan' }, 'html')).toContain('project-scan');
  });

  it('uses url-scan in name for url mode', () => {
    expect(getSuggestedFilename({ mode: 'url-scan' }, 'json')).toContain('url-scan');
  });

  it('handles null gracefully', () => {
    expect(() => getSuggestedFilename(null, 'html')).not.toThrow();
  });
});
