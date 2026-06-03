import React from 'react';
import { Finding, ScanResult } from '../types';
import { formatOwaspCategory } from '../utils/owasp';

interface Props { scanResult: ScanResult }

const SEV_W: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 1 };

function calcRiskScore(findings: Finding[]): number {
  if (!findings.length) return 0;
  return Math.min(100, findings.reduce((s, f) => s + (SEV_W[f.severity] || 0), 0));
}

function riskInfo(s: number): { label: string; sublabel: string; color: string; cls: string } {
  if (s >= 70) return { label: 'Nghiêm trọng', sublabel: 'Cần xử lý ngay',    color: 'var(--crit)', cls: 'rg-score-crit' };
  if (s >= 40) return { label: 'Cao',          sublabel: 'Ưu tiên xử lý sớm', color: 'var(--high)', cls: 'rg-score-high' };
  if (s >= 15) return { label: 'Trung bình',   sublabel: 'Theo dõi dần',       color: 'var(--med)',  cls: 'rg-score-med'  };
  if (s >  0)  return { label: 'Thấp',         sublabel: 'Mức chấp nhận',      color: 'var(--low)',  cls: 'rg-score-low'  };
  return              { label: 'An toàn',      sublabel: 'Không phát hiện',    color: 'var(--low)',  cls: 'rg-score-low'  };
}

const SEV_LABELS: Record<string, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
};

export const RiskDashboard: React.FC<Props> = ({ scanResult }) => {
  const { findings, metadata } = scanResult;
  const score  = calcRiskScore(findings);
  const risk   = riskInfo(score);
  const byCat  = metadata.summary.byCategory;
  const maxCat = Math.max(1, ...Object.values(byCat));
  const bySev  = metadata.summary.bySeverity;
  const target = scanResult.target || scanResult.scannedUrl || '—';

  return (
    <div className="risk-dashboard">
      <div className="rg-top-row">

        {/* Score */}
        <div className={`rg-score-block ${risk.cls}`}>
          <div className="rg-score-number">{score}</div>
          <div className="rg-score-max">/100</div>
          <div className="rg-score-label" style={{ color: risk.color }}>{risk.label}</div>
          <div className="rg-score-sub">{risk.sublabel}</div>
          <div className="rg-score-mode">
            {scanResult.mode === 'url-scan' ? 'Quét Website' : 'Quét Mã Nguồn'}
          </div>
        </div>

        {/* Severity grid */}
        <div className="rg-sev-summary">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <div key={sev} className={`rg-sev-box sev-box-${sev}`}>
              <span className="rg-sev-n">{bySev[sev] || 0}</span>
              <span className="rg-sev-label">{SEV_LABELS[sev]}</span>
            </div>
          ))}
        </div>

        {/* OWASP bars */}
        {Object.keys(byCat).length > 0 && (
          <div className="rg-bars">
            <div className="rg-bars-hdr">Theo danh mục OWASP</div>
            {Object.entries(byCat)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, count]) => (
                <div key={cat} className="rg-bar-row">
                  <span className="rg-bar-cat" title={formatOwaspCategory(cat)}>{formatOwaspCategory(cat)}</span>
                  <div className="rg-bar-track">
                    <div className="rg-bar-fill" style={{ width: `${(count / maxCat) * 100}%`, background: risk.color }} />
                  </div>
                  <span className="rg-bar-n">{count}</span>
                </div>
              ))}
          </div>
        )}

        {/* Scan meta — compact */}
        <div className="rg-meta-col">
          <div className="rg-bars-hdr">Thông tin quét</div>
          <div className="rg-meta-list">
            <div className="rg-meta-row">
              <span className="rg-meta-k">Mục tiêu</span>
              <span className="rg-meta-v" title={target}>{target}</span>
            </div>
            {metadata.scannedFiles !== undefined && (
              <div className="rg-meta-row">
                <span className="rg-meta-k">Files</span>
                <span className="rg-meta-v">{metadata.scannedFiles}</span>
              </div>
            )}
            {metadata.crawledEndpointsCount !== undefined && (
              <div className="rg-meta-row">
                <span className="rg-meta-k">Trang quét</span>
                <span className="rg-meta-v">{metadata.crawledEndpointsCount}</span>
              </div>
            )}
            <div className="rg-meta-row">
              <span className="rg-meta-k">Phát hiện</span>
              <span className="rg-meta-v rg-meta-v--bold">{metadata.summary.total}</span>
            </div>
          </div>

          {/* Tech stack */}
          {metadata.techStack && metadata.techStack.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div className="rg-bars-hdr">Công nghệ</div>
              <div className="rg-tech-chips">
                {metadata.techStack.map((t) => (
                  <span key={t} className="tech-chip">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* CSP warning */}
          {metadata.cspAnalysis && !metadata.cspAnalysis.present && (
            <div className="rg-csp-warn" style={{ marginTop: 8 }}>
              <span>Thiếu Content-Security-Policy</span>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
