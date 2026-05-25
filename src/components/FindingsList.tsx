import { useStore } from '../store/useStore';
import { ReportExportButton } from './ReportExportButton';
import { Finding } from '../types';
import { formatOwaspCategory } from '../utils/owasp';

const severityColor = (sev: string) => {
  switch (sev) {
    case 'critical': return 'badge-critical';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-medium';
    default: return 'badge-low';
  }
};

const severityLabel = (sev: string) => {
  switch (sev) {
    case 'critical': return 'Nghiêm trọng';
    case 'high': return 'Cao';
    case 'medium': return 'Trung bình';
    default: return 'Thấp';
  }
};

const confidenceLabel = (confidence: Finding['confidence']) => {
  if (confidence === 'high') return 'Cao';
  if (confidence === 'medium') return 'Trung bình';
  if (confidence === 'potential') return 'Tiềm năng';
  return 'Thấp';
};

const collectorLabel = (collector: Finding['collector']) => {
  if (collector === 'source') return 'Quét mã nguồn';
  if (collector === 'active-fuzzer') return 'Kiểm thử chủ động';
  return 'Quét URL';
};

export const FindingsList: React.FC = () => {
  const { urlScanResult, projectScanResult, activeTab, error, isLoading } = useStore();
  const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;

  if (isLoading) {
    return (
      <div className="card findings-panel">
        <div className="loading-spinner"></div>
        <p>Đang quét...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card findings-panel error-panel">
        <h3>⚠️ Lỗi quét</h3>
        <p>{error}</p>
      </div>
    );
  }

  if (!scanResult) {
    return (
      <div className="card findings-panel empty-panel">
        <p>✨ Chưa có lần quét nào. Dùng biểu mẫu phía trên để bắt đầu đánh giá bảo mật.</p>
      </div>
    );
  }

  const { findings, metadata, mode, target } = scanResult;
  const summary = metadata.summary;

  return (
    <div className="card findings-panel">
      <div className="findings-header">
        <h3>🔎 Kết quả quét</h3>
        <ReportExportButton />
      </div>
      <div className="scan-info">
        <p><strong>Chế độ:</strong> {mode === 'url-scan' ? 'URL Scan' : 'Project Scan'}</p>
        <p><strong>Mục tiêu:</strong> {target || scanResult.scannedUrl}</p>
        {scanResult.finalUrl && <p><strong>URL cuối:</strong> {scanResult.finalUrl}</p>}
        {scanResult.status && <p><strong>HTTP Status:</strong> {scanResult.status}</p>}
        {scanResult.title && <p><strong>Tiêu đề trang:</strong> {scanResult.title}</p>}
      </div>

      <div className="summary-stats">
        <div className="stat">Tổng phát hiện: <strong>{summary.total}</strong></div>
        <div className="stat-categories">
          {Object.entries(summary.bySeverity).map(([sev, count]) => (
            <span key={sev} className={`stat-badge ${severityColor(sev)}`}>
              {severityLabel(sev)}: {count}
            </span>
          ))}
        </div>
      </div>

      {findings.length === 0 ? (
        <p className="no-findings">✅ Không phát hiện vấn đề bảo mật nào theo các heuristic hiện tại.</p>
      ) : (
        <div className="findings-list">
          {findings.map((finding: Finding, idx: number) => (
            <div key={idx} className={`finding-item ${severityColor(finding.severity)}`}>
              <div className="finding-title">
                <span className={`severity-dot ${severityColor(finding.severity)}`}></span>
                <strong>{finding.title}</strong>
                <span className="rule-id">{finding.ruleId}</span>
              </div>
              <div className="finding-meta">
                <span>OWASP: {formatOwaspCategory(finding.owaspCategory)}</span>
                <span>Độ tin cậy: {confidenceLabel(finding.confidence)}</span>
                <span>Nguồn quét: {collectorLabel(finding.collector)}</span>
              </div>
              <div className="finding-location">📍 {finding.location || finding.target}</div>
              {finding.evidence.length > 0 && (
                <div className="finding-evidence">
                  <strong>Bằng chứng:</strong>
                  <ul>
                    {finding.evidence.slice(0, 3).map((e: string, i: number) => <li key={i}>{e}</li>)}
                  </ul>
                </div>
              )}
              <div className="finding-remediation">
                <strong>Khuyến nghị:</strong> {finding.remediation}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
