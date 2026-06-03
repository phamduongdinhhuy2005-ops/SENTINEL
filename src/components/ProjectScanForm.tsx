import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { PROJECT_SCAN_COVERAGE } from '../utils/owasp';

const SCOPE_CARDS = [
  {
    icon: '✓',
    title: 'Thư viện & gói phần mềm',
    desc: 'Tìm dependency cũ hoặc có rủi ro bảo mật.',
  },
  {
    icon: '✓',
    title: 'Mật khẩu & khoá bí mật',
    desc: 'Phát hiện API key, token hoặc secret nằm trong mã nguồn.',
  },
  {
    icon: '✓',
    title: 'File cấu hình & môi trường',
    desc: 'Rà soát .env và config có thể làm lộ thông tin nhạy cảm.',
  },
  {
    icon: '✓',
    title: 'Pipeline CI/CD',
    desc: 'Kiểm tra cấu hình build, test và triển khai cơ bản.',
  },
  {
    icon: '✓',
    title: 'Ghi log & xử lý lỗi',
    desc: 'Tìm log hoặc thông báo lỗi có thể lộ dữ liệu.',
  },
];

export const ProjectScanForm: React.FC = () => {
  const { selectedFolder, setSelectedFolder, performProjectScan, isLoading } = useStore();
  const [showCoverage, setShowCoverage] = useState(false);

  const handleBrowse = async () => {
    const result = await window.owaspWorkbench?.pickFolder?.();
    if (result?.ok && result.folderPath) setSelectedFolder(result.folderPath);
  };

  return (
    <>
      {/* ── Tip người mới ── */}
      <div className="onboarding-tip">
        <strong>Bắt đầu nhanh:</strong> Chọn thư mục gốc của dự án hoặc thư mục chứa mã nguồn chính.
        Với dự án nhỏ, chọn thư mục gốc thường là đủ.
      </div>

      {/* ── Chọn thư mục ── */}
      <div className={`scan-scope-notice ${showCoverage ? 'is-open' : 'is-collapsed'}`}>
        <button
          type="button"
          className="scan-scope-toggle"
          onClick={() => setShowCoverage((value) => !value)}
          aria-expanded={showCoverage}
        >
          {showCoverage ? 'Thu gọn' : 'OWASP'}
        </button>
        <div>
          <div className="scan-scope-title">Quét Mã Nguồn kiểm tra gì?</div>
          <p className="scan-scope-copy">
            Đọc mã nguồn, cấu hình và dependency để tìm secret, thư viện lỗi thời, cấu hình yếu và mẫu code rủi ro.
          </p>
        </div>
        <div className="owasp-chip-grid">
          {PROJECT_SCAN_COVERAGE.map((item) => (
            <span key={item.id} className="owasp-scope-chip" title={item.summary}>
              <strong>{item.id}</strong> {item.name}
            </span>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="section-label">Thư mục mã nguồn</div>

        <div className="field">
          <label className="field-label" htmlFor="folder-path">Đường dẫn thư mục</label>
          <div className="folder-select-row">
            <div className="input-clear-row">
              <input
                id="folder-path"
                type="text"
                value={selectedFolder || ''}
                readOnly
                placeholder="Chưa chọn thư mục nào"
              />
              {selectedFolder && (
                <button
                  type="button"
                  className="btn-clear"
                  title="Xoá thư mục đã chọn"
                  disabled={isLoading}
                  onClick={() => setSelectedFolder('')}
                >✕</button>
              )}
            </div>
            <button
              className="btn-browse"
              onClick={handleBrowse}
              disabled={isLoading}
              type="button"
            >
              Chọn thư mục
            </button>
          </div>
        </div>
      </div>

      {/* ── Phạm vi phân tích ── */}
      <div className="section">
        <div className="section-label">Những gì sẽ được kiểm tra</div>
        <div className="scope-cards">
          {SCOPE_CARDS.map((card, i) => (
            <div key={i} className="scope-card">
              <div className="scope-card-check">{card.icon}</div>
              <div>
                <div className="scope-card-title">{card.title}</div>
                <div className="scope-card-desc">{card.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Sticky CTA ── */}
      <div className="left-panel-cta">
        <button
          className="btn-primary"
          onClick={performProjectScan}
          disabled={isLoading || !selectedFolder}
          title={!selectedFolder ? 'Vui lòng chọn thư mục trước khi phân tích' : 'Bắt đầu phân tích bảo mật (Ctrl+Enter)'}
        >
          {isLoading ? (
            <><span className="spinner-sm" style={{ borderColor: 'rgba(42,54,59,.2)', borderTopColor: 'var(--text)' }} /> Đang phân tích…</>
          ) : (
            <>Bắt đầu phân tích mã nguồn</>
          )}
        </button>
        <p
          className="form-hint-below"
          style={{
            visibility: selectedFolder || isLoading ? 'hidden' : 'visible',
            minHeight: '15px'
          }}
        >
          Chọn thư mục phía trên để kích hoạt nút phân tích
        </p>
      </div>
    </>
  );
};
