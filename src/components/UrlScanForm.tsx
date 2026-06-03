import React, { useState } from 'react';
import { useStore } from '../store/useStore';
import { URL_SCAN_COVERAGE } from '../utils/owasp';

const DEPTH_OPTIONS = [
  { value: 0, label: 'Chỉ trang gốc',   desc: 'Chỉ quét đúng URL bạn nhập vào — nhanh nhất' },
  { value: 1, label: '1 cấp liên kết',  desc: 'Theo các liên kết từ trang gốc — khuyến nghị cho người mới' },
  { value: 2, label: '2 cấp liên kết',  desc: 'Quét sâu hơn, phủ rộng hơn nhưng chậm hơn' },
];

const BUDGET_OPTIONS = [
  { value: 30,  label: 'Nhẹ — 30 yêu cầu',        desc: 'Quét nhanh, phù hợp thử nghiệm ban đầu' },
  { value: 60,  label: 'Cân bằng — 60 yêu cầu',   desc: 'Mức khuyến nghị — đủ kỹ, không quá lâu' },
  { value: 100, label: 'Kỹ — 100 yêu cầu',        desc: 'Nhiều bài kiểm tra hơn, cần thêm thời gian' },
  { value: 200, label: 'Chuyên sâu — 200 yêu cầu', desc: 'Toàn diện nhất — có thể mất 2–3 phút' },
];

function getScanProfile(depth: number, budget: number) {
  if (depth >= 2 || budget >= 100) return { label: 'Chuyên sâu', kind: 'deep',     est: '60–120 giây' };
  if (depth === 1 && budget >= 60)  return { label: 'Cân bằng',   kind: 'balanced', est: '30–60 giây' };
  return                                   { label: 'Nhanh',      kind: 'fast',     est: '10–30 giây' };
}

export const UrlScanForm: React.FC = () => {
  const {
    urlInput, setUrlInput, authConfig, setAuthConfig,
    performUrlScan, isLoading,
    crawlDepth, setCrawlDepth, requestBudget, setRequestBudget,
  } = useStore();
  const [showAuth, setShowAuth] = useState(false);
  const [showCoverage, setShowCoverage] = useState(false);

  const profile = getScanProfile(crawlDepth, requestBudget);

  return (
    <>
      {/* ── Hướng dẫn nhanh ── */}
      <div className="onboarding-tip">
        <strong>Bắt đầu nhanh:</strong> Nhập URL website, giữ cài đặt mặc định rồi bắt đầu quét.
        Nếu mới dùng, bạn chưa cần chỉnh các tuỳ chọn nâng cao.
      </div>

      {/* ── Mục tiêu ── */}
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
          <div className="scan-scope-title">Quét Website kiểm tra gì?</div>
          <p className="scan-scope-copy">
            Kiểm tra website đang chạy qua HTTP: header, endpoint, form/input và response công khai. Không đọc mã nguồn.
          </p>
        </div>
        <div className="owasp-chip-grid">
          {URL_SCAN_COVERAGE.map((item) => (
            <span key={item.id} className="owasp-scope-chip" title={item.summary}>
              <strong>{item.id}</strong> {item.name}
            </span>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="section-label">Địa chỉ website</div>

        <div className="field">
          <label className="field-label" htmlFor="url-input">URL cần quét</label>
          <div className="input-clear-row">
            <input
              id="url-input"
              type="text"
              placeholder="https://example.com"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              disabled={isLoading}
              onKeyDown={(e) => e.key === 'Enter' && !isLoading && performUrlScan()}
              autoComplete="off"
            />
            {urlInput && (
              <button
                type="button"
                className="btn-clear"
                title="Xoá URL"
                disabled={isLoading}
                onClick={() => setUrlInput('')}
              >✕</button>
            )}
          </div>
        </div>
      </div>

      {/* ── Cấu hình quét ── */}
      <div className="section">
        <div className="section-label">Mức độ quét</div>

        <div className="field-row">
          <div className="field">
            <label className="field-label field-label-inline" htmlFor="crawl-depth">
              Phạm vi
              <span className="field-help" title={DEPTH_OPTIONS.find(o => o.value === crawlDepth)?.desc}>?</span>
            </label>
            <select
              id="crawl-depth"
              value={crawlDepth}
              onChange={(e) => setCrawlDepth(Number(e.target.value))}
              disabled={isLoading}
            >
              {DEPTH_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="field">
            <label className="field-label field-label-inline" htmlFor="request-budget">
              Cường độ
              <span className="field-help" title={BUDGET_OPTIONS.find(o => o.value === requestBudget)?.desc}>?</span>
            </label>
            <select
              id="request-budget"
              value={requestBudget}
              onChange={(e) => setRequestBudget(Number(e.target.value))}
              disabled={isLoading}
            >
              {BUDGET_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
        </div>

        {/* Badge tốc độ */}
        <div className="scan-profile-row">
          <span className={`scan-speed-badge scan-speed-${profile.kind}`}>{profile.label}</span>
          <span className="scan-profile-est">Ước tính {profile.est}</span>
        </div>
      </div>

      {/* ── Xác thực (tuỳ chọn) ── */}
      <div className="section">
        <button
          type="button"
          className={`collapsible-btn ${showAuth ? 'open' : ''}`}
          onClick={() => setShowAuth(!showAuth)}
          aria-expanded={showAuth}
        >
          <span>Xác thực <span className="optional-tag">không bắt buộc</span></span>
          <span className={`collapsible-icon ${showAuth ? 'open' : ''}`}>›</span>
        </button>

        {showAuth && (
          <div className="collapsible-body">
            <p className="auth-hint">Chỉ cần điền nếu website yêu cầu đăng nhập để truy cập nội dung.</p>

            <div className="field">
              <label className="field-label" htmlFor="auth-cookie">Cookie phiên đăng nhập</label>
              <input id="auth-cookie" type="text" placeholder="session=abc123; token=xyz"
                value={authConfig.cookie}
                onChange={(e) => setAuthConfig({ cookie: e.target.value })}
                disabled={isLoading} />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="auth-bearer">Token Bearer</label>
              <input id="auth-bearer" type="text" placeholder="eyJhbGci..."
                value={authConfig.bearerToken}
                onChange={(e) => setAuthConfig({ bearerToken: e.target.value })}
                disabled={isLoading} />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="auth-authz">Header Authorization</label>
              <input id="auth-authz" type="text" placeholder="Basic dXNlcjpwYXNz"
                value={authConfig.authorization}
                onChange={(e) => setAuthConfig({ authorization: e.target.value })}
                disabled={isLoading} />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="auth-custom">Header tuỳ chỉnh (JSON)</label>
              <textarea
                id="auth-custom"
                placeholder='{"X-API-Key": "abc123"}'
                value={typeof authConfig.customHeaders === 'string'
                  ? authConfig.customHeaders
                  : JSON.stringify(authConfig.customHeaders || {}, null, 2)}
                onChange={(e) => setAuthConfig({ customHeaders: e.target.value })}
                disabled={isLoading} rows={2}
              />
            </div>
          </div>
        )}
      </div>

      {/* ── Sticky CTA ── */}
      <div className="left-panel-cta">
        <button
          className="btn-primary"
          onClick={performUrlScan}
          disabled={isLoading || !urlInput.trim()}
          title={!urlInput.trim() ? 'Vui lòng nhập URL trước khi quét' : 'Bắt đầu quét bảo mật (Ctrl+Enter)'}
        >
          {isLoading ? (
            <><span className="spinner-sm" style={{ borderColor: 'rgba(42,54,59,.2)', borderTopColor: 'var(--text)' }} /> Đang quét…</>
          ) : (
            <>Bắt đầu quét website</>
          )}
        </button>
        {!urlInput.trim() && !isLoading && (
          <p className="form-hint-below">Nhập URL phía trên để kích hoạt nút quét</p>
        )}
      </div>
    </>
  );
};
