import React, { useMemo, useState } from 'react';
import { useStore } from '../store/useStore';

function timeAgo(ts: number): string {
  const m = Math.floor((Date.now() - ts) / 60000);
  if (m < 1)  return 'vừa xong';
  if (m < 60) return `${m}p trước`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h trước`;
  return `${Math.floor(h / 24)}d trước`;
}

function riskScoreColor(score?: number): string {
  if (!score) return 'var(--text-3)';
  if (score >= 70) return 'var(--crit)';
  if (score >= 40) return 'var(--high)';
  if (score >= 15) return 'var(--med)';
  return 'var(--low)';
}

export const HistoryPanel: React.FC<{ onOpenShortcuts?: () => void }> = ({ onOpenShortcuts: _onOpenShortcuts }) => {
  const { history, restoreFromHistory, removeHistoryEntry, clearHistory, setShowHistoryDropdown } = useStore();
  const [query, setQuery]           = useState('');
  const [modeFilter, setModeFilter] = useState<'all' | 'url-scan' | 'project-scan'>('all');
  const [confirmClear, setConfirmClear] = useState(false);

  const visible = useMemo(() => {
    return history.filter((entry) => {
      const byMode = modeFilter === 'all' || entry.mode === modeFilter;
      const byText =
        query.trim().length === 0 ||
        entry.target.toLowerCase().includes(query.toLowerCase());
      return byMode && byText;
    });
  }, [history, modeFilter, query]);

  return (
    <>
      {/* Backdrop */}
      <div className="hist-backdrop" onClick={() => setShowHistoryDropdown(false)} />

      <div className="hist-dropdown">

        {/* Header */}
        <div className="hist-hdr">
          <span className="hist-hdr-title">Lịch sử quét</span>
          <div className="hist-hdr-actions">
            {history.length > 0 && !confirmClear && (
              <button
                className="btn-history-clear"
                onClick={() => setConfirmClear(true)}
                title="Xóa toàn bộ - không thể hoàn tác"
              >
                Xóa tất cả
              </button>
            )}
            {confirmClear && (
              <div style={{ display: 'flex', gap: '4px' }}>
                <button
                  className="btn-history-clear"
                  style={{ background: 'var(--crit-bg)', borderColor: 'var(--crit-b)', color: 'var(--crit)' }}
                  onClick={() => { clearHistory(); setConfirmClear(false); }}
                >
                  Xác nhận xóa
                </button>
                <button
                  className="btn-history-clear"
                  onClick={() => setConfirmClear(false)}
                >
                  Hủy
                </button>
              </div>
            )}
            <button
              className="btn-history-close"
              onClick={() => setShowHistoryDropdown(false)}
              title="Đóng"
              aria-label="Đóng"
            >
              ×
            </button>
          </div>
        </div>

        {/* Search + filter */}
        <div className="hist-tools">
          <input
            className="hist-search"
            type="text"
            placeholder="Tìm mục tiêu..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select
            className="hist-filter"
            value={modeFilter}
            onChange={(e) => setModeFilter(e.target.value as 'all' | 'url-scan' | 'project-scan')}
          >
            <option value="all">Tất cả</option>
            <option value="url-scan">Website</option>
            <option value="project-scan">Mã nguồn</option>
          </select>
        </div>

        {/* Empty state */}
        {history.length === 0 ? (
          <div className="hist-empty">
            <div style={{ fontSize: 22, opacity: 0.25 }}>▷</div>
            <div>Chưa có lịch sử quét</div>
            <div style={{ fontSize: 10 }}>Kết quả sẽ được lưu sau khi quét xong</div>
          </div>
        ) : (
          <div className="hist-list">
            {visible.map((entry) => {
              const { bySeverity, total } = entry.summary;
              return (
                <div key={entry.id} className="hist-entry-row">
                  <button
                    className="hist-entry"
                    onClick={() => restoreFromHistory(entry.id)}
                    title={entry.target}
                  >
                  {/* Top row: mode badge + target + time */}
                  <div className="hist-entry-top">
                    <span className={`hist-entry-mode-badge ${entry.mode === 'url-scan' ? 'mode-url' : 'mode-proj'}`}>
                      {entry.mode === 'url-scan' ? 'URL' : 'SRC'}
                    </span>
                    <span className="hist-entry-target">{entry.target}</span>
                    <span className="hist-entry-time">{timeAgo(entry.ts)}</span>
                  </div>

                  {/* Bottom row: sev chips + risk score */}
                  <div className="hist-entry-bottom">
                    <div className="hist-entry-chips">
                      {(bySeverity.critical || 0) > 0 && <span className="sev-chip chip-outline chip-crit">{bySeverity.critical} C</span>}
                      {(bySeverity.high     || 0) > 0 && <span className="sev-chip chip-outline chip-high">{bySeverity.high} H</span>}
                      {(bySeverity.medium   || 0) > 0 && <span className="sev-chip chip-outline chip-med">{bySeverity.medium} M</span>}
                      {(bySeverity.low      || 0) > 0 && <span className="sev-chip chip-outline chip-low">{bySeverity.low} L</span>}
                      {total === 0 && <span className="sev-chip chip-outline chip-info">Sạch ✓</span>}
                    </div>
                    {entry.riskScore !== undefined && (
                      <div
                        className="hist-risk-score"
                        style={{ color: riskScoreColor(entry.riskScore) }}
                      >
                        {entry.riskScore}/100
                      </div>
                    )}
                  </div>
                  </button>
                  <button
                    className="hist-entry-delete"
                    onClick={() => { void removeHistoryEntry(entry.id); }}
                    title="Xóa mục này"
                    aria-label="Xóa mục lịch sử này"
                  >
                    x
                  </button>
                </div>
              );
            })}
          </div>
        )}

        {/* Footer */}
        {history.length > 0 && (
          <div className="hist-footer">
            {visible.length}/{history.length} mục - click để khôi phục, x để xóa
          </div>
        )}

      </div>
    </>
  );
};
