import { useEffect, useState } from 'react';
import { initOrchestrator } from './ai/llm/hybridOrchestrator';
import { buildLLMRouter } from './ai/llm/providerRegistry';
import { AIChatWidget } from './components/AIChatWidget';
import { ChecklistPanel } from './components/ChecklistPanel';
import { ChecklistRightPanel } from './components/ChecklistRightPanel';
import { HistoryPanel } from './components/HistoryPanel';
import { ProjectScanForm } from './components/ProjectScanForm';
import { ResultsPanel } from './components/ResultsPanel';
import { ScanProgress } from './components/ScanProgress';
import { UrlScanForm } from './components/UrlScanForm';
import { useStore } from './store/useStore';

type AppTab = 'url' | 'project' | 'checklist';

function App() {
  const {
    activeTab, setActiveTab, isLoading,
    showHistoryDropdown, setShowHistoryDropdown, history,
    themeMode, toggleThemeMode,
    performUrlScan, performProjectScan, exportReport,
  } = useStore();
  const [showShortcutHelp, setShowShortcutHelp] = useState(false);

  useEffect(() => {
    try {
      initOrchestrator(buildLLMRouter());
    } catch (err) {
      console.warn('[SENTINEL] LLM router init failed:', err);
    }
  }, []);

  useEffect(() => {
    document.body.classList.remove('theme-dark', 'theme-light');
    document.body.classList.add(`theme-${themeMode}`);
  }, [themeMode]);

  useEffect(() => {
    const isEditable = (target: EventTarget | null) => {
      const el = target as HTMLElement | null;
      if (!el) return false;
      const tag = el.tagName.toLowerCase();
      return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
    };

    const onKeyDown = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (!mod) return;
      const key = e.key.toLowerCase();
      const editable = isEditable(e.target);
      if (key === '/') { e.preventDefault(); setShowShortcutHelp((v) => !v); return; }
      if (editable) return;
      if (key === '1') { e.preventDefault(); setActiveTab('url'); return; }
      if (key === '2') { e.preventDefault(); setActiveTab('project'); return; }
      if (key === '3') { e.preventDefault(); setActiveTab('checklist'); return; }
      if (key === '6') { e.preventDefault(); setShowHistoryDropdown(!showHistoryDropdown); return; }
      if (key === '7') { e.preventDefault(); exportReport('html'); return; }
      if (key === '8') { e.preventDefault(); toggleThemeMode(); return; }
      if (key === 'enter') {
        e.preventDefault();
        if (activeTab === 'url') void performUrlScan();
        if (activeTab === 'project') void performProjectScan();
      }
    };
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setShowShortcutHelp(false); setShowHistoryDropdown(false); }
    };
    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('keydown', onEsc);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('keydown', onEsc);
    };
  }, [activeTab, exportReport, performProjectScan, performUrlScan, setActiveTab, setShowHistoryDropdown, showHistoryDropdown, toggleThemeMode]);

  const switchTab = (tab: AppTab) => setActiveTab(tab);
  const isChecklist = activeTab === 'checklist';
  const isUrlScan = activeTab === 'url';

  const leftPanelTitle = isChecklist ? 'Checklist' : isUrlScan ? 'Cấu hình quét' : 'Chọn dự án';
  const leftPanelSub = isChecklist
    ? 'Tổng hợp việc cần làm từ kết quả quét và đánh giá thiết kế.'
    : isUrlScan
      ? 'Nhập URL và cấu hình mức độ quét.'
      : 'Chọn thư mục mã nguồn để phân tích bảo mật.';

  const rightPanelTitle = isChecklist ? 'Checklist tổng hợp' : 'Kết quả quét';

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-logo">
          <img className="logo-icon" src="./app-icon.png" alt="" aria-hidden="true" />
          <div>
            <div className="logo-text">SENTINEL</div>
            <div className="logo-sub">OWASP 2025</div>
          </div>
        </div>

        <div className="header-divider" />

        <nav className="nav-tabs" role="tablist">
          <button
            role="tab"
            aria-selected={activeTab === 'url'}
            className={`nav-tab ${activeTab === 'url' ? 'active' : ''}`}
            onClick={() => switchTab('url')}
            title="Kiểm tra bảo mật website (Ctrl+1)"
          >
            Quét Website
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'project'}
            className={`nav-tab ${activeTab === 'project' ? 'active' : ''}`}
            onClick={() => switchTab('project')}
            title="Phân tích bảo mật mã nguồn (Ctrl+2)"
          >
            Quét Mã Nguồn
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'checklist'}
            className={`nav-tab ${activeTab === 'checklist' ? 'active' : ''}`}
            onClick={() => switchTab('checklist')}
            title="Checklist xử lý và đánh giá bảo mật (Ctrl+3)"
          >
            Checklist
          </button>
        </nav>

        <div className="header-gap" />

        <div className="header-actions">
          <div className="status-indicator" title={isLoading ? 'Đang chạy quét...' : 'Sẵn sàng'}>
            <div className={`status-dot ${isLoading ? 'active' : ''}`} />
            <span>{isLoading ? 'Đang quét' : 'Sẵn sàng'}</span>
          </div>

          <div className="header-actions-divider" />

          <div className="hist-btn-wrap">
            <button
              className={`btn-header ${showHistoryDropdown ? 'btn-header-active' : ''}`}
              onClick={() => setShowHistoryDropdown(!showHistoryDropdown)}
              title="Xem lịch sử quét (Ctrl+6)"
            >
              Lịch sử
              {history.length > 0 && <span className="hist-badge">{history.length}</span>}
            </button>
            {showHistoryDropdown && <HistoryPanel />}
          </div>

          <button
            className="btn-header"
            onClick={toggleThemeMode}
            title={themeMode === 'dark' ? 'Chuyển giao diện sáng (Ctrl+8)' : 'Chuyển giao diện tối (Ctrl+8)'}
          >
            {themeMode === 'dark' ? 'Sáng' : 'Tối'}
          </button>

          <button
            className="btn-header"
            onClick={() => setShowShortcutHelp(true)}
            title="Xem phím tắt (Ctrl+/)"
            aria-label="Phím tắt"
          >
            Phím tắt
          </button>
        </div>
      </header>

      {isChecklist ? (
        <div className="workspace workspace-checklist-v2">
          <aside className="left-panel checklist-control-panel">
            <div className="layout-panel-head">
              <div className="layout-panel-title">{leftPanelTitle}</div>
              <div className="layout-panel-sub">{leftPanelSub}</div>
            </div>
            <ChecklistPanel />
          </aside>
          <main className="right-panel checklist-main-panel checklist-right-panel">
            <div className="layout-panel-head">
              <div className="layout-panel-title">{rightPanelTitle}</div>
              <div className="layout-panel-sub">Ưu tiên xử lý theo mức độ rủi ro, nguồn phát hiện và nguyên tắc OWASP.</div>
            </div>
            {isLoading ? <ScanProgress /> : <ChecklistRightPanel />}
          </main>
        </div>
      ) : (
        <div className="workspace workspace-scan-v2">
          <aside className="left-panel scan-config-panel">
            <div className="layout-panel-head">
              <div className="layout-panel-title">{leftPanelTitle}</div>
              <div className="layout-panel-sub">{leftPanelSub}</div>
            </div>
            {activeTab === 'url' && <UrlScanForm />}
            {activeTab === 'project' && <ProjectScanForm />}
          </aside>
          <main className="right-panel scan-results-panel">
            {isLoading ? <ScanProgress /> : <ResultsPanel />}
          </main>
        </div>
      )}

      {showShortcutHelp && (
        <div className="shortcut-overlay" onClick={() => setShowShortcutHelp(false)}>
          <div className="shortcut-modal" onClick={(e) => e.stopPropagation()}>
            <div className="shortcut-modal-head">
              <div className="shortcut-title">Phím tắt nhanh</div>
              <button className="btn-header" onClick={() => setShowShortcutHelp(false)}>Đóng</button>
            </div>
            <div className="shortcut-list">
              <div className="shortcut-row"><span>Chuyển sang Quét Website</span><kbd>Ctrl + 1</kbd></div>
              <div className="shortcut-row"><span>Chuyển sang Quét Mã Nguồn</span><kbd>Ctrl + 2</kbd></div>
              <div className="shortcut-row"><span>Chuyển sang Checklist</span><kbd>Ctrl + 3</kbd></div>
              <div className="shortcut-row"><span>Mở / đóng Lịch sử</span><kbd>Ctrl + 6</kbd></div>
              <div className="shortcut-row"><span>Xuất báo cáo HTML</span><kbd>Ctrl + 7</kbd></div>
              <div className="shortcut-row"><span>Đổi giao diện</span><kbd>Ctrl + 8</kbd></div>
              <div className="shortcut-row"><span>Bắt đầu quét tab hiện tại</span><kbd>Ctrl + Enter</kbd></div>
              <div className="shortcut-row"><span>Hiện / ẩn phím tắt</span><kbd>Ctrl + /</kbd></div>
              <div className="shortcut-row"><span>Đóng panel / modal</span><kbd>Esc</kbd></div>
            </div>
          </div>
        </div>
      )}

      <AIChatWidget />
    </div>
  );
}

export default App;
