import { create } from 'zustand';
import { AuthConfig, ChecklistData, Finding, ScanHistoryEntry, ScanProgressEvent, ScanResult } from '../types';
import { redactDeep } from '../utils/redact';

const HISTORY_KEY  = 'sentinel_v2_history';
const THEME_KEY    = 'sentinel_v2_theme';
const FINDING_STATUS_KEY = 'sentinel_v2_finding_statuses';
const RESULTS_DENSITY_KEY = 'sentinel_v2_results_density';
const MAX_HISTORY  = 10;
const MAX_LOG      = 200;

type ThemeMode = 'dark' | 'light';
type FindingStatus = 'new' | 'triaged' | 'in-progress' | 'mitigated';
type ResultsDensity = 'comfort' | 'compact';

function getInitialTheme(): ThemeMode {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === 'dark' || stored === 'light') return stored;
  } catch (_e) { void 0; }
  return 'dark';
}

function getInitialFindingStatuses(): Record<string, FindingStatus> {
  try {
    const raw = localStorage.getItem(FINDING_STATUS_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, string>;
    const out: Record<string, FindingStatus> = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (v === 'new' || v === 'triaged' || v === 'in-progress' || v === 'mitigated') {
        out[k] = v;
      }
    }
    return out;
  } catch (_e) {
    return {};
  }
}

function saveFindingStatuses(map: Record<string, FindingStatus>) {
  try {
    localStorage.setItem(FINDING_STATUS_KEY, JSON.stringify(map));
  } catch (_e) { void 0; }
}

function getInitialResultsDensity(): ResultsDensity {
  try {
    const raw = localStorage.getItem(RESULTS_DENSITY_KEY);
    if (raw === 'compact' || raw === 'comfort') return raw;
  } catch (_e) { void 0; }
  return 'comfort';
}

// ── IndexedDB helpers ──────────────────────────────────────────────────────
const DB_NAME = 'SentinelV2DB';
const STORE_NAME = 'historyStore';

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE_NAME)) {
        req.result.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function loadHistoryFromDB(): Promise<ScanHistoryEntry[]> {
  try {
    const db = await openDB();
    return new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(HISTORY_KEY);
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => resolve([]);
    });
  } catch (_e) {
    try {
      const raw = localStorage.getItem(HISTORY_KEY) || '[]';
      return JSON.parse(raw);
    } catch { return []; }
  }
}

async function saveHistoryToDB(h: ScanHistoryEntry[]) {
  try {
    const db = await openDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(h, HISTORY_KEY);
  } catch (_e) {
    try {
      const slim = h.map(e => ({
        ...e,
        scanResult: {
          ...e.scanResult,
          findings: e.scanResult.findings.slice(0, 50),
        },
      }));
      localStorage.setItem(HISTORY_KEY, JSON.stringify(slim.slice(0, Math.max(1, Math.floor(slim.length / 2)))));
    } catch { void 0; }
  }
}

function calcRiskScore(findings: ScanResult['findings']): number {
  const SEV_W: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 1 };
  return Math.min(100, findings.reduce((s, f) => s + (SEV_W[f.severity] || 0), 0));
}

export function isLocalUrl(url: string): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    const h = parsed.hostname.toLowerCase();
    return (
      h === 'localhost' ||
      h === '127.0.0.1' ||
      h === '::1' ||
      h.endsWith('.localhost') ||
      /^10\./.test(h) ||
      /^192\.168\./.test(h) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(h)
    );
  } catch {
    return false;
  }
}

export function mergeFindings(urlFindings: Finding[], projectFindings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const result: Finding[] = [];
  const normalizeFindingForUi = (f: Finding): Finding => ({
    ...f,
    owaspCategory: f.owaspCategory || (f as Finding & { category?: string }).category || 'OTHER',
  });
  const makeKey = (f: Finding) => [
    f.ruleId,
    f.owaspCategory || (f as Finding & { category?: string }).category || 'OTHER',
    f.severity,
    f.confidence,
    f.collector,
    f.target,
    f.location,
    f.title,
  ].join('||');

  for (const f of urlFindings) {
    const key = makeKey(f);
    if (!seen.has(key)) { seen.add(key); result.push(normalizeFindingForUi(f)); }
  }
  for (const f of projectFindings) {
    const key = makeKey(f);
    if (!seen.has(key)) { seen.add(key); result.push(normalizeFindingForUi(f)); }
  }
  return result;
}

const ipc = () => {
  if (typeof window !== 'undefined' && window.owaspWorkbench) return window.owaspWorkbench;
  throw new Error('Ứng dụng cần chạy trong Electron. Khởi động bằng npm run dev.');
};

interface AppState {
  activeTab: 'url' | 'project' | 'checklist';
  setActiveTab: (tab: 'url' | 'project' | 'checklist') => void;
  isLoading: boolean;
  urlScanResult: ScanResult | null;
  projectScanResult: ScanResult | null;
  error: string | null;
  urlScanIsLocal: boolean;
  getCombinedFindings: () => Finding[];
  checkedChecklistItems: string[];
  toggleChecklistItem: (id: string) => void;
  urlInput: string;
  authConfig: AuthConfig;
  setUrlInput: (url: string) => void;
  setAuthConfig: (config: Partial<AuthConfig>) => void;
  crawlDepth: number;
  requestBudget: number;
  setCrawlDepth: (n: number) => void;
  setRequestBudget: (n: number) => void;
  selectedFolder: string | null;
  setSelectedFolder: (folder: string | null) => void;
  checklist: ChecklistData | null;
  progressLog: ScanProgressEvent[];
  appendProgress: (ev: ScanProgressEvent) => void;
  clearProgress: () => void;
  history: ScanHistoryEntry[];
  loadHistory: () => Promise<void>;
  saveToHistory: (result: ScanResult) => Promise<void>;
  restoreFromHistory: (id: string) => void;
  removeHistoryEntry: (id: string) => Promise<void>;
  clearHistory: () => Promise<void>;
  showHistoryDropdown: boolean;
  setShowHistoryDropdown: (show: boolean) => void;
  themeMode: ThemeMode;
  setThemeMode: (mode: ThemeMode) => void;
  toggleThemeMode: () => void;
  resultsDensity: ResultsDensity;
  setResultsDensity: (mode: ResultsDensity) => void;
  findingStatuses: Record<string, FindingStatus>;
  setFindingStatus: (scopeKey: string, findingKey: string, status: FindingStatus) => void;
  getFindingStatus: (scopeKey: string, findingKey: string) => FindingStatus | undefined;
  clearFindingStatuses: (scopeKey?: string) => void;
  performUrlScan: () => Promise<void>;
  performProjectScan: () => Promise<void>;
  stopScan: () => Promise<void>;
  loadChecklist: () => Promise<void>;
  resetScan: () => void;
  resetUrlScanResult: () => void;
  resetProjectScanResult: () => void;
  exportReport: (format: 'json' | 'html') => Promise<void>;

  // BUG FIX: Phiên bản cũ lưu `cb` (callback người dùng) vào _progressListener.
  // Nhưng `onScanProgress(cb)` trong preload.js tạo ra một inner listener wrapper
  //   `const listener = (_e, msg) => cb(msg);`
  // và RETURN về listener đó. `offScanProgress` cần đúng listener này để removeListener.
  // Nếu ta truyền `cb` vào offScanProgress → ipcRenderer.removeListener('scan:progress', cb)
  // → KHÔNG TÌM THẤY listener, không remove được → listener leak sau mỗi lần scan.
  // FIX: lưu GIÁ TRỊ TRẢ VỀ của onScanProgress() thay vì lưu cb.
  _progressListener: unknown | null;
}

export const useStore = create<AppState>((set, get) => ({
  activeTab:  'url',
  setActiveTab: (tab) => set({ activeTab: tab }),
  isLoading: false,
  urlScanResult: null,
  projectScanResult: null,
  error: null,
  urlScanIsLocal: false,

  getCombinedFindings: () => {
    const { urlScanResult, projectScanResult } = get();
    const urlFindings  = urlScanResult?.findings ?? [];
    const projFindings = projectScanResult?.findings ?? [];
    return mergeFindings(urlFindings, projFindings);
  },

  checkedChecklistItems: [],
  toggleChecklistItem: (id) => set((s) => ({
    checkedChecklistItems: s.checkedChecklistItems.includes(id)
      ? s.checkedChecklistItems.filter(i => i !== id)
      : [...s.checkedChecklistItems, id],
  })),

  urlInput: '',
  authConfig: { cookie: '', bearerToken: '', authorization: '', customHeaders: '' },
  setUrlInput: (url) => set({ urlInput: url }),
  setAuthConfig: (config) => set((s) => ({ authConfig: { ...s.authConfig, ...config } })),

  crawlDepth: 1,
  requestBudget: 30,
  setCrawlDepth: (n) => set({ crawlDepth: n }),
  setRequestBudget: (n) => set({ requestBudget: n }),

  selectedFolder: null,
  setSelectedFolder: (folder) => set({ selectedFolder: folder }),

  checklist: null,

  progressLog: [],
  appendProgress: (ev) => set((s) => ({
    progressLog: s.progressLog.length >= MAX_LOG
      ? [...s.progressLog.slice(-MAX_LOG + 1), ev]
      : [...s.progressLog, ev],
  })),
  clearProgress: () => set({ progressLog: [] }),

  history: [],
  loadHistory: async () => {
    const data = await loadHistoryFromDB();
    set({ history: data });
  },

  saveToHistory: async (result) => {
    const sanitizedResult = redactDeep(result);
    const riskScore = calcRiskScore(sanitizedResult.findings);
    const entry: ScanHistoryEntry = {
      id:       Date.now().toString(),
      ts:       Date.now(),
      mode:     sanitizedResult.mode,
      target:   sanitizedResult.scannedUrl || sanitizedResult.target || '',
      riskScore,
      summary:  { total: sanitizedResult.metadata.summary.total, bySeverity: sanitizedResult.metadata.summary.bySeverity },
      scanResult: sanitizedResult,
    };
    const updated = [entry, ...get().history].slice(0, MAX_HISTORY);
    set({ history: updated });
    await saveHistoryToDB(updated);
  },

  restoreFromHistory: (id) => {
    const entry = get().history.find((e) => e.id === id);
    if (entry) {
      if (entry.mode === 'url-scan') {
        const local = isLocalUrl(entry.scanResult.scannedUrl || '');
        set({ urlScanResult: entry.scanResult, urlScanIsLocal: local, activeTab: 'url', error: null, showHistoryDropdown: false });
      } else {
        set({ projectScanResult: entry.scanResult, activeTab: 'project', error: null, showHistoryDropdown: false });
      }
    }
  },

  removeHistoryEntry: async (id) => {
    const updated = get().history.filter((entry) => entry.id !== id);
    set({ history: updated });
    await saveHistoryToDB(updated);
  },

  clearHistory: async () => {
    set({ history: [] });
    await saveHistoryToDB([]);
  },

  showHistoryDropdown: false,
  setShowHistoryDropdown: (show) => set({ showHistoryDropdown: show }),

  themeMode: getInitialTheme(),
  setThemeMode: (mode) => {
    try { localStorage.setItem(THEME_KEY, mode); } catch (_e) { void 0; }
    set({ themeMode: mode });
  },
  toggleThemeMode: () => {
    const next = get().themeMode === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, next); } catch (_e) { void 0; }
    set({ themeMode: next });
  },

  resultsDensity: getInitialResultsDensity(),
  setResultsDensity: (mode) => {
    try { localStorage.setItem(RESULTS_DENSITY_KEY, mode); } catch (_e) { void 0; }
    set({ resultsDensity: mode });
  },

  findingStatuses: getInitialFindingStatuses(),
  setFindingStatus: (scopeKey, findingKey, status) => {
    const id = `${scopeKey}::${findingKey}`;
    set((s) => {
      const next = { ...s.findingStatuses, [id]: status };
      saveFindingStatuses(next);
      return { findingStatuses: next };
    });
  },
  getFindingStatus: (scopeKey, findingKey) => {
    const id = `${scopeKey}::${findingKey}`;
    return get().findingStatuses[id];
  },
  clearFindingStatuses: (scopeKey) => {
    if (!scopeKey) {
      saveFindingStatuses({});
      set({ findingStatuses: {} });
      return;
    }
    set((s) => {
      const next: Record<string, FindingStatus> = {};
      const scopePrefix = `${scopeKey}::`;
      for (const [k, v] of Object.entries(s.findingStatuses)) {
        if (!k.startsWith(scopePrefix)) next[k] = v;
      }
      saveFindingStatuses(next);
      return { findingStatuses: next };
    });
  },

  _progressListener: null,

  // ── Scan Actions ──────────────────────────────────────────
  performUrlScan: async () => {
    const { urlInput, authConfig, crawlDepth, requestBudget } = get();
    if (!urlInput.trim()) { set({ error: 'Vui lòng nhập URL mục tiêu' }); return; }
    get().clearProgress();
    set({ isLoading: true, error: null, urlScanResult: null, urlScanIsLocal: false });

    try {
      const cb = (ev: ScanProgressEvent) => get().appendProgress(ev);
      // BUG FIX: Lưu GIÁ TRỊ TRẢ VỀ của onScanProgress (là inner ipcRenderer listener),
      // không phải lưu `cb`. offScanProgress cần đúng reference này để removeListener.
      const listenerRef = window.owaspWorkbench?.onScanProgress?.(cb);
      set({ _progressListener: listenerRef ?? null });
    } catch (_e) { void 0; }

    try {
      const result = await ipc().scanUrl({ url: urlInput, auth: authConfig, maxDepth: crawlDepth, maxBudget: requestBudget });
      if (result.ok) {
        const local = isLocalUrl(urlInput);
        set({ urlScanResult: result, urlScanIsLocal: local, error: null });
        get().saveToHistory(result);
      } else {
        set({ error: result.error || 'Scan thất bại' });
      }
    } catch (err: Error | unknown) {
      set({ error: (err instanceof Error ? err.message : String(err)) || 'Lỗi không xác định' });
    } finally {
      try {
        // BUG FIX: truyền đúng listenerRef (returned từ onScanProgress) vào offScanProgress
        const listenerRef = get()._progressListener;
        window.owaspWorkbench?.offScanProgress?.(listenerRef ?? undefined);
      } catch (_e) { void 0; }
      set({ isLoading: false, _progressListener: null });
    }
  },

  performProjectScan: async () => {
    const { selectedFolder } = get();
    if (!selectedFolder) { set({ error: 'Vui lòng chọn thư mục project' }); return; }
    get().clearProgress();
    set({ isLoading: true, error: null, projectScanResult: null });

    try {
      const cb = (ev: ScanProgressEvent) => get().appendProgress(ev);
      // BUG FIX: tương tự performUrlScan — lưu returned listener ref
      const listenerRef = window.owaspWorkbench?.onScanProgress?.(cb);
      set({ _progressListener: listenerRef ?? null });
    } catch (_e) { void 0; }

    try {
      const result = await ipc().scanProject(selectedFolder);
      if (result.ok) { set({ projectScanResult: result, error: null }); get().saveToHistory(result); }
      else set({ error: result.error || 'Scan thất bại' });
    } catch (err: Error | unknown) {
      set({ error: (err instanceof Error ? err.message : String(err)) || 'Lỗi không xác định' });
    } finally {
      try {
        const listenerRef = get()._progressListener;
        window.owaspWorkbench?.offScanProgress?.(listenerRef ?? undefined);
      } catch (_e) { void 0; }
      set({ isLoading: false, _progressListener: null });
    }
  },

  stopScan: async () => {
    try {
      await window.owaspWorkbench?.stopScan?.();
    } catch (_e) { void 0; }
    // Cleanup listener trước khi set isLoading: false
    try {
      const listenerRef = get()._progressListener;
      window.owaspWorkbench?.offScanProgress?.(listenerRef ?? undefined);
    } catch (_e) { void 0; }
    set({ isLoading: false, error: 'Scan đã bị hủy bởi người dùng.', _progressListener: null });
  },

  loadChecklist: async () => {
    if (get().checklist) return;
    try {
      const r = await ipc().getChecklist();
      if (r.ok && r.data) set({ checklist: r.data });
    } catch (err: Error | unknown) {
      console.warn('Checklist unavailable:', err instanceof Error ? err.message : String(err));
    }
  },

  resetScan: () => {
    if (get().activeTab === 'url') set({ urlScanResult: null, urlScanIsLocal: false, error: null });
    else set({ projectScanResult: null, checkedChecklistItems: [], error: null });
  },

  resetUrlScanResult: () => set({ urlScanResult: null, urlScanIsLocal: false, error: null }),
  resetProjectScanResult: () => set({ projectScanResult: null, checkedChecklistItems: [], error: null }),

  exportReport: async (format) => {
    const { urlScanResult, projectScanResult, activeTab } = get();
    const scanResult = activeTab === 'url' ? urlScanResult : projectScanResult;
    if (!scanResult) { set({ error: 'Không có kết quả scan để xuất báo cáo' }); return; }
    try {
      const r = await ipc().exportReport({ format, scanResult });
      if (!r.ok && !r.canceled) set({ error: r.error || 'Xuất báo cáo thất bại' });
    } catch (err: Error | unknown) {
      set({ error: (err instanceof Error ? err.message : String(err)) || 'Xuất báo cáo thất bại' });
    }
  },
}));

useStore.getState().loadHistory();
