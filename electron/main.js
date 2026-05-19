const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs   = require('fs/promises');
const fsSync = require('fs');
const { runUrlScan, runProjectScan, getChecklist } = require('../engine/scanner/scan-engine');
const { buildJsonReport, buildHtmlReport, getSuggestedFilename } = require('../engine/report/report-engine');

function loadLocalEnv() {
  const candidatePaths = [
    process.env.PORTABLE_EXECUTABLE_DIR ? path.join(process.env.PORTABLE_EXECUTABLE_DIR, '.env') : null,
    process.env.PORTABLE_EXECUTABLE_FILE ? path.join(path.dirname(process.env.PORTABLE_EXECUTABLE_FILE), '.env') : null,
    path.join(path.dirname(process.execPath), '.env'),
    path.join(app.getPath('userData'), '.env'),
    path.join(__dirname, '..', '.env'),
  ].filter(Boolean);

  for (const envPath of candidatePaths) {
    try {
      if (!fsSync.existsSync(envPath)) continue;
      const raw = fsSync.readFileSync(envPath, 'utf8');
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIndex = trimmed.indexOf('=');
        if (eqIndex === -1) continue;
        const key = trimmed.slice(0, eqIndex).trim();
        let value = trimmed.slice(eqIndex + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        if (!(key in process.env)) process.env[key] = value;
      }
    } catch {
      // Ignore .env loading errors in main process
    }
  }
}

function getWindowIconPath() {
  if (app.isPackaged) {
    return path.join(__dirname, 'renderer', 'app-icon.png');
  }
  return path.join(__dirname, '..', 'build', 'icon.png');
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1380, height: 920, minWidth: 1280, minHeight: 760,
    title: 'SENTINEL v2',
    icon: getWindowIconPath(),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
  });
  if (process.env.VITE_DEV_SERVER_URL) {
    win.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  }
}

// ── Shared abort controller for stop-scan ─────────────────────────────────
let currentScanAbort = null;

ipcMain.handle('scan:url', async (event, payload) => {
  // Cancel any previous scan
  currentScanAbort?.abort('New scan started');

  const ac = new AbortController();
  try {
    require('events').setMaxListeners(100, ac.signal);
  } catch (err) {
    // Fallback if setMaxListeners is not supported
    if (typeof ac.signal.setMaxListeners === 'function') {
      ac.signal.setMaxListeners(100);
    }
  }
  currentScanAbort = ac;

  try {
    const onProgress = (msg) => {
      try { event.sender.send('scan:progress', msg); } catch (_) {}
    };
    return await runUrlScan(payload?.url || '', {
      auth:        payload?.auth      || {},
      maxDepth:    payload?.maxDepth  ?? 1,
      maxBudget:   payload?.maxBudget ?? 30,
      onProgress,
      abortSignal: ac.signal,
    });
  } catch (error) {
    if (ac.signal.aborted) {
      return { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
    }
    return { ok: false, error: error?.message || 'Quét URL thất bại', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  } finally {
    if (currentScanAbort === ac) currentScanAbort = null;
  }
});

ipcMain.handle('scan:project', async (event, payload) => {
  currentScanAbort?.abort('New scan started');
  const ac = new AbortController();
  try {
    require('events').setMaxListeners(100, ac.signal);
  } catch (err) {
    if (typeof ac.signal.setMaxListeners === 'function') {
      ac.signal.setMaxListeners(100);
    }
  }
  currentScanAbort = ac;

  try {
    const folderPath = payload?.folderPath || '';
    const stat = await fs.stat(folderPath).catch(() => null);
    if (!stat?.isDirectory()) throw new Error('Thư mục quét không hợp lệ.');
    const onProgress = (msg) => {
      try { event.sender.send('scan:progress', msg); } catch {}
    };
    return await runProjectScan(folderPath, { onProgress, abortSignal: ac.signal });
  } catch (error) {
    if (ac.signal.aborted) {
      return { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
    }
    return { ok: false, error: error?.message || 'Quét mã nguồn thất bại', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  } finally {
    if (currentScanAbort === ac) currentScanAbort = null;
  }
});

// ── Stop Scan ─────────────────────────────────────────────────────────────
ipcMain.handle('scan:stop', () => {
  if (currentScanAbort) {
    currentScanAbort.abort('User cancelled');
    return { ok: true };
  }
  return { ok: false, error: 'Không có phiên quét đang chạy' };
});

ipcMain.handle('checklist:get', async () => {
  try { return { ok: true, data: getChecklist() }; }
  catch (error) { return { ok: false, error: error?.message || 'Tải Checklist thất bại' }; }
});

ipcMain.handle('dialog:pickFolder', async () => {
  const result = await dialog.showOpenDialog({ properties: ['openDirectory'] });
  if (result.canceled || !result.filePaths?.length) return { ok: false };
  return { ok: true, folderPath: result.filePaths[0] };
});

ipcMain.handle('docs:open', async (_event, url) => {
  try {
    const parsed = new URL(String(url || ''));
    const allowedHosts = new Set([
      'owasp.org',
      'cheatsheetseries.owasp.org',
      'github.com',
      'developer.mozilla.org',
    ]);
    if (parsed.protocol !== 'https:' || !allowedHosts.has(parsed.hostname)) {
      throw new Error('Blocked external URL');
    }
    await shell.openExternal(parsed.toString());
    return { ok: true };
  }
  catch (error) { return { ok: false, error: error?.message }; }
});

// ── AI Fetch Proxy (avoid CORS in renderer) ───────────────────────────────
const AI_ALLOWED_HOSTS = new Set([
  'openrouter.ai',
  'api.groq.com',
  'api.together.xyz',
  'api-inference.huggingface.co',
  'generativelanguage.googleapis.com',
]);

const AI_PROVIDER_CONFIG = {
  openrouter: {
    hosts: new Set(['openrouter.ai']),
    envKeys: ['OPENROUTER_API_KEY', 'VITE_OPENROUTER_API_KEY'],
    auth: 'bearer',
  },
  groq: {
    hosts: new Set(['api.groq.com']),
    envKeys: ['GROQ_API_KEY', 'VITE_GROQ_API_KEY'],
    auth: 'bearer',
  },
  together: {
    hosts: new Set(['api.together.xyz']),
    envKeys: ['TOGETHER_API_KEY', 'VITE_TOGETHER_API_KEY'],
    auth: 'bearer',
  },
  huggingface: {
    hosts: new Set(['api-inference.huggingface.co']),
    envKeys: ['HF_API_KEY', 'HUGGINGFACE_API_KEY', 'VITE_HF_API_KEY'],
    auth: 'bearer',
  },
  gemini: {
    hosts: new Set(['generativelanguage.googleapis.com']),
    envKeys: ['GEMINI_API_KEY', 'VITE_GEMINI_API_KEY'],
    auth: 'query-key',
  },
};

const AI_CONFIG_FILE = 'ai-config.json';

function getAIConfigPath() {
  return path.join(app.getPath('userData'), AI_CONFIG_FILE);
}

function readStoredAIConfig() {
  try {
    const configPath = getAIConfigPath();
    if (!fsSync.existsSync(configPath)) return { keys: {} };
    const parsed = JSON.parse(fsSync.readFileSync(configPath, 'utf8'));
    return parsed && typeof parsed === 'object' && parsed.keys && typeof parsed.keys === 'object'
      ? { keys: parsed.keys }
      : { keys: {} };
  } catch {
    return { keys: {} };
  }
}

function writeStoredAIConfig(config) {
  const configPath = getAIConfigPath();
  fsSync.mkdirSync(path.dirname(configPath), { recursive: true });
  fsSync.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
}

function getStoredProviderKey(providerId) {
  const cfg = readStoredAIConfig();
  const value = cfg.keys?.[providerId];
  return typeof value === 'string' ? value.trim() : '';
}

function applyStoredAIConfig() {
  // Keys are read from userData at request time so deleting/updating them applies immediately
  // without mutating OS/.env-provided environment variables.
}

function getEnvValue(names) {
  for (const name of names) {
    const value = process.env[name];
    if (value && value.trim()) return value.trim();
  }
  return '';
}

function getConfiguredApiKey(providerId, cfg) {
  return getStoredProviderKey(providerId) || getEnvValue(cfg.envKeys);
}

function getProviderConfig(providerId, host) {
  const cfg = AI_PROVIDER_CONFIG[String(providerId || '').toLowerCase()];
  if (!cfg || !cfg.hosts.has(host)) return null;
  return cfg;
}

ipcMain.handle('ai:fetch', async (_event, payload) => {
  const url = payload?.url || '';
  const method = payload?.method || 'POST';
  const headers = { ...(payload?.headers || {}) };
  const body = payload?.body || '';
  const timeoutMs = Math.min(Math.max(Number(payload?.timeoutMs || 15_000), 1000), 60_000);
  const providerId = String(payload?.providerId || '').toLowerCase();

  try {
    let parsed = new URL(url);
    if (parsed.protocol !== 'https:') throw new Error('Blocked non-HTTPS URL');
    if (!AI_ALLOWED_HOSTS.has(parsed.host)) throw new Error('Blocked host');
    if (!['POST'].includes(method.toUpperCase())) throw new Error('Blocked AI method');
    for (const name of Object.keys(headers)) {
      if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) throw new Error('Blocked invalid header');
    }

    const provider = getProviderConfig(providerId, parsed.host);
    if (!provider) throw new Error('Blocked provider/host pair');

    const apiKey = getConfiguredApiKey(providerId, provider);
    if (!apiKey) {
      return { ok: false, status: 401, body: '', error: `Missing API key for ${providerId}` };
    }

    delete headers.Authorization;
    delete headers.authorization;
    if (provider.auth === 'bearer') {
      headers.Authorization = `Bearer ${apiKey}`;
    } else if (provider.auth === 'query-key') {
      parsed.searchParams.set('key', apiKey);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const res = await fetch(parsed.toString(), {
      method,
      headers,
      body,
      signal: controller.signal,
    });

    clearTimeout(timer);
    const text = await res.text();
    const respHeaders = {};
    res.headers.forEach((value, key) => { respHeaders[key] = value; });

    return { ok: res.ok, status: res.status, body: text, headers: respHeaders };
  } catch (error) {
    return { ok: false, status: 0, body: '', error: error?.message || 'AI fetch failed' };
  }
});

ipcMain.handle('ai:providers', async () => {
  return Object.fromEntries(Object.entries(AI_PROVIDER_CONFIG).map(([id, cfg]) => [
    id,
    { configured: Boolean(getConfiguredApiKey(id, cfg)) },
  ]));
});

ipcMain.handle('ai:config:get', async () => {
  return {
    ok: true,
    userDataPath: app.getPath('userData'),
    providers: Object.fromEntries(Object.entries(AI_PROVIDER_CONFIG).map(([id, cfg]) => [
      id,
      {
        configured: Boolean(getConfiguredApiKey(id, cfg)),
        stored: Boolean(getStoredProviderKey(id)),
        envKeys: cfg.envKeys,
      },
    ])),
  };
});

ipcMain.handle('ai:config:save', async (_event, payload) => {
  try {
    const updates = payload?.keys && typeof payload.keys === 'object' ? payload.keys : {};
    const stored = readStoredAIConfig();
    const next = { keys: { ...(stored.keys || {}) } };

    for (const [providerId, rawValue] of Object.entries(updates)) {
      if (!AI_PROVIDER_CONFIG[providerId]) continue;
      const value = typeof rawValue === 'string' ? rawValue.trim() : '';
      if (value) {
        next.keys[providerId] = value;
      } else {
        delete next.keys[providerId];
      }
    }

    writeStoredAIConfig(next);
    applyStoredAIConfig();
    return {
      ok: true,
      userDataPath: app.getPath('userData'),
      providers: Object.fromEntries(Object.entries(AI_PROVIDER_CONFIG).map(([id, cfg]) => [
        id,
        { configured: Boolean(getConfiguredApiKey(id, cfg)), stored: Boolean(getStoredProviderKey(id)) },
      ])),
    };
  } catch (error) {
    return { ok: false, error: error?.message || 'Không lưu được cấu hình AI.' };
  }
});

ipcMain.handle('report:export', async (_event, payload) => {
  try {
    const format     = payload?.format === 'json' ? 'json' : 'html';
    const scanResult = payload?.scanResult;
    if (!scanResult) throw new Error('Không có dữ liệu scan để export.');

    const content    = format === 'json' ? buildJsonReport(scanResult) : buildHtmlReport(scanResult);
    const saveResult = await dialog.showSaveDialog({
      title: 'Xuất báo cáo',
      defaultPath: getSuggestedFilename(scanResult, format),
      filters: format === 'json'
        ? [{ name: 'JSON', extensions: ['json'] }]
        : [{ name: 'HTML', extensions: ['html'] }],
    });

    if (saveResult.canceled || !saveResult.filePath) return { ok: false, canceled: true };
    await fs.writeFile(saveResult.filePath, content, 'utf8');
    return { ok: true, filePath: saveResult.filePath };
  } catch (error) {
    return { ok: false, error: error?.message || 'Xuất báo cáo thất bại' };
  }
});

app.whenReady().then(() => {
  app.setName('SENTINEL v2');
  loadLocalEnv();
  applyStoredAIConfig();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
