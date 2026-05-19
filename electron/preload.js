const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('owaspWorkbench', {
  scanUrl:      (payload)    => ipcRenderer.invoke('scan:url', payload),
  scanProject:  (folderPath) => ipcRenderer.invoke('scan:project', { folderPath }),
  getChecklist: ()           => ipcRenderer.invoke('checklist:get'),
  pickFolder:   ()           => ipcRenderer.invoke('dialog:pickFolder'),
  openDocs:     (url)        => ipcRenderer.invoke('docs:open', url),
  exportReport: (payload)    => ipcRenderer.invoke('report:export', payload),
  stopScan:     ()           => ipcRenderer.invoke('scan:stop'),
  aiFetch:      (payload)    => ipcRenderer.invoke('ai:fetch', payload),
  getAIProviders: ()         => ipcRenderer.invoke('ai:providers'),
  getAIConfig:   ()          => ipcRenderer.invoke('ai:config:get'),
  saveAIConfig:  (payload)   => ipcRenderer.invoke('ai:config:save', payload),

  // Real-time progress streaming
  // FIX: store listener ref so we can remove *exactly* that listener (not all listeners)
  onScanProgress: (cb) => {
    const listener = (_e, msg) => cb(msg);
    ipcRenderer.on('scan:progress', listener);
    // Return a cleanup function so caller can remove exactly this listener
    return listener;
  },
  offScanProgress: (listener) => {
    if (listener) {
      ipcRenderer.removeListener('scan:progress', listener);
    } else {
      ipcRenderer.removeAllListeners('scan:progress');
    }
  },
});
