const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  startRegionSelection: () => ipcRenderer.send('start-region-selection'),
  cancelRegionSelection: () => ipcRenderer.send('cancel-region-selection'),
  captureRegion: (bounds) => ipcRenderer.invoke('capture-region', bounds),
  showNotification: (details) => ipcRenderer.send('show-notification', details),
  readClipboard: () => ipcRenderer.invoke('read-clipboard'),
  moveFloatingKey: (delta) => ipcRenderer.send('move-floating-key', delta),
  updateFloatingKeyState: (state) => ipcRenderer.send('update-floating-key-state', state),
  
  onOpenScanDetails: (callback) => ipcRenderer.on('open-scan-details', (_event) => callback()),
  onFloatingKeyState: (callback) => ipcRenderer.on('floating-key-state', (_event, state) => callback(state))
});
