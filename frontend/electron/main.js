import { app, BrowserWindow, ipcMain, globalShortcut, Notification, desktopCapturer, screen, clipboard } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;
let floatingKeyWindow;
let regionSelectorWindow;
let smartScanOverlayWindow;

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  if (process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }
}

function createFloatingKeyWindow() {
  floatingKeyWindow = new BrowserWindow({
    width: 80,
    height: 80,
    x: 50,
    y: 50,
    transparent: true,
    frame: false,
    alwaysOnTop: true,
    resizable: false,
    skipTaskbar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  floatingKeyWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  floatingKeyWindow.setAlwaysOnTop(true, 'screen-saver', 1);

  const url = process.env.VITE_DEV_SERVER_URL 
    ? `${process.env.VITE_DEV_SERVER_URL}floating-key` 
    : `file://${path.join(__dirname, '../dist/index.html')}#/floating-key`;
  
  floatingKeyWindow.loadURL(url);
}

function createRegionSelectorWindow() {
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width, height } = primaryDisplay.workAreaSize;

  regionSelectorWindow = new BrowserWindow({
    width,
    height,
    x: 0,
    y: 0,
    transparent: true,
    frame: false,
    alwaysOnTop: true,
    resizable: false,
    skipTaskbar: true,
    show: false, // Initially hidden
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  regionSelectorWindow.setIgnoreMouseEvents(false);
  regionSelectorWindow.setAlwaysOnTop(true, 'screen-saver', 1);

  const url = process.env.VITE_DEV_SERVER_URL 
    ? `${process.env.VITE_DEV_SERVER_URL}region-selector` 
    : `file://${path.join(__dirname, '../dist/index.html')}#/region-selector`;
  
  regionSelectorWindow.loadURL(url);

  regionSelectorWindow.on('close', (e) => {
    e.preventDefault();
    regionSelectorWindow.hide();
  });
}

function createSmartScanOverlayWindow() {
  const primaryDisplay = screen.getPrimaryDisplay();
  const { width, height } = primaryDisplay.workAreaSize;

  smartScanOverlayWindow = new BrowserWindow({
    width,
    height,
    x: 0,
    y: 0,
    transparent: true,
    frame: false,
    alwaysOnTop: true,
    resizable: false,
    skipTaskbar: true,
    show: false, // Initially hidden
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  smartScanOverlayWindow.setAlwaysOnTop(true, 'screen-saver', 1);

  const url = process.env.VITE_DEV_SERVER_URL 
    ? `${process.env.VITE_DEV_SERVER_URL}smart-scan-overlay` 
    : `file://${path.join(__dirname, '../dist/index.html')}#/smart-scan-overlay`;
  
  smartScanOverlayWindow.loadURL(url);

  smartScanOverlayWindow.on('close', (e) => {
    e.preventDefault();
    smartScanOverlayWindow.hide();
  });
}

app.whenReady().then(() => {
  createMainWindow();
  createFloatingKeyWindow();
  
  // Need to wait for app ready to get screen size
  createRegionSelectorWindow();
  createSmartScanOverlayWindow();

  // Register Global Hotkey
  globalShortcut.register('CommandOrControl+Shift+Q', () => {
    if (smartScanOverlayWindow) {
      smartScanOverlayWindow.show();
      smartScanOverlayWindow.focus();
    }
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC: Show Region Selector (e.g. from clicking Floating Key)
ipcMain.on('start-region-selection', () => {
  if (regionSelectorWindow) {
    regionSelectorWindow.show();
    regionSelectorWindow.focus();
  }
});

// IPC: Hide Region Selector (e.g. on Esc)
ipcMain.on('cancel-region-selection', () => {
  if (regionSelectorWindow) {
    regionSelectorWindow.hide();
  }
});

// IPC: Update Floating Window position
ipcMain.on('move-floating-key', (event, { x, y }) => {
  if (floatingKeyWindow) {
    const bounds = floatingKeyWindow.getBounds();
    floatingKeyWindow.setPosition(bounds.x + x, bounds.y + y);
  }
});

// IPC: Capture Region
ipcMain.handle('capture-region', async (event, bounds) => {
  try {
    if (regionSelectorWindow) {
      regionSelectorWindow.hide();
    }
    
    // Wait for the window to hide completely
    await new Promise(resolve => setTimeout(resolve, 150));

    const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 10000, height: 10000 } });
    const primarySource = sources[0]; // Assuming primary display for now

    const image = primarySource.thumbnail;
    const croppedImage = image.crop(bounds);
    
    return croppedImage.toDataURL();
  } catch (error) {
    console.error('Failed to capture region:', error);
    return null;
  }
});

// IPC: Capture Full Screen
ipcMain.handle('capture-full-screen', async (event) => {
  try {
    if (smartScanOverlayWindow) {
      smartScanOverlayWindow.hide();
    }
    
    // Wait for the overlay window to hide completely so it doesn't appear in screenshot
    await new Promise(resolve => setTimeout(resolve, 200));

    const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 10000, height: 10000 } });
    const primarySource = sources[0];

    const image = primarySource.thumbnail;
    const dataUrl = image.toDataURL();
    
    // Show overlay again
    if (smartScanOverlayWindow) {
      smartScanOverlayWindow.show();
    }
    
    return dataUrl;
  } catch (error) {
    console.error('Failed to capture full screen:', error);
    if (smartScanOverlayWindow) smartScanOverlayWindow.show();
    return null;
  }
});

// IPC: Close Smart Scan Overlay
ipcMain.on('close-smart-scan-overlay', () => {
  if (smartScanOverlayWindow) {
    smartScanOverlayWindow.hide();
  }
});

// IPC: Read Clipboard
ipcMain.handle('read-clipboard', async () => {
  const text = clipboard.readText();
  const image = clipboard.readImage();
  return {
    text: text || null,
    image: image.isEmpty() ? null : image.toDataURL()
  };
});

// IPC: Show Notification
ipcMain.on('show-notification', (event, { title, body, risk, confidence }) => {
  const notification = new Notification({
    title: title || 'PhishGuard.AI Scan Complete',
    body: `${body}\nRisk: ${risk} | Confidence: ${confidence}%`,
    actions: [{ type: 'button', text: 'View Details' }]
  });

  notification.on('action', (event, index) => {
    if (index === 0) {
      // User clicked "View Details"
      if (mainWindow) {
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.focus();
        // Send IPC to main window to open the scan details
        mainWindow.webContents.send('open-scan-details');
      }
    }
  });

  notification.show();
});

ipcMain.on('update-floating-key-state', (event, state) => {
  if (floatingKeyWindow) {
    floatingKeyWindow.webContents.send('floating-key-state', state);
  }
});
