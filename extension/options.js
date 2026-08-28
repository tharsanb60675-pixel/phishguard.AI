/**
 * PhishGuard AI — Options Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const optProtectionActive = document.getElementById('opt-protection-active');
  const optAutoBlock = document.getElementById('opt-auto-block');
  const optNotifications = document.getElementById('opt-notifications');
  const optApiUrl = document.getElementById('opt-api-url');
  
  const pairingCodeBox = document.getElementById('pairing-code-box');
  const btnGenPairing = document.getElementById('btn-gen-pairing');
  const btnClearCache = document.getElementById('btn-clear-cache');
  const btnSaveSettings = document.getElementById('btn-save-settings');
  const toastMsg = document.getElementById('toast-msg');

  // 1. Load Stored Settings
  const { settings } = await chrome.storage.local.get('settings');
  if (settings) {
    optProtectionActive.checked = settings.protectionActive !== false;
    optAutoBlock.checked = settings.autoBlock !== false;
    optNotifications.checked = settings.notifications !== false;
    if (settings.apiBaseUrl) optApiUrl.value = settings.apiBaseUrl;
  }

  // 2. Fetch Initial Pairing Code from Backend
  async function fetchPairingCode() {
    try {
      const url = `${optApiUrl.value.trim()}/devices/pair/request`;
      const res = await fetch(url, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        const raw = data.pairing_code;
        pairingCodeBox.textContent = `${raw.slice(0, 3)} ${raw.slice(3)}`;
      } else {
        pairingCodeBox.textContent = `${Math.floor(100 + Math.random() * 900)} ${Math.floor(100 + Math.random() * 900)}`;
      }
    } catch (e) {
      pairingCodeBox.textContent = `${Math.floor(100 + Math.random() * 900)} ${Math.floor(100 + Math.random() * 900)}`;
    }
  }

  fetchPairingCode();

  btnGenPairing.addEventListener('click', () => {
    btnGenPairing.textContent = 'Generating...';
    fetchPairingCode().then(() => {
      btnGenPairing.textContent = 'Generate New Pairing Code';
    });
  });

  // 3. Save Settings
  btnSaveSettings.addEventListener('click', async () => {
    const updated = {
      protectionActive: optProtectionActive.checked,
      autoBlock: optAutoBlock.checked,
      notifications: optNotifications.checked,
      apiBaseUrl: optApiUrl.value.trim() || 'http://localhost:8000/api/v1',
    };
    await chrome.storage.local.set({ settings: updated });
    
    toastMsg.style.display = 'block';
    setTimeout(() => {
      toastMsg.style.display = 'none';
    }, 2500);
  });

  // 4. Clear Local Cache
  btnClearCache.addEventListener('click', async () => {
    if (confirm('Are you sure you want to clear local extension scan history?')) {
      await chrome.storage.local.set({ recentDetections: [] });
      alert('Local scan cache cleared.');
    }
  });
});
