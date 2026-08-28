/**
 * PhishGuard AI — Popup Controller
 */

document.addEventListener('DOMContentLoaded', async () => {
  const btnTriggerScan = document.getElementById('btn-trigger-scan');
  const statQrScanned = document.getElementById('stat-qr-scanned');
  const statThreatsBlocked = document.getElementById('stat-threats-blocked');
  const statSuspicious = document.getElementById('stat-suspicious');
  
  const emptyState = document.getElementById('empty-state');
  const detectionItem = document.getElementById('detection-item');
  const latestSevPill = document.getElementById('latest-sev-pill');
  const latestScoreText = document.getElementById('latest-score-text');
  const latestUrlText = document.getElementById('latest-url-text');
  const latestReasonsText = document.getElementById('latest-reasons-text');

  const toggleAutoBlock = document.getElementById('toggle-autoblock');
  const toggleNotifications = document.getElementById('toggle-notifications');

  // Load Status from Background Service Worker
  chrome.runtime.sendMessage({ type: 'GET_EXTENSION_STATUS' }, (res) => {
    if (!res) return;
    const { stats, settings, recentDetections } = res;

    // Populate Counters
    if (stats) {
      statQrScanned.textContent = stats.qrScansToday || 0;
      statThreatsBlocked.textContent = stats.threatsBlocked || 0;
      statSuspicious.textContent = stats.suspiciousCount || 0;
    }

    // Populate Toggles
    if (settings) {
      toggleAutoBlock.checked = !!settings.autoBlock;
      toggleNotifications.checked = !!settings.notifications;
    }

    // Populate Latest Detection Card
    if (recentDetections && recentDetections.length > 0) {
      const latest = recentDetections[0];
      emptyState.classList.add('hidden');
      detectionItem.classList.remove('hidden');

      const sev = latest.verdict || latest.severity || 'SAFE';
      latestSevPill.textContent = sev;
      latestSevPill.className = `sev-pill ${sev}`;
      latestScoreText.textContent = `${latest.riskScore || latest.threat_score || 0}/100`;
      latestUrlText.textContent = latest.url || latest.payload || 'Unknown Destination';

      const reasons = latest.reasons || latest.analysis_reasons || [];
      latestReasonsText.textContent = reasons.length > 0 ? reasons[0] : (sev === 'SAFE' ? 'Verified destination' : 'Suspicious indicators detected');
    }
  });

  // Trigger Quick Scan Button
  btnTriggerScan.addEventListener('click', () => {
    btnTriggerScan.disabled = true;
    btnTriggerScan.innerHTML = `<span class="scan-icon">⏳</span><div class="btn-text-wrap"><span class="btn-title">Scanning Tab...</span><span class="btn-sub">Decoding visible QR codes</span></div>`;
    
    chrome.runtime.sendMessage({ type: 'TRIGGER_QUICK_SCAN' }, () => {
      setTimeout(() => {
        window.close(); // Close popup so user sees the in-page HUD
      }, 300);
    });
  });

  // Toggle handlers
  toggleAutoBlock.addEventListener('change', async () => {
    const { settings } = await chrome.storage.local.get('settings');
    const updated = { ...(settings || {}), autoBlock: toggleAutoBlock.checked };
    await chrome.storage.local.set({ settings: updated });
  });

  toggleNotifications.addEventListener('change', async () => {
    const { settings } = await chrome.storage.local.get('settings');
    const updated = { ...(settings || {}), notifications: toggleNotifications.checked };
    await chrome.storage.local.set({ settings: updated });
  });
});
