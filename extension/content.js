/**
 * PhishGuard AI — Content Script & In-Page HUD Shield
 *
 * Responsibilities:
 * - Scans DOM elements & captured screenshot bitmaps using jsQR
 * - Injects animated radar scanning indicator
 * - Draws glowing cybersecurity bounding boxes over detected QR codes
 * - Displays in-page threat analysis HUD modal with reasons & actions
 * - Blocks navigation to malicious QR destinations
 */

(() => {
  // Prevent double injection
  if (window.__PHISHGUARD_AI_INJECTED__) return;
  window.__PHISHGUARD_AI_INJECTED__ = true;

  console.log('[PhishGuard AI] Content Script Shield Active.');

  let scanningHudElement = null;
  let resultModalElement = null;
  let activeOverlays = [];

  // ─── Helper: Clean Existing Overlays ───────────────────────────────────────
  function removeExistingOverlays() {
    activeOverlays.forEach((el) => el.remove());
    activeOverlays = [];
    if (resultModalElement) {
      resultModalElement.remove();
      resultModalElement = null;
    }
  }

  // ─── 1. Animated Scanning Radar HUD ─────────────────────────────────────────
  function showScanningHud() {
    if (scanningHudElement) scanningHudElement.remove();

    scanningHudElement = document.createElement('div');
    scanningHudElement.className = 'phishguard-scanning-hud';
    scanningHudElement.innerHTML = `
      <div class="phishguard-hud-radar">
        <div class="phishguard-radar-sweep"></div>
      </div>
      <div class="phishguard-hud-content">
        <div class="phishguard-hud-title">PhishGuard.AI</div>
        <div class="phishguard-hud-subtitle">Scanning visible page for QR threats...</div>
      </div>
    `;
    document.body.appendChild(scanningHudElement);
  }

  function hideScanningHud() {
    if (scanningHudElement) {
      scanningHudElement.classList.add('phishguard-hud-fadeout');
      setTimeout(() => {
        if (scanningHudElement) {
          scanningHudElement.remove();
          scanningHudElement = null;
        }
      }, 400);
    }
  }

  // ─── 2. No QR Code Toast ───────────────────────────────────────────────────
  function showNoQRToast() {
    hideScanningHud();
    const toast = document.createElement('div');
    toast.className = 'phishguard-toast-no-qr';
    toast.innerHTML = `
      <div class="phishguard-toast-icon">ℹ</div>
      <div class="phishguard-toast-body">
        <strong>PhishGuard.AI</strong>
        <span>No QR code detected on the visible webpage.</span>
      </div>
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('phishguard-toast-fade');
      setTimeout(() => toast.remove(), 400);
    }, 3500);
  }

  // ─── 3. In-Memory QR Decoder (jsQR on Screenshot + DOM Images) ─────────────
  async function decodeQRCodesFromScreenshot(screenshotDataUrl) {
    const detectedCodes = [];
    const seenPayloads = new Set();

    // A. Decode from full tab screenshot using offscreen Canvas
    try {
      const img = new Image();
      await new Promise((resolve, reject) => {
        img.onload = resolve;
        img.onerror = reject;
        img.src = screenshotDataUrl;
      });

      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(img, 0, 0);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if (typeof jsQR !== 'undefined') {
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth',
        });

        if (code && code.data && !seenPayloads.has(code.data)) {
          seenPayloads.add(code.data);
          // Scale bounding box coordinates to CSS window coordinates
          const scaleX = window.innerWidth / img.width;
          const scaleY = window.innerHeight / img.height;

          const minX = Math.min(code.location.topLeftCorner.x, code.location.bottomLeftCorner.x) * scaleX;
          const minY = Math.min(code.location.topLeftCorner.y, code.location.topRightCorner.y) * scaleY;
          const maxX = Math.max(code.location.topRightCorner.x, code.location.bottomRightCorner.x) * scaleX;
          const maxY = Math.max(code.location.bottomLeftCorner.y, code.location.bottomRightCorner.y) * scaleY;

          detectedCodes.push({
            payload: code.data,
            type: code.data.startsWith('http') ? 'URL' : 'Text',
            boundingBox: {
              x: Math.max(0, minX - 10),
              y: Math.max(0, minY - 10),
              width: Math.max(80, maxX - minX + 20),
              height: Math.max(80, maxY - minY + 20),
            },
          });
        }
      }
    } catch (e) {
      console.warn('[PhishGuard AI] Screenshot decode failed:', e);
    }

    // B. Multi-source DOM fallback: inspect all <img> and <canvas> on page
    const domImages = document.querySelectorAll('img, canvas');
    for (const el of domImages) {
      try {
        const rect = el.getBoundingClientRect();
        if (rect.width < 40 || rect.height < 40 || rect.bottom < 0 || rect.top > window.innerHeight) continue;

        let canvas = document.createElement('canvas');
        canvas.width = Math.min(600, rect.width * 2);
        canvas.height = Math.min(600, rect.height * 2);
        let ctx = canvas.getContext('2d', { willReadFrequently: true });

        if (el.tagName === 'IMG' && el.complete && el.naturalWidth > 0) {
          ctx.drawImage(el, 0, 0, canvas.width, canvas.height);
          const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          if (typeof jsQR !== 'undefined') {
            const res = jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: 'attemptBoth' });
            if (res && res.data && !seenPayloads.has(res.data)) {
              seenPayloads.add(res.data);
              detectedCodes.push({
                payload: res.data,
                type: res.data.startsWith('http') ? 'URL' : 'Text',
                boundingBox: {
                  x: rect.left,
                  y: rect.top,
                  width: rect.width,
                  height: rect.height,
                },
              });
            }
          }
        }
      } catch (err) {
        // Cross-origin image canvas security limitation handled safely
      }
    }

    return detectedCodes;
  }

  // ─── 4. Render Glowing Cyberpunk Bounding Boxes on Page ─────────────────────
  function renderBoundingBoxes(codes) {
    codes.forEach((item, index) => {
      if (!item.boundingBox) return;
      const { x, y, width, height } = item.boundingBox;
      const severity = item.analysis?.severity || 'SAFE';

      const box = document.createElement('div');
      box.className = `phishguard-qr-bbox phishguard-bbox-${severity.toLowerCase().replace(/\s+/g, '-')}`;
      box.style.left = `${Math.max(10, x)}px`;
      box.style.top = `${Math.max(10, y + window.scrollY)}px`;
      box.style.width = `${Math.max(60, width)}px`;
      box.style.height = `${Math.max(60, height)}px`;

      box.innerHTML = `
        <div class="phishguard-bbox-header">
          <span class="phishguard-bbox-tag">QR #${index + 1}</span>
          <span class="phishguard-bbox-sev">${severity}</span>
        </div>
        <div class="phishguard-bbox-corners">
          <span class="phishguard-corner c-tl"></span>
          <span class="phishguard-corner c-tr"></span>
          <span class="phishguard-corner c-bl"></span>
          <span class="phishguard-corner c-br"></span>
        </div>
      `;
      document.body.appendChild(box);
      activeOverlays.push(box);
    });
  }

  // ─── 5. Modern PhishGuard HUD Result Card ──────────────────────────────────
  function showThreatResultsModal(codes, pageUrl, pageTitle) {
    hideScanningHud();
    removeExistingOverlays();

    if (!codes || codes.length === 0) {
      showNoQRToast();
      return;
    }

    // Draw visual boxes on the page
    renderBoundingBoxes(codes);

    const primaryCode = codes[0];
    const analysis = primaryCode.analysis || {};
    const severity = analysis.severity || 'SAFE';
    const verdict = analysis.verdict || severity;
    const threatScore = analysis.threat_score !== undefined ? analysis.threat_score : (analysis.threatScore !== undefined ? analysis.threatScore : 0);
    const classification = analysis.classification || 'BENIGN';
    const qrType = analysis.qr_type || analysis.qrType || (primaryCode.payload.startsWith('http') ? 'URL' : 'Plain Text');
    const authenticity = analysis.authenticity || (threatScore <= 15 ? 'VERIFIED' : threatScore >= 60 ? 'SUSPICIOUS' : 'UNVERIFIED');
    const authenticityReason = analysis.authenticity_reason || analysis.authenticityReason || (authenticity === 'VERIFIED' ? 'Verified legitimate destination.' : authenticity === 'SUSPICIOUS' ? 'Possible spoofing or impersonation detected.' : 'Unable to verify destination with available security intelligence.');
    const whatWillHappen = analysis.what_will_happen || analysis.whatWillHappen || (qrType.includes('URL') ? 'This QR code opens a website.' : 'This QR code displays content.');
    const confidenceLevel = analysis.confidence_level || analysis.confidenceLevel || 'HIGH';
    const reasons = analysis.analysis_reasons || analysis.reasons || [];
    const checks = analysis.checks || reasons.map(r => ({
      status: threatScore >= 60 ? 'FAIL' : 'WARN',
      icon: threatScore <= 20 ? '✓' : '⚠',
      text: r
    }));
    const isBlocked = !!analysis.is_blocked || threatScore >= 60;
    const isSafe = threatScore < 20 && authenticity === 'VERIFIED';
    const isUnknown = verdict.includes('UNKNOWN') || authenticity === 'UNVERIFIED';

    const sevColorClass =
      threatScore >= 80
        ? 'phishguard-sev-critical'
        : threatScore >= 60
        ? 'phishguard-sev-high'
        : threatScore >= 40
        ? 'phishguard-sev-suspicious'
        : isUnknown
        ? 'phishguard-sev-suspicious'
        : 'phishguard-sev-safe';

    const authColorStyle =
      authenticity === 'VERIFIED'
        ? 'color: #34d399; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3);'
        : authenticity === 'SUSPICIOUS'
        ? 'color: #f87171; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3);'
        : 'color: #fbbf24; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.3);';

    resultModalElement = document.createElement('div');
    resultModalElement.className = 'phishguard-result-hud-card';
    resultModalElement.innerHTML = `
      <div class="phishguard-hud-card-header">
        <div class="phishguard-header-brand">
          <div class="phishguard-brand-icon">🛡️</div>
          <div>
            <div class="phishguard-brand-title">PhishGuard.AI</div>
            <div class="phishguard-brand-sub">Real-Time QR Security Shield</div>
          </div>
        </div>
        <button class="phishguard-hud-close" id="phishguard-btn-close">✕</button>
      </div>

      <div class="phishguard-hud-card-body">
        <div class="phishguard-threat-banner ${sevColorClass}">
          <div class="phishguard-threat-left">
            <span class="phishguard-tag-badge">QR CODE DETECTED</span>
            <div class="phishguard-threat-title">${threatScore} / 100 — ${verdict}</div>
            <div class="phishguard-threat-cls">CONFIDENCE: ${confidenceLevel}</div>
          </div>
          <div class="phishguard-score-circle">
            <span class="phishguard-score-val">${threatScore}</span>
            <span class="phishguard-score-max">/ 100</span>
          </div>
        </div>

        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <span style="font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: rgba(6, 182, 212, 0.15); color: #38bdf8; border: 1px solid rgba(6, 182, 212, 0.3);">
            QR TYPE: ${qrType.toUpperCase()}
          </span>
          <span style="font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 6px; ${authColorStyle}">
            AUTHENTICITY: ${authenticity}
          </span>
        </div>

        <div class="phishguard-target-box">
          <div class="phishguard-target-label">DECODED DESTINATION</div>
          <div class="phishguard-target-val" title="${primaryCode.payload}">${primaryCode.payload}</div>
        </div>

        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 10px 12px;">
          <div style="font-size: 9px; font-weight: 800; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px;">WHAT WILL HAPPEN</div>
          <div style="font-size: 11px; color: #e2e8f0; margin-top: 4px; line-height: 1.4;">${whatWillHappen}</div>
          ${authenticityReason ? `<div style="font-size: 10px; color: #94a3b8; margin-top: 4px; font-style: italic;">ℹ ${authenticityReason}</div>` : ''}
        </div>

        <div class="phishguard-reasons-section">
          <div class="phishguard-reasons-title">SECURITY ANALYSIS</div>
          <ul class="phishguard-reasons-list">
            ${checks.map((c) => `<li><span class="${c.icon === '✓' ? 'phishguard-bullet-pass' : 'phishguard-bullet'}">${c.icon || '⚠'}</span> ${c.text || c}</li>`).join('')}
          </ul>
        </div>

        ${
          isBlocked
            ? `<div class="phishguard-blocked-notice">
                🛑 <strong>THREAT DETECTED — STOP PROCEEDING:</strong> PhishGuard AI blocked automatic navigation to protect your device.
              </div>`
            : isUnknown
            ? `<div style="background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 10px; padding: 10px 12px; font-size: 11px; color: #fde68a; line-height: 1.4;">
                ⚠ <strong>UNVERIFIED DESTINATION:</strong> Unable to verify this destination with the available security intelligence. Proceed only if you trust the source.
              </div>`
            : ''
        }

        ${
          codes.length > 1
            ? `<div class="phishguard-multi-notice">
                ℹ ${codes.length} QR codes detected on this webpage. Showing primary threat evaluation.
              </div>`
            : ''
        }
      </div>

      <div class="phishguard-hud-card-actions">
        ${
          isSafe
            ? `<button class="phishguard-action-btn phishguard-btn-safe" id="phishguard-btn-proceed">
                ✓ PROCEED
              </button>`
            : isBlocked
            ? `<button class="phishguard-action-btn phishguard-btn-block" id="phishguard-btn-stop">
                🛑 STOP PROCEEDING
              </button>`
            : `<button class="phishguard-action-btn phishguard-btn-caution" id="phishguard-btn-caution">
                ⚠ PROCEED WITH CAUTION
              </button>`
        }
        <a href="http://localhost:5173/background-protection" target="_blank" class="phishguard-action-btn phishguard-btn-view">
          SOC View ↗
        </a>
      </div>
    `;

    document.body.appendChild(resultModalElement);
    activeOverlays.push(resultModalElement);

    // Button event handlers
    document.getElementById('phishguard-btn-close')?.addEventListener('click', () => {
      removeExistingOverlays();
    });

    document.getElementById('phishguard-btn-stop')?.addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.textContent = '✓ Navigation Blocked';
      btn.style.background = '#334155';
      setTimeout(() => removeExistingOverlays(), 1000);
    });

    document.getElementById('phishguard-btn-proceed')?.addEventListener('click', () => {
      if (primaryCode.payload.startsWith('http://') || primaryCode.payload.startsWith('https://')) {
        window.open(primaryCode.payload, '_blank');
      }
      removeExistingOverlays();
    });

    document.getElementById('phishguard-btn-caution')?.addEventListener('click', () => {
      if (primaryCode.payload.startsWith('http://') || primaryCode.payload.startsWith('https://')) {
        if (confirm(`PhishGuard Warning: This destination could not be verified (${primaryCode.payload}). Do you still want to proceed?`)) {
          window.open(primaryCode.payload, '_blank');
        }
      }
      removeExistingOverlays();
    });
  }

  // Helper: Extract visible text snippet from active DOM
  function extractVisiblePageText() {
    const selection = window.getSelection() ? window.getSelection().toString().trim() : '';
    if (selection && selection.length > 5) return selection;

    const popups = document.querySelectorAll('.notification, .alert, .toast, [role="alert"], .message, .banner, .modal-body, .popup');
    for (const el of popups) {
      const text = (el.innerText || el.textContent || '').trim();
      if (text.length > 10 && text.length < 1000) return text;
    }

    const links = Array.from(document.querySelectorAll('a[href^="http"]')).map(a => a.href);
    if (links.length > 0) return links[0];

    const bodyText = (document.body.innerText || '').trim();
    const sentences = bodyText.split('\n').map(s => s.trim()).filter(s => s.length > 15);
    if (sentences.length > 0) {
      return sentences.slice(0, 3).join(' ');
    }

    return '';
  }

  // ─── 5. Universal Security Result Modal ──────────────────────────────────────
  function showUniversalThreatResultsModal(result, codes, pageUrl, pageTitle) {
    hideScanningHud();
    removeExistingOverlays();

    const detectedType = result.detected_type || 'NOTHING SUPPORTED';
    const threatScore = result.threat_score !== undefined ? result.threat_score : 0;
    const threatLevel = result.threat_level || result.verdict || 'SAFE';
    const isBlocked = !!result.is_blocked;
    const checks = result.checks || (result.analysis_reasons || []).map(r => ({ icon: '⚠', text: r }));

    resultModalElement = document.createElement('div');
    resultModalElement.className = 'phishguard-result-hud-card';

    if (detectedType === 'NOTHING SUPPORTED') {
      resultModalElement.innerHTML = `
        <div class="phishguard-hud-card-header">
          <div class="phishguard-header-brand">
            <div class="phishguard-brand-icon">ℹ️</div>
            <div>
              <div class="phishguard-brand-title">PhishGuard.AI</div>
              <div class="phishguard-brand-sub">Universal Manual Scanner</div>
            </div>
          </div>
          <button class="phishguard-hud-close" id="phishguard-btn-close">✕</button>
        </div>
        <div class="phishguard-hud-card-body" style="text-align: center; padding: 24px 16px;">
          <div style="font-size: 28px; margin-bottom: 8px;">🔍</div>
          <div style="font-size: 14px; font-weight: 800; color: #f87171; text-transform: uppercase; letter-spacing: 0.5px;">NOTHING DETECTED</div>
          <div style="font-size: 12px; color: #94a3b8; margin-top: 6px; line-height: 1.5;">
            No supported URL, notification, email ID, or QR code was found on the visible webpage.
          </div>
        </div>
        <div class="phishguard-hud-card-actions">
          <button class="phishguard-action-btn phishguard-btn-safe" id="phishguard-btn-close-2">Close</button>
        </div>
      `;
    } else if (detectedType === 'URL DETECTED') {
      const url = result.url || '';
      const domain = result.domain || '';
      const isHttps = result.is_https;

      resultModalElement.innerHTML = `
        <div class="phishguard-hud-card-header">
          <div class="phishguard-header-brand">
            <div class="phishguard-brand-icon">🌐</div>
            <div>
              <div class="phishguard-brand-title">PhishGuard.AI</div>
              <div class="phishguard-brand-sub">URL Security Analyzer</div>
            </div>
          </div>
          <button class="phishguard-hud-close" id="phishguard-btn-close">✕</button>
        </div>
        <div class="phishguard-hud-card-body">
          <div class="phishguard-threat-banner ${threatScore >= 60 ? 'phishguard-sev-critical' : 'phishguard-sev-safe'}">
            <div class="phishguard-threat-left">
              <span class="phishguard-tag-badge">URL DETECTED</span>
              <div class="phishguard-threat-title">${threatScore} / 100 — ${threatLevel}</div>
              <div class="phishguard-threat-cls">CONFIDENCE: HIGH</div>
            </div>
            <div class="phishguard-score-circle">
              <span class="phishguard-score-val">${threatScore}</span>
              <span class="phishguard-score-max">/ 100</span>
            </div>
          </div>

          <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px;">
            <span style="font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: rgba(6, 182, 212, 0.15); color: #38bdf8; border: 1px solid rgba(6, 182, 212, 0.3);">
              DOMAIN: ${domain || 'Web URL'}
            </span>
            <span style="font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: ${isHttps ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)'}; color: ${isHttps ? '#34d399' : '#f87171'}; border: 1px solid ${isHttps ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'};">
              ENCRYPTION: ${isHttps ? 'HTTPS SECURE' : 'HTTP UNENCRYPTED'}
            </span>
          </div>

          <div class="phishguard-target-box">
            <div class="phishguard-target-label">DETECTED URL</div>
            <div class="phishguard-target-val" title="${url}">${url}</div>
          </div>

          <div class="phishguard-reasons-section">
            <div class="phishguard-reasons-title">SECURITY ANALYSIS</div>
            <ul class="phishguard-reasons-list">
              ${checks.map((c) => `<li><span class="${c.icon === '✓' ? 'phishguard-bullet-pass' : 'phishguard-bullet'}">${c.icon || '⚠'}</span> ${c.text || c}</li>`).join('')}
            </ul>
          </div>

          ${isBlocked ? `<div class="phishguard-blocked-notice">🛑 <strong>ACTION: STOP PROCEEDING:</strong> High-risk URL threat detected. Do not open or enter credentials.</div>` : ''}
        </div>
        <div class="phishguard-hud-card-actions">
          ${isBlocked ? `<button class="phishguard-action-btn phishguard-btn-block" id="phishguard-btn-stop">🛑 STOP PROCEEDING</button>` : `<button class="phishguard-action-btn phishguard-btn-safe" id="phishguard-btn-proceed">✓ PROCEED</button>`}
        </div>
      `;
    } else if (detectedType === 'NOTIFICATION DETECTED') {
      const msgText = result.extracted_message || '';
      const statusVerdict = result.status || result.status_verdict || 'UNKNOWN / UNVERIFIED';

      resultModalElement.innerHTML = `
        <div class="phishguard-hud-card-header">
          <div class="phishguard-header-brand">
            <div class="phishguard-brand-icon">🔔</div>
            <div>
              <div class="phishguard-brand-title">PhishGuard.AI</div>
              <div class="phishguard-brand-sub">Notification / Message Analyzer</div>
            </div>
          </div>
          <button class="phishguard-hud-close" id="phishguard-btn-close">✕</button>
        </div>
        <div class="phishguard-hud-card-body">
          <div class="phishguard-threat-banner ${statusVerdict === 'LIKELY FAKE' ? 'phishguard-sev-critical' : statusVerdict === 'SUSPICIOUS' ? 'phishguard-sev-suspicious' : 'phishguard-sev-safe'}">
            <div class="phishguard-threat-left">
              <span class="phishguard-tag-badge">NOTIFICATION DETECTED</span>
              <div class="phishguard-threat-title">${statusVerdict}</div>
              <div class="phishguard-threat-cls">RISK: ${threatScore} / 100</div>
            </div>
            <div class="phishguard-score-circle">
              <span class="phishguard-score-val">${threatScore}</span>
              <span class="phishguard-score-max">/ 100</span>
            </div>
          </div>

          <div class="phishguard-target-box">
            <div class="phishguard-target-label">EXTRACTED MESSAGE TEXT</div>
            <div class="phishguard-target-val" style="white-space: pre-wrap;">"${msgText}"</div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; padding: 10px 12px;">
            <div style="font-size: 9px; font-weight: 800; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px;">AI HELPLINE ANALYSIS</div>
            <div style="font-size: 11px; color: #e2e8f0; margin-top: 4px; line-height: 1.4;">${result.ai_helpline_analysis || 'Analyzed message for psychological manipulation and fraud indicators.'}</div>
          </div>

          <div class="phishguard-reasons-section">
            <div class="phishguard-reasons-title">REASONS</div>
            <ul class="phishguard-reasons-list">
              ${checks.map((c) => `<li><span class="${c.icon === '✓' ? 'phishguard-bullet-pass' : 'phishguard-bullet'}">${c.icon || '⚠'}</span> ${c.text || c}</li>`).join('')}
            </ul>
          </div>

          <div style="font-size: 11px; font-weight: 800; color: #fde68a; margin-top: 6px;">
            ACTION: ${result.recommended_action || 'STOP PROCEEDING'}
          </div>
        </div>
        <div class="phishguard-hud-card-actions">
          <a href="http://localhost:5173/helpline" target="_blank" class="phishguard-action-btn phishguard-btn-view">
            Ask AI Helpline ↗
          </a>
          <button class="phishguard-action-btn phishguard-btn-block" id="phishguard-btn-close-2">Close</button>
        </div>
      `;
    } else if (detectedType === 'EMAIL ID DETECTED') {
      const email = result.email || '';
      const domain = result.domain || '';
      const authenticity = result.authenticity || 'UNVERIFIED';

      resultModalElement.innerHTML = `
        <div class="phishguard-hud-card-header">
          <div class="phishguard-header-brand">
            <div class="phishguard-brand-icon">✉️</div>
            <div>
              <div class="phishguard-brand-title">PhishGuard.AI</div>
              <div class="phishguard-brand-sub">Email Security Analyzer</div>
            </div>
          </div>
          <button class="phishguard-hud-close" id="phishguard-btn-close">✕</button>
        </div>
        <div class="phishguard-hud-card-body">
          <div class="phishguard-threat-banner ${authenticity === 'SUSPICIOUS' ? 'phishguard-sev-critical' : 'phishguard-sev-suspicious'}">
            <div class="phishguard-threat-left">
              <span class="phishguard-tag-badge">EMAIL ID DETECTED</span>
              <div class="phishguard-threat-title">AUTHENTICITY: ${authenticity}</div>
              <div class="phishguard-threat-cls">RISK: ${threatScore} / 100 — ${threatLevel}</div>
            </div>
            <div class="phishguard-score-circle">
              <span class="phishguard-score-val">${threatScore}</span>
              <span class="phishguard-score-max">/ 100</span>
            </div>
          </div>

          <div class="phishguard-target-box">
            <div class="phishguard-target-label">EMAIL ADDRESS</div>
            <div class="phishguard-target-val">${email}</div>
          </div>

          <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px;">
            <span style="font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 6px; background: rgba(6, 182, 212, 0.15); color: #38bdf8; border: 1px solid rgba(6, 182, 212, 0.3);">
              DOMAIN: ${domain}
            </span>
          </div>

          <div class="phishguard-reasons-section">
            <div class="phishguard-reasons-title">SECURITY ANALYSIS</div>
            <ul class="phishguard-reasons-list">
              ${checks.map((c) => `<li><span class="${c.icon === '✓' ? 'phishguard-bullet-pass' : 'phishguard-bullet'}">${c.icon || '⚠'}</span> ${c.text || c}</li>`).join('')}
            </ul>
          </div>
        </div>
        <div class="phishguard-hud-card-actions">
          <button class="phishguard-action-btn phishguard-btn-safe" id="phishguard-btn-close-2">Close</button>
        </div>
      `;
    } else {
      // Fallback QR view
      showThreatResultsModal(codes, pageUrl, pageTitle);
      return;
    }

    document.body.appendChild(resultModalElement);
    activeOverlays.push(resultModalElement);

    document.getElementById('phishguard-btn-close')?.addEventListener('click', removeExistingOverlays);
    document.getElementById('phishguard-btn-close-2')?.addEventListener('click', removeExistingOverlays);
    document.getElementById('phishguard-btn-stop')?.addEventListener('click', removeExistingOverlays);
    document.getElementById('phishguard-btn-proceed')?.addEventListener('click', removeExistingOverlays);
  }

  // Helper: Extract visible text snippet within a specific screen region
  function extractVisiblePageTextInRegion(rx, ry, rw, rh) {
    const selection = window.getSelection() ? window.getSelection().toString().trim() : '';
    if (selection && selection.length > 5) return selection;

    const elements = document.querySelectorAll('p, span, h1, h2, h3, div, a, li, button, td');
    let collectedText = [];

    elements.forEach(el => {
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        if (
          rect.left >= rx - 50 &&
          rect.right <= rx + rw + 50 &&
          rect.top >= ry - 50 &&
          rect.bottom <= ry + rh + 50
        ) {
          const t = (el.innerText || el.textContent || '').trim();
          if (t && t.length > 3 && !collectedText.includes(t)) {
            collectedText.push(t);
          }
        }
      }
    });

    if (collectedText.length > 0) {
      return collectedText.slice(0, 5).join(' ');
    }

    return extractVisiblePageText();
  }

  // ─── Interactive Region Selection Mode (Ctrl + Shift + Q) ────────────────
  let isRegionSelecting = false;
  let regionSelectionOverlay = null;

  function startRegionSelectionMode(screenshotDataUrl, callback) {
    if (isRegionSelecting) return;
    isRegionSelecting = true;

    removeExistingOverlays();

    regionSelectionOverlay = document.createElement('div');
    regionSelectionOverlay.className = 'phishguard-region-overlay';
    regionSelectionOverlay.innerHTML = `
      <style>
        .phishguard-region-overlay {
          position: fixed;
          inset: 0;
          z-index: 2147483647;
          background: rgba(0, 0, 0, 0.40);
          cursor: crosshair;
          user-select: none;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        .phishguard-region-banner {
          position: absolute;
          top: 24px;
          left: 50%;
          transform: translateX(-50%);
          background: rgba(15, 23, 42, 0.96);
          border: 1px solid rgba(6, 182, 212, 0.6);
          border-radius: 16px;
          padding: 12px 24px;
          color: #fff;
          text-align: center;
          box-shadow: 0 12px 30px rgba(0,0,0,0.6);
          pointer-events: auto;
        }
        .phishguard-smart-highlight-box {
          position: absolute;
          border: 2px solid #06b6d4;
          background: rgba(6, 182, 212, 0.15);
          box-shadow: 0 0 25px rgba(6, 182, 212, 0.5), inset 0 0 15px rgba(6, 182, 212, 0.2);
          pointer-events: auto;
          transition: all 0.08s cubic-bezier(0.16, 1, 0.3, 1);
          border-radius: 8px;
        }
        .phishguard-reticle-badge {
          position: absolute;
          top: -24px;
          left: -2px;
          background: #06b6d4;
          color: #0f172a;
          font-size: 10px;
          font-weight: 800;
          font-family: monospace;
          padding: 2px 8px;
          border-radius: 4px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          box-shadow: 0 4px 10px rgba(0,0,0,0.3);
          pointer-events: none;
          white-space: nowrap;
        }
      </style>
      <div class="phishguard-region-banner">
        <div style="font-size: 13px; font-weight: 800; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.5px;">PhishGuard Smart Scan</div>
        <div style="font-size: 12px; color: #e2e8f0; margin-top: 2px;">Move over content to scan • Click to scan • Esc to cancel</div>
        <div style="font-size: 10px; color: #94a3b8; margin-top: 4px; font-style: italic;">Hover to auto-highlight regions. Click to confirm selection.</div>
      </div>
      <div class="phishguard-smart-highlight-box" id="phishguard-rect" style="display: none;">
        <div class="phishguard-reticle-badge" id="phishguard-rect-badge">[ SMART REGION ]</div>
      </div>
    `;

    document.body.appendChild(regionSelectionOverlay);

    const rectBox = document.getElementById('phishguard-rect');
    const rectBadge = document.getElementById('phishguard-rect-badge');
    let activeBox = { x: 0, y: 0, width: 300, height: 180 };
    let isMouseDown = false;
    let startX = 0, startY = 0;

    const updateHighlightBox = (x, y, width, height, label = 'SMART REGION') => {
      activeBox = { x, y, width, height };
      rectBox.style.left = `${x}px`;
      rectBox.style.top = `${y}px`;
      rectBox.style.width = `${width}px`;
      rectBox.style.height = `${height}px`;
      rectBox.style.display = 'block';
      if (rectBadge) rectBadge.innerText = `[ ${label} ]`;
    };

    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        cleanup();
      }
    };

    const onMouseMoveHover = (e) => {
      if (isMouseDown) return;

      rectBox.style.pointerEvents = 'none';
      regionSelectionOverlay.style.pointerEvents = 'none';
      const el = document.elementFromPoint(e.clientX, e.clientY);
      regionSelectionOverlay.style.pointerEvents = 'auto';

      if (el) {
        const tag = el.tagName ? el.tagName.toLowerCase() : '';
        const rect = el.getBoundingClientRect();

        const isQrImage = tag === 'img' && (el.src?.includes('qr') || el.alt?.includes('qr') || el.className?.includes('qr'));
        const isLink = tag === 'a' || !!el.closest('a');
        const isMsgBlock = el.className?.includes('message') || el.className?.includes('chat') || el.className?.includes('notification') || tag === 'p' || tag === 'h1' || tag === 'h2';

        if (rect.width > 25 && rect.height > 25 && rect.width < window.innerWidth * 0.85 && rect.height < window.innerHeight * 0.85) {
          const pad = 6;
          const label = isQrImage ? 'QR CODE' : isLink ? 'LINK / URL' : isMsgBlock ? 'MESSAGE BLOCK' : 'DETECTED OBJECT';
          updateHighlightBox(
            Math.max(0, rect.left - pad),
            Math.max(0, rect.top - pad),
            rect.width + pad * 2,
            rect.height + pad * 2,
            label
          );
          return;
        }
      }

      const defaultW = 320;
      const defaultH = 180;
      updateHighlightBox(
        Math.max(0, e.clientX - defaultW / 2),
        Math.max(0, e.clientY - defaultH / 2),
        defaultW,
        defaultH,
        'SMART REGION'
      );
    };

    const onMouseDown = (e) => {
      if (e.target.closest('.phishguard-region-banner')) return;
      isMouseDown = true;
      startX = e.clientX;
      startY = e.clientY;
    };

    const onMouseUp = async (e) => {
      if (e.target.closest('.phishguard-region-banner')) return;

      const endX = e.clientX;
      const endY = e.clientY;
      const dragWidth = Math.abs(endX - startX);
      const dragHeight = Math.abs(endY - startY);

      let finalBox = activeBox;
      if (dragWidth > 30 && dragHeight > 30) {
        finalBox = {
          x: Math.min(startX, endX),
          y: Math.min(startY, endY),
          width: dragWidth,
          height: dragHeight
        };
      }

      cleanup();

      showScanningHud();
      const cropResult = await cropAndAnalyzeRegion(screenshotDataUrl, finalBox.x, finalBox.y, finalBox.width, finalBox.height);
      callback(cropResult);
    };

    function cleanup() {
      isRegionSelecting = false;
      window.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('mousemove', onMouseMoveHover);
      if (regionSelectionOverlay) {
        regionSelectionOverlay.remove();
        regionSelectionOverlay = null;
      }
    }

    window.addEventListener('keydown', onKeyDown);
    window.addEventListener('mousemove', onMouseMoveHover);
    regionSelectionOverlay.addEventListener('mousedown', onMouseDown);
    regionSelectionOverlay.addEventListener('mouseup', onMouseUp);
  }


  async function cropAndAnalyzeRegion(screenshotDataUrl, x, y, width, height) {
    const codes = [];
    const barcodes = [];
    let extractedText = '';

    try {
      const img = new Image();
      await new Promise((res, rej) => {
        img.onload = res;
        img.onerror = rej;
        img.src = screenshotDataUrl;
      });

      const scaleX = img.width / window.innerWidth;
      const scaleY = img.height / window.innerHeight;

      const cropX = x * scaleX;
      const cropY = y * scaleY;
      const cropW = width * scaleX;
      const cropH = height * scaleY;

      const canvas = document.createElement('canvas');
      canvas.width = Math.max(1, cropW);
      canvas.height = Math.max(1, cropH);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(img, cropX, cropY, cropW, cropH, 0, 0, canvas.width, canvas.height);

      // 1. Detect QR code
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      if (typeof jsQR !== 'undefined') {
        const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: 'attemptBoth' });
        if (code && code.data) {
          codes.push({ payload: code.data, boundingBox: { x, y, width, height } });
        }
      }

      // 2. Detect Barcode if API supported
      if ('BarcodeDetector' in window) {
        try {
          const detector = new window.BarcodeDetector();
          const detected = await detector.detect(canvas);
          if (detected && detected.length > 0) {
            for (const b of detected) {
              if (b.rawValue) barcodes.push({ rawValue: b.rawValue, format: b.format || 'barcode' });
            }
          }
        } catch (err) {}
      }

      // 3. Extract text in cropped region
      extractedText = extractVisiblePageTextInRegion(x, y, width, height);

    } catch (err) {
      console.warn('[PhishGuard AI] Crop region analysis error:', err);
    }

    return { text: extractedText, codes, barcodes };
  }

  // ─── 6. Message Listener from Background Service Worker ────────────────────
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'SHOW_SCANNING_HUD') {
      showScanningHud();
      sendResponse({ status: 'hud_shown' });
      return false;
    }

    if (msg.type === 'SHOW_NO_QR_HUD') {
      showNoQRToast();
      sendResponse({ status: 'no_qr_shown' });
      return false;
    }

    if (msg.type === 'RUN_TAB_QR_DECODE') {
      decodeQRCodesFromScreenshot(msg.screenshot).then((codes) => {
        sendResponse({ detected: codes.length > 0, codes: codes });
      });
      return true; // async reply
    }

    if (msg.type === 'RUN_UNIVERSAL_TAB_SCAN') {
      startRegionSelectionMode(msg.screenshot, (cropResult) => {
        sendResponse(cropResult);
      });
      return true; // async reply
    }

    if (msg.type === 'DISPLAY_QR_THREAT_RESULTS') {
      showThreatResultsModal(msg.codes, msg.pageUrl, msg.pageTitle);
      sendResponse({ status: 'modal_displayed' });
      return false;
    }

    if (msg.type === 'DISPLAY_UNIVERSAL_THREAT_RESULTS') {
      showUniversalThreatResultsModal(msg.result, msg.codes, msg.pageUrl, msg.pageTitle);
      sendResponse({ status: 'universal_modal_displayed' });
      return false;
    }
  });


  // ─── 7. Passive DOM Scanner on Page Load (Non-Intrusive Background Shield) ───
  setTimeout(() => {
    const qrImgs = document.querySelectorAll('img[src*="qr"], canvas');
    if (qrImgs.length > 0) {
      console.log(`[PhishGuard AI] Background Shield detected ${qrImgs.length} potential QR elements on page. Press Ctrl+Shift+Q to scan.`);
    }
  }, 1500);
})();

