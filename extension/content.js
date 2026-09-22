// Extension Content Script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'EXTRACT_CONTENT') {
    sendResponse(extractPageData());
  }

  if (request.action === 'SHOW_SCANNER_UI') {
    showOverlayUI();
    // Simulate steps 0-6 over a few seconds, while we extract data
    simulateProgress();
    
    // Return extracted content immediately so background can start AI call
    sendResponse({ success: true, data: extractPageData() });
  }

  if (request.action === 'SHOW_SCAN_RESULT') {
    updateResultUI(request.result);
  }

  return true;
});

function extractPageData() {
  let pageText = document.body.innerText.trim().substring(0, 5000);
  let links = [];
  document.querySelectorAll('a').forEach(a => {
    if (a.href && !a.href.startsWith('javascript:')) {
      links.push(a.href);
    }
  });
  let hasPasswordForms = false;
  document.querySelectorAll('input[type="password"]').forEach(input => {
    hasPasswordForms = true;
  });

  return {
    text: pageText,
    links: Array.from(new Set(links)).slice(0, 50),
    hasPasswordForms: hasPasswordForms
  };
}

let shadowRoot = null;
let overlayHost = null;

const PROGRESS_STAGES = [
  "Initializing Smart Shield...",
  "Capturing visible screen...",
  "Detecting text...",
  "Checking URLs...",
  "Checking phishing indicators...",
  "AI Threat Analysis...",
  "Calculating Safety Score..."
];

function showOverlayUI() {
  if (overlayHost) {
    overlayHost.remove();
  }
  
  overlayHost = document.createElement('div');
  overlayHost.style.position = 'fixed';
  overlayHost.style.inset = '0';
  overlayHost.style.zIndex = '2147483647';
  overlayHost.style.display = 'flex';
  overlayHost.style.alignItems = 'center';
  overlayHost.style.justifyContent = 'center';
  overlayHost.style.backgroundColor = 'rgba(0, 0, 0, 0.6)';
  overlayHost.style.backdropFilter = 'blur(4px)';
  overlayHost.style.fontFamily = 'monospace';
  
  shadowRoot = overlayHost.attachShadow({ mode: 'closed' });
  
  shadowRoot.innerHTML = `
    <style>
      .panel {
        width: 100%;
        max-width: 450px;
        background-color: #080c14;
        border: 1px solid rgba(6, 182, 212, 0.3);
        padding: 32px;
        border-radius: 24px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        color: #f1f5f9;
      }
      .header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 24px;
      }
      .title {
        font-size: 18px;
        font-weight: 900;
        margin: 0;
      }
      .icon {
        width: 24px;
        height: 24px;
        color: #22d3ee;
      }
      .progress-bg {
        height: 16px;
        background-color: #0f172a;
        border-radius: 9999px;
        overflow: hidden;
        border: 1px solid #1e293b;
        margin-bottom: 16px;
      }
      .progress-bar {
        height: 100%;
        background-color: #22d3ee;
        width: 0%;
        transition: width 0.3s ease-out;
        box-shadow: 0 0 10px rgba(6, 182, 212, 0.5);
      }
      .status-row {
        display: flex;
        justify-content: space-between;
        font-size: 12px;
        color: #94a3b8;
      }
      .status-text {
        color: #22d3ee;
        font-weight: bold;
      }
      .result-box {
        display: none;
        padding: 24px;
        border-radius: 16px;
        text-align: center;
        border: 1px solid #334155;
      }
      .result-title {
        font-size: 24px;
        font-weight: 900;
        margin-bottom: 8px;
      }
      .score {
        font-size: 12px;
      }
      .btn-close {
        margin-top: 16px;
        padding: 10px 20px;
        background: #1e293b;
        color: white;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-weight: bold;
      }
      .btn-close:hover {
        background: #334155;
      }
    </style>
    <div class="panel">
      <div class="header">
        <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
        <h3 class="title">PhishGuard.AI Smart Scan</h3>
      </div>
      <div id="progress-container">
        <div class="progress-bg">
          <div id="progress-bar" class="progress-bar"></div>
        </div>
        <div class="status-row">
          <span id="status-text" class="status-text">Initializing...</span>
          <span id="status-pct">0%</span>
        </div>
      </div>
      <div id="result-box" class="result-box">
        <div id="result-title" class="result-title"></div>
        <div id="result-score" class="score"></div>
        <button id="btn-close" class="btn-close">Close</button>
      </div>
    </div>
  `;
  
  document.body.appendChild(overlayHost);
  
  shadowRoot.getElementById('btn-close').addEventListener('click', () => {
    overlayHost.remove();
  });
}

function simulateProgress() {
  if (!shadowRoot) return;
  
  let step = 0;
  const interval = setInterval(() => {
    if (step >= PROGRESS_STAGES.length) {
      clearInterval(interval);
      return;
    }
    
    const pct = Math.round((step / PROGRESS_STAGES.length) * 85); // Cap at 85% until result
    
    const pBar = shadowRoot.getElementById('progress-bar');
    const pText = shadowRoot.getElementById('status-text');
    const pPct = shadowRoot.getElementById('status-pct');
    
    if (pBar) pBar.style.width = pct + '%';
    if (pText) pText.innerText = PROGRESS_STAGES[step];
    if (pPct) pPct.innerText = pct + '%';
    
    step++;
  }, 600);
}

function updateResultUI(result) {
  if (!shadowRoot) return;
  
  const pContainer = shadowRoot.getElementById('progress-container');
  const rBox = shadowRoot.getElementById('result-box');
  const rTitle = shadowRoot.getElementById('result-title');
  const rScore = shadowRoot.getElementById('result-score');
  
  if (pContainer) pContainer.style.display = 'none';
  if (rBox) {
    rBox.style.display = 'block';
    if (result.verdict === 'CRITICAL') {
      rBox.style.backgroundColor = 'rgba(225, 29, 72, 0.1)';
      rBox.style.borderColor = 'rgba(225, 29, 72, 0.5)';
      rTitle.style.color = '#fb7185';
    } else if (result.verdict === 'SUSPICIOUS') {
      rBox.style.backgroundColor = 'rgba(217, 119, 6, 0.1)';
      rBox.style.borderColor = 'rgba(217, 119, 6, 0.5)';
      rTitle.style.color = '#fbbf24';
    } else {
      rBox.style.backgroundColor = 'rgba(16, 185, 129, 0.1)';
      rBox.style.borderColor = 'rgba(16, 185, 129, 0.5)';
      rTitle.style.color = '#34d399';
    }
    rTitle.innerText = result.verdict;
    rScore.innerText = `Safety Score: ${result.riskScore} / 100`;
  }
}
