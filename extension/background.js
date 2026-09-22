// Extension Background Service Worker
chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
  if (request.action === 'PING') {
    sendResponse({ status: 'OK', version: '1.0' });
    return true;
  }
  
  if (request.action === 'SCAN_CURRENT_TAB') {
    executeScanOnActiveTab(sendResponse);
    return true; // Keep message channel open for async response
  }
});

// Extension Shortcut Listener
chrome.commands.onCommand.addListener((command) => {
  if (command === 'scan_current_tab') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length === 0) return;
      const activeTab = tabs[0];
      
      if (activeTab.url.startsWith('chrome://') || activeTab.url.startsWith('edge://')) {
        return;
      }
      
      // Inject content script if not there
      chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        files: ['content.js']
      }).then(() => {
        // Tell content script to show the overlay and extract content
        chrome.tabs.sendMessage(activeTab.id, { action: 'SHOW_SCANNER_UI' }, async (response) => {
          if (!response || !response.success) {
            chrome.tabs.sendMessage(activeTab.id, { action: 'SHOW_SCAN_RESULT', result: { verdict: 'ERROR', riskScore: 0 }});
            return;
          }

          // Make API call to localhost backend
          let score = 0;
          let verdict = 'SAFE';
          
          try {
            const apiResponse = await fetch('http://localhost:8000/api/v1/nlp/analyze', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                text_content: response.data.text || 'No text found',
                sender_context: 'Chrome Extension Global Scan'
              })
            });
            
            if (apiResponse.ok) {
              const resultData = await apiResponse.json();
              score = (resultData.overall_manipulation_score || 0) * 100;
              if (score > 60) verdict = 'CRITICAL';
              else if (score > 30) verdict = 'SUSPICIOUS';
            } else {
               throw new Error("Backend unavailable");
            }
          } catch (e) {
            // Fallback rules
            const lowerText = (response.data.text || '').toLowerCase();
            if (lowerText.includes('login') || lowerText.includes('verify') || lowerText.includes('urgent')) {
              score = 85;
              verdict = 'CRITICAL';
            }
          }

          // Send result back to content script to update UI
          chrome.tabs.sendMessage(activeTab.id, { 
            action: 'SHOW_SCAN_RESULT', 
            result: { riskScore: score.toFixed(1), verdict }
          });
        });
      }).catch((err) => {
        console.error(err);
      });
    });
  }
});

// Helper for the external message
function executeScanOnActiveTab(sendResponse) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) {
      sendResponse({ success: false, error: 'No active tab found' });
      return;
    }
    
    const activeTab = tabs[0];
    if (activeTab.url.startsWith('chrome://') || activeTab.url.startsWith('edge://')) {
      sendResponse({ success: false, error: 'Cannot scan browser internal pages' });
      return;
    }
    
    chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      files: ['content.js']
    }).then(() => {
      chrome.tabs.sendMessage(activeTab.id, { action: 'EXTRACT_CONTENT' }, (response) => {
        if (chrome.runtime.lastError) {
           sendResponse({ success: false, error: chrome.runtime.lastError.message });
        } else {
           sendResponse({ success: true, tabUrl: activeTab.url, tabTitle: activeTab.title, data: response });
        }
      });
    }).catch((err) => {
      sendResponse({ success: false, error: err.message });
    });
  });
}
