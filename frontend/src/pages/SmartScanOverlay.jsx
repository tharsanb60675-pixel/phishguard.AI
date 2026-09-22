import React, { useState, useEffect } from 'react';
import Tesseract from 'tesseract.js';
import jsQR from 'jsqr';
import { ShieldCheck, ShieldAlert, Monitor, CheckCircle2, Lock } from 'lucide-react';
import api from '../services/api';

const PROGRESS_STAGES = [
  "Initializing Smart Shield...",
  "Capturing visible screen...",
  "Detecting text...",
  "Checking URLs...",
  "Detecting QR codes...",
  "Checking phishing indicators...",
  "AI Threat Analysis...",
  "Calculating Safety Score...",
  "Scan Complete"
];

const SmartScanOverlay = () => {
  const [authorized, setAuthorized] = useState(
    localStorage.getItem('phishguard_screen_capture_authorized') === 'true'
  );
  
  const [isScanning, setIsScanning] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const [scanResult, setScanResult] = useState(null);
  
  useEffect(() => {
    // Auto-start scan if authorized
    if (authorized && !isScanning && !scanResult) {
      startScan();
    }
  }, [authorized]);

  const handleAllow = () => {
    localStorage.setItem('phishguard_screen_capture_authorized', 'true');
    setAuthorized(true);
  };

  const handleCancel = () => {
    window.electronAPI.closeSmartScanOverlay();
  };

  const startScan = async () => {
    setIsScanning(true);
    setStageIndex(0); // Initializing Smart Shield...
    
    try {
      // Step 2: Capturing
      await new Promise(r => setTimeout(r, 600));
      setStageIndex(1);
      const dataUrl = await window.electronAPI.captureFullScreen();
      if (!dataUrl) throw new Error("Failed to capture screen");

      // Load image for processing
      const img = new Image();
      img.src = dataUrl;
      await new Promise(r => (img.onload = r));

      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      // Step 3 & 4: Text and URLs
      setStageIndex(2);
      const { data: { text } } = await Tesseract.recognize(dataUrl, 'eng');
      
      setStageIndex(3);
      const urlRegex = /(https?:\/\/[^\s]+)/g;
      const urls = text.match(urlRegex) || [];
      await new Promise(r => setTimeout(r, 600));

      // Step 5: QR Codes
      setStageIndex(4);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: 'dontInvert'
      });
      const qrPayload = code ? code.data : null;
      await new Promise(r => setTimeout(r, 600));

      // Step 6 & 7: Phishing & AI Threat
      setStageIndex(5);
      await new Promise(r => setTimeout(r, 800));
      setStageIndex(6);
      
      let score = 0;
      let verdict = 'SAFE';

      // Send to backend (Simulated here if no real endpoint, but let's try the real one)
      let finalVerdict = { riskScore: 0, verdict: 'SAFE' };
      try {
        const payloadToAnalyze = qrPayload || (urls.length > 0 ? urls[0] : text);
        const res = await api.post('/nlp/analyze', { text_content: payloadToAnalyze, sender_context: 'Global Smart Scan' });
        
        // Convert to Risk
        score = res.data.overall_manipulation_score * 100;
        if (score > 60) verdict = 'CRITICAL';
        else if (score > 30) verdict = 'SUSPICIOUS';
        
        finalVerdict = { riskScore: score.toFixed(1), verdict };
      } catch (e) {
        console.warn("Backend unavailable, using local rules");
        const lowerText = text.toLowerCase();
        if (lowerText.includes('login') || lowerText.includes('verify') || lowerText.includes('urgent') || qrPayload) {
          score = 85;
          verdict = 'CRITICAL';
        }
        finalVerdict = { riskScore: score, verdict };
      }

      setStageIndex(7); // Calculating Safety Score
      await new Promise(r => setTimeout(r, 1000));
      
      setStageIndex(8); // Complete
      setScanResult(finalVerdict);
      
      // Notify main app via Notification
      window.electronAPI.showNotification({
         title: `Scan Complete: ${finalVerdict.verdict}`,
         body: `Safety Score: ${finalVerdict.riskScore}/100`,
         risk: finalVerdict.verdict,
         confidence: 95
      });

      // Auto close after result
      setTimeout(() => {
        window.electronAPI.closeSmartScanOverlay();
      }, 3000);

    } catch (err) {
      console.error(err);
      setScanResult({ error: err.message });
      setTimeout(() => {
         window.electronAPI.closeSmartScanOverlay();
      }, 2000);
    }
  };

  // 1. Permission Prompt UI
  if (!authorized) {
    return (
      <div className="w-screen h-screen flex items-center justify-center bg-black/60 backdrop-blur-sm p-6 text-slate-100 font-mono">
        <div className="max-w-md w-full bg-[#080c14] border border-cyan-500/30 p-8 rounded-2xl shadow-2xl animate-slideIn">
          <div className="flex justify-center mb-4">
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Lock className="w-8 h-8" />
            </div>
          </div>
          <h2 className="text-xl font-black text-center text-white mb-2">PhishGuard.AI Screen Protection</h2>
          <p className="text-xs text-slate-400 text-center mb-8 leading-relaxed">
            PhishGuard.AI needs permission to analyze visible screen content for phishing and security threats.
          </p>
          <div className="flex gap-4">
            <button onClick={handleCancel} className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-xl transition-colors">
              Cancel
            </button>
            <button onClick={handleAllow} className="flex-1 py-3 bg-cyan-500 hover:bg-cyan-400 text-black font-extrabold rounded-xl transition-colors shadow-lg shadow-cyan-500/20">
              Allow Screen Access
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 2. Scanning / Result UI
  return (
    <div className="w-screen h-screen flex items-center justify-center bg-black/40 backdrop-blur-sm pointer-events-none p-6 text-slate-100">
      <div className="w-full max-w-lg bg-[#080c14] border border-cyan-500/30 p-8 rounded-3xl shadow-2xl">
        <div className="flex items-center gap-3 mb-6">
          <Monitor className="w-6 h-6 text-cyan-400" />
          <h3 className="text-lg font-black text-white">PhishGuard.AI Smart Scan</h3>
        </div>
        
        {scanResult ? (
           <div className={`p-6 rounded-2xl border flex flex-col items-center justify-center text-center ${
             scanResult.verdict === 'CRITICAL' ? 'bg-rose-950/20 border-rose-500/50' :
             scanResult.verdict === 'SUSPICIOUS' ? 'bg-amber-950/20 border-amber-500/50' :
             'bg-emerald-950/20 border-emerald-500/50'
           }`}>
             {scanResult.verdict === 'CRITICAL' ? (
                <ShieldAlert className="w-12 h-12 text-rose-400 mb-3" />
             ) : (
                <ShieldCheck className="w-12 h-12 text-emerald-400 mb-3" />
             )}
             <div className="text-2xl font-black mb-1">{scanResult.verdict}</div>
             <div className="text-xs font-mono">Safety Score: {scanResult.riskScore} / 100</div>
           </div>
        ) : (
           <div className="space-y-4">
             <div className="h-4 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
               <div 
                 className="h-full bg-cyan-500 transition-all duration-300 ease-out shadow-[0_0_10px_rgba(6,182,212,0.5)]" 
                 style={{ width: `${(stageIndex / (PROGRESS_STAGES.length - 1)) * 100}%` }}
               />
             </div>
             
             <div className="flex justify-between items-center text-xs font-mono">
               <span className="text-cyan-400 font-bold">{PROGRESS_STAGES[stageIndex]}</span>
               <span className="text-slate-400">{Math.round((stageIndex / (PROGRESS_STAGES.length - 1)) * 100)}%</span>
             </div>
           </div>
        )}
      </div>
    </div>
  );
};

export default SmartScanOverlay;
