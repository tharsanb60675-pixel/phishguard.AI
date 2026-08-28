import React, { useState, useEffect, useRef } from 'react';
import { Crosshair, ShieldAlert, CheckCircle, Shield, ClipboardList } from 'lucide-react';
import api from '../services/api';
import Tesseract from 'tesseract.js';
import jsQR from 'jsqr';

const FloatingKeyOverlay = () => {
  const [state, setState] = useState('READY'); // READY, SCANNING, ANALYZING, SAFE, HIGH_RISK
  const [showMenu, setShowMenu] = useState(false);
  const isDragging = useRef(false);
  const dragStart = useRef({ x: 0, y: 0 });

  useEffect(() => {
    if (window.electronAPI) {
      window.electronAPI.onFloatingKeyState((newState) => {
        setState(newState);
      });
    }
  }, []);

  const handleMouseDown = (e) => {
    isDragging.current = true;
    dragStart.current = { x: e.screenX, y: e.screenY };
  };

  const handleMouseMove = (e) => {
    if (isDragging.current && window.electronAPI) {
      const deltaX = e.screenX - dragStart.current.x;
      const deltaY = e.screenY - dragStart.current.y;
      if (Math.abs(deltaX) > 0 || Math.abs(deltaY) > 0) {
        window.electronAPI.moveFloatingKey({ x: deltaX, y: deltaY });
        dragStart.current = { x: e.screenX, y: e.screenY };
      }
    }
  };

  const handleMouseUp = (e) => {
    if (isDragging.current) {
      isDragging.current = false;
      // If we barely moved, treat as a click to start selection
      const deltaX = Math.abs(e.screenX - dragStart.current.x);
      const deltaY = Math.abs(e.screenY - dragStart.current.y);
      if (deltaX < 3 && deltaY < 3 && e.button === 0) {
        setShowMenu(false);
        if (window.electronAPI) {
          window.electronAPI.startRegionSelection();
        }
      }
    }
  };

  const handleContextMenu = (e) => {
    e.preventDefault();
    setShowMenu(true);
  };

  const processClipboard = async () => {
    setShowMenu(false);
    if (!window.electronAPI) return;

    setState('ANALYZING');
    try {
      const clipboardData = await window.electronAPI.readClipboard();
      let textToScan = clipboardData.text || '';
      let qr_codes = [];

      // If there's an image, run OCR and QR
      if (clipboardData.image) {
        const img = new Image();
        img.src = clipboardData.image;
        await new Promise((resolve) => { img.onload = resolve; });

        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
        if (qrCode && qrCode.data) {
          qr_codes.push({
            type: 'qr',
            format: 'QR_CODE',
            rawValue: qrCode.data,
            boundingBox: qrCode.location
          });
        }

        const { data: { text } } = await Tesseract.recognize(clipboardData.image, 'eng');
        if (text) textToScan += ' ' + text;
      }

      if (!textToScan.trim() && qr_codes.length === 0) {
        window.electronAPI.showNotification({
          title: "Clipboard Scan",
          body: "No scannable text, URL, or image found in clipboard.",
          risk: "SAFE",
          confidence: 100
        });
        setState('READY');
        return;
      }

      const payload = {
        text: textToScan,
        qr_codes: qr_codes,
        barcodes: [],
        page_url: "Clipboard Scanning",
        page_title: "Essential Key"
      };

      const res = await api.post('/qr/analyze-universal', payload);
      const result = res.data;

      let riskStr = 'SAFE';
      if (result.threat_score >= 80) riskStr = 'CRITICAL';
      else if (result.threat_score >= 60) riskStr = 'HIGH_RISK';
      else if (result.threat_score >= 40) riskStr = 'SUSPICIOUS';

      setState(riskStr);
      setTimeout(() => setState('READY'), 5000);

      window.electronAPI.showNotification({
        title: "Clipboard Scan Complete",
        body: `Detected: ${result.detected_type || 'Content'}\nReason: ${result.reasons?.[0] || 'Clean'}`,
        risk: result.severity,
        confidence: result.confidence
      });

    } catch (err) {
      console.error("Clipboard scan error:", err);
      setState('READY');
    }
  };

  const getStateStyles = () => {
    switch (state) {
      case 'SCANNING':
        return 'bg-cyan-500/90 text-black border-cyan-400 shadow-[0_0_15px_rgba(34,211,238,0.6)] animate-pulse';
      case 'ANALYZING':
        return 'bg-amber-500/90 text-black border-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.6)] animate-spin-slow';
      case 'SAFE':
        return 'bg-emerald-500/90 text-black border-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.6)]';
      case 'HIGH_RISK':
        return 'bg-rose-500/90 text-white border-rose-400 shadow-[0_0_20px_rgba(244,63,94,0.8)] animate-bounce';
      default: // READY
        return 'bg-slate-900/80 text-cyan-400 border-cyan-500/50 hover:bg-slate-800 hover:border-cyan-400 hover:shadow-[0_0_15px_rgba(34,211,238,0.4)]';
    }
  };

  const getIcon = () => {
    switch (state) {
      case 'SCANNING':
        return <Crosshair className="w-8 h-8 animate-spin" />;
      case 'ANALYZING':
        return <Shield className="w-8 h-8" />;
      case 'SAFE':
        return <CheckCircle className="w-8 h-8" />;
      case 'HIGH_RISK':
        return <ShieldAlert className="w-8 h-8 animate-pulse" />;
      default: // READY
        return <Crosshair className="w-8 h-8" />;
    }
  };

  return (
    <div 
      className="w-full h-full flex items-center justify-center p-2"
      style={{ WebkitUserSelect: 'none', background: 'transparent' }}
    >
      <div 
        className={`w-14 h-14 rounded-full flex items-center justify-center border-2 cursor-pointer backdrop-blur-md transition-all duration-300 ${getStateStyles()}`}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onContextMenu={handleContextMenu}
      >
        {getIcon()}
      </div>

      {showMenu && (
        <div 
          className="absolute top-16 left-16 bg-slate-900 border border-cyan-500/50 rounded-lg shadow-xl overflow-hidden min-w-[140px] animate-in fade-in zoom-in duration-200"
          onMouseLeave={() => setShowMenu(false)}
        >
          <button 
            className="w-full px-4 py-2 text-sm text-cyan-400 hover:bg-slate-800 flex items-center gap-2 transition-colors"
            onClick={processClipboard}
          >
            <ClipboardList className="w-4 h-4" />
            Scan Clipboard
          </button>
        </div>
      )}
    </div>
  );
};

export default FloatingKeyOverlay;
