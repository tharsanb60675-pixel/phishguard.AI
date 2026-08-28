import React, { useState, useEffect, useRef } from 'react';
import api from '../services/api';
import jsQR from 'jsqr';
import Tesseract from 'tesseract.js';

const RegionSelectorOverlay = () => {
  const [isDrawing, setIsDrawing] = useState(false);
  const [startPos, setStartPos] = useState({ x: 0, y: 0 });
  const [currentPos, setCurrentPos] = useState({ x: 0, y: 0 });
  
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && window.electronAPI) {
        window.electronAPI.cancelRegionSelection();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleMouseDown = (e) => {
    setIsDrawing(true);
    setStartPos({ x: e.clientX, y: e.clientY });
    setCurrentPos({ x: e.clientX, y: e.clientY });
  };

  const handleMouseMove = (e) => {
    if (isDrawing) {
      setCurrentPos({ x: e.clientX, y: e.clientY });
    }
  };

  const processImage = async (dataUrl) => {
    if (window.electronAPI) {
      window.electronAPI.updateFloatingKeyState('ANALYZING');
    }

    try {
      const img = new Image();
      img.src = dataUrl;
      await new Promise((resolve) => { img.onload = resolve; });

      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      // Extract QR codes
      const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
      const qr_codes = [];
      if (qrCode && qrCode.data) {
        qr_codes.push({
          type: 'qr',
          format: 'QR_CODE',
          rawValue: qrCode.data,
          boundingBox: qrCode.location
        });
      }

      // Extract Text
      const { data: { text } } = await Tesseract.recognize(dataUrl, 'eng');
      
      const payload = {
        text: text || "",
        qr_codes: qr_codes,
        barcodes: [],
        page_url: "Desktop Scanning",
        page_title: "Essential Key"
      };

      const res = await api.post('/qr/analyze-universal', payload);
      const result = res.data;

      // Map Risk
      let riskStr = 'SAFE';
      if (result.threat_score >= 80) riskStr = 'CRITICAL';
      else if (result.threat_score >= 60) riskStr = 'HIGH_RISK';
      else if (result.threat_score >= 40) riskStr = 'SUSPICIOUS';
      
      if (window.electronAPI) {
        window.electronAPI.updateFloatingKeyState(riskStr);
        setTimeout(() => {
          window.electronAPI.updateFloatingKeyState('READY');
        }, 5000);

        window.electronAPI.showNotification({
          title: "PhishGuard.AI Scan Complete",
          body: `Detected: ${result.detected_type || 'Unknown'}\nReason: ${result.reasons?.[0] || 'Clean'}`,
          risk: result.severity,
          confidence: result.confidence
        });
      }
    } catch (err) {
      console.error(err);
      if (window.electronAPI) {
        window.electronAPI.updateFloatingKeyState('READY');
      }
    }
  };

  const handleMouseUp = async (e) => {
    if (!isDrawing) return;
    setIsDrawing(false);
    
    const x = Math.min(startPos.x, currentPos.x);
    const y = Math.min(startPos.y, currentPos.y);
    const width = Math.abs(startPos.x - currentPos.x);
    const height = Math.abs(startPos.y - currentPos.y);

    if (width > 20 && height > 20 && window.electronAPI) {
      window.electronAPI.updateFloatingKeyState('SCANNING');
      // Adding a slight delay to allow UI to update before capture blocks main thread
      setTimeout(async () => {
        const dataUrl = await window.electronAPI.captureRegion({ x, y, width, height });
        if (dataUrl) {
          await processImage(dataUrl);
        } else {
          window.electronAPI.updateFloatingKeyState('READY');
        }
      }, 50);
    } else {
      if (window.electronAPI) {
        window.electronAPI.cancelRegionSelection();
      }
    }
  };

  const x = Math.min(startPos.x, currentPos.x);
  const y = Math.min(startPos.y, currentPos.y);
  const w = Math.abs(currentPos.x - startPos.x);
  const h = Math.abs(currentPos.y - startPos.y);

  return (
    <div 
      className="fixed inset-0 cursor-crosshair z-[9999]"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      style={{ background: 'rgba(0,0,0,0.1)' }}
    >
      {isDrawing && (
        <div 
          className="absolute border-2 border-cyan-400 bg-cyan-500/10 shadow-[0_0_15px_rgba(34,211,238,0.3)]"
          style={{
            left: x,
            top: y,
            width: w,
            height: h
          }}
        >
          {/* Corner accents */}
          <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyan-300"></div>
          <div className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyan-300"></div>
          <div className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyan-300"></div>
          <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyan-300"></div>
        </div>
      )}
    </div>
  );
};

export default RegionSelectorOverlay;
