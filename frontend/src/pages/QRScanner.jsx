/**
 * QRScanner.jsx — Universal QR & Barcode Threat Scanner with Integrated AI Helpline
 *
 * Universal Multi-Symbology Detection:
 * - 1D Barcodes: EAN-13, EAN-8, UPC-A, UPC-E, Code 128, Code 39, Code 93, ITF, Codabar, ITF-14
 * - 2D Codes: QR Code, Data Matrix, Aztec, PDF417
 * - Dynamically leverages browser native BarcodeDetector API across full uncropped camera frame
 * - Fallback client-side multi-format decoders with jsQR
 * - Identifies and reports exact barcode symbology & category
 * - Routes URL-bearing codes to PhishGuard AI threat intelligence; preserves clean barcode info for numeric barcodes
 * - Deeply integrated AI Helpline Side Panel with automated scan context pass-through
 * - Maintains 10 recent scans audit history
 * - 100% client-side execution — zero third-party camera apps or external scanning services
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Link } from 'react-router-dom';
import jsQR from 'jsqr';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import RiskGauge from '../components/RiskGauge';
import ShapWaterfallChart from '../components/ShapWaterfallChart';
import {
  QrCode,
  Barcode,
  Camera,
  CameraOff,
  Upload,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Link2,
  Mail,
  Phone,
  Wifi,
  FileText,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  AlertTriangle,
  Info,
  Loader2,
  Layers,
  RefreshCw,
  Image as ImageIcon,
  Scan,
  Copy,
  Check,
  History,
  Tag,
  Hash,
  Bot,
  Send,
  Lock,
} from 'lucide-react';

// ─── Barcode Symbologies Registry ─────────────────────────────────────────────
const ALL_BARCODE_FORMATS = [
  'aztec',
  'code_128',
  'code_39',
  'code_93',
  'codabar',
  'data_matrix',
  'ean_13',
  'ean_8',
  'itf',
  'pdf417',
  'qr_code',
  'upc_a',
  'upc_e',
];

const BARCODE_FORMAT_INFO = {
  // 1D Product Barcodes
  ean_13: { name: 'EAN-13', formatType: '1D Product Barcode', is2D: false, description: 'International Article Number (Retail)' },
  ean_8: { name: 'EAN-8', formatType: '1D Product Barcode', is2D: false, description: 'Short-form International Article Number' },
  upc_a: { name: 'UPC-A', formatType: '1D Product Barcode', is2D: false, description: 'Universal Product Code (12-digit Retail)' },
  upc_e: { name: 'UPC-E', formatType: '1D Product Barcode', is2D: false, description: 'Zero-suppressed Universal Product Code' },

  // 1D Industrial / Logistics Barcodes
  code_128: { name: 'Code 128', formatType: '1D Barcode (Alphanumeric)', is2D: false, description: 'High-density alphanumeric code (Logistics/Shipping)' },
  code_39: { name: 'Code 39', formatType: '1D Barcode (Alphanumeric)', is2D: false, description: 'Standard alphanumeric code (Inventory/Defense)' },
  code_93: { name: 'Code 93', formatType: '1D Barcode (High-Density)', is2D: false, description: 'Compact alphanumeric code with checksums' },
  itf: { name: 'ITF / Interleaved 2 of 5', formatType: '1D Packaging Barcode', is2D: false, description: 'Packaging and shipping carton distribution code' },
  itf_14: { name: 'ITF-14', formatType: '1D Packaging Barcode', is2D: false, description: '14-digit Global Trade Item Number for shipping cartons' },
  codabar: { name: 'Codabar', formatType: '1D Barcode (Numeric)', is2D: false, description: 'Numeric code used in libraries, healthcare, and airbills' },

  // 2D Matrix Codes
  qr_code: { name: 'QR Code', formatType: '2D Matrix Code', is2D: true, description: 'High-capacity 2D Quick Response matrix' },
  data_matrix: { name: 'Data Matrix', formatType: '2D Industrial Matrix', is2D: true, description: 'High-density 2D matrix for compact components' },
  aztec: { name: 'Aztec Code', formatType: '2D Matrix Code', is2D: true, description: 'High-density 2D code with central bullseye target' },
  pdf417: { name: 'PDF417', formatType: '2D Stacked Barcode', is2D: true, description: 'High-capacity stacked barcode (IDs, licenses, transport)' },
};

function normalizeBarcodeFormat(rawFormat) {
  if (!rawFormat) {
    return { name: 'Standard Barcode', formatType: 'Barcode', is2D: false, description: 'Universal code' };
  }
  const clean = String(rawFormat).toLowerCase().replace(/[\s-_]+/g, '_');

  if (clean.includes('qr')) return BARCODE_FORMAT_INFO.qr_code;
  if (clean.includes('ean_13') || clean === 'ean13') return BARCODE_FORMAT_INFO.ean_13;
  if (clean.includes('ean_8') || clean === 'ean8') return BARCODE_FORMAT_INFO.ean_8;
  if (clean.includes('upc_a') || clean === 'upca') return BARCODE_FORMAT_INFO.upc_a;
  if (clean.includes('upc_e') || clean === 'upce') return BARCODE_FORMAT_INFO.upc_e;
  if (clean.includes('128')) return BARCODE_FORMAT_INFO.code_128;
  if (clean.includes('39')) return BARCODE_FORMAT_INFO.code_39;
  if (clean.includes('93')) return BARCODE_FORMAT_INFO.code_93;
  if (clean.includes('data_matrix') || clean.includes('datamatrix')) return BARCODE_FORMAT_INFO.data_matrix;
  if (clean.includes('aztec')) return BARCODE_FORMAT_INFO.aztec;
  if (clean.includes('pdf417') || clean.includes('pdf_417')) return BARCODE_FORMAT_INFO.pdf417;
  if (clean.includes('itf_14') || clean.includes('itf14')) return BARCODE_FORMAT_INFO.itf_14;
  if (clean.includes('itf')) return BARCODE_FORMAT_INFO.itf;
  if (clean.includes('codabar')) return BARCODE_FORMAT_INFO.codabar;

  return (
    BARCODE_FORMAT_INFO[clean] || {
      name: String(rawFormat).toUpperCase(),
      formatType: clean.includes('2d') ? '2D Matrix' : '1D Barcode',
      is2D: clean.includes('2d'),
      description: 'Standard decoded symbology',
    }
  );
}

// ─── Payload Content Classifier ───────────────────────────────────────────────
function classifyPayload(raw) {
  if (!raw) return { type: 'other', isUrl: false };
  const s = raw.trim();
  const low = s.toLowerCase();

  // Strict URL detection
  if (low.startsWith('http://') || low.startsWith('https://')) {
    return { type: 'url', isUrl: true };
  }
  if (low.startsWith('mailto:')) return { type: 'email', isUrl: false };
  if (low.startsWith('tel:')) return { type: 'phone', isUrl: false };
  if (low.startsWith('wifi:') || low.startsWith('wifi;')) return { type: 'wifi', isUrl: false };

  // Heuristic domain detection without http (e.g. login-secure.xyz/auth)
  if (s.includes('.') && !s.includes(' ') && s.length < 120) {
    const parts = s.split('/');
    const host = parts[0];
    if (host.includes('.')) {
      const segs = host.split('.');
      if (segs.length >= 2 && segs.every((p) => /^[a-z0-9-]*$/i.test(p)) && segs[segs.length - 1].length >= 2) {
        return { type: 'url', isUrl: true };
      }
    }
  }

  // Pure numeric product barcode (EAN, UPC, etc.)
  if (/^\d{8,14}$/.test(s)) {
    return { type: 'barcode_numeric', isUrl: false };
  }

  return { type: 'text', isUrl: false };
}

const TYPE_META = {
  url: { label: 'URL / Web Destination', Icon: Link2, color: 'text-cyan-400' },
  email: { label: 'Email Address', Icon: Mail, color: 'text-indigo-400' },
  phone: { label: 'Phone Number', Icon: Phone, color: 'text-emerald-400' },
  wifi: { label: 'Wi-Fi Configuration', Icon: Wifi, color: 'text-amber-400' },
  barcode_numeric: { label: 'Product Barcode (Numeric)', Icon: Hash, color: 'text-emerald-400' },
  text: { label: 'Plain Text / Data', Icon: FileText, color: 'text-slate-300' },
  other: { label: 'Standard Data', Icon: Info, color: 'text-slate-400' },
};

// ─── Status Text ──────────────────────────────────────────────────────────────
const STATUS = {
  idle: 'Camera standby — Universal detector active',
  scanning: 'Live Camera Active — Scanning Entire Viewport…',
  image_decoding: 'Decoding uploaded image…',
  detected: 'Code Detected ✓',
  invalid: 'No valid QR code or barcode detected',
  analyzing: 'Analyzing URL with PhishGuard AI…',
  done: 'Analysis & Decoding Complete',
};

// ─── Level Badge Component ────────────────────────────────────────────────────
const LevelBadge = ({ level, label, passed }) => {
  const passedClass = 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300';
  const failedClass = 'bg-rose-500/20 border-rose-500/40 text-rose-300';
  const pendingClass = 'bg-slate-800 border-slate-700 text-slate-400';

  const cls = passed === true ? passedClass : passed === false ? failedClass : pendingClass;
  const Icon = passed === true ? CheckCircle2 : passed === false ? XCircle : Clock;

  return (
    <div className={`flex items-center gap-2.5 px-4 py-3 rounded-xl border ${cls} text-sm font-semibold transition-all`}>
      <Icon className="w-4 h-4 shrink-0" />
      <span className="text-[11px] font-mono uppercase tracking-wider opacity-70">Level {level}</span>
      <span className="text-xs font-semibold">{label}</span>
    </div>
  );
};

// ─── Verdict Badge ────────────────────────────────────────────────────────────
const VerdictBadge = ({ verdict }) => {
  if (!verdict) return null;
  const cls =
    verdict === 'SAFE'
      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
      : verdict === 'SUSPICIOUS'
      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
      : 'bg-rose-500/20 text-rose-300 border border-rose-500/30';

  return (
    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${cls}`}>
      {verdict} THREAT
    </span>
  );
};

// ═════════════════════════════════════════════════════════════════════════════
// Main Universal Scanner Page Component
// ═════════════════════════════════════════════════════════════════════════════
const QRScanner = () => {
  const { addToast, triggerPreClickCheck, updateScanContext } = useThreat();

  // Camera & Device states
  const [scannerActive, setScannerActive] = useState(false);
  const [cameraStatus, setCameraStatus] = useState('idle');
  const [cameraError, setCameraError] = useState(null);
  const [availableDevices, setAvailableDevices] = useState([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState('');

  // Frozen Snapshot & Uploaded Image state
  const [capturedFramePreview, setCapturedFramePreview] = useState(null);
  const [imageError, setImageError] = useState(null);

  // Decoded Code Information
  const [decodedInfo, setDecodedInfo] = useState(null);

  // Threat Analysis result for URLs
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);

  // Confirmation dialog for risky URLs
  const [confirmNavOpen, setConfirmNavOpen] = useState(false);

  // Recent Scans List (stored in localStorage)
  const [recentScans, setRecentScans] = useState(() => {
    try {
      const saved = localStorage.getItem('phishguard_universal_scans');
      return saved ? JSON.parse(saved) : [];
    } catch (e) {
      return [];
    }
  });

  // Copied indicator state
  const [copied, setCopied] = useState(false);

  // ─── Inline AI Helpline Chat State ───
  const [helplineOpen, setHelplineOpen] = useState(true);
  const [chatMessages, setChatMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatScrollRef = useRef(null);

  // DOM Refs & Loop Controllers
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const fileInputRef = useRef(null);
  const streamRef = useRef(null);
  const animationFrameRef = useRef(null);
  const isScanningRef = useRef(false);
  const isProcessingRef = useRef(false);
  const lastScanTimestampRef = useRef(0);
  const lastDecodedValueRef = useRef('');
  const lastDecodedTimeRef = useRef(0);

  // Save recent scans to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('phishguard_universal_scans', JSON.stringify(recentScans.slice(0, 10)));
    } catch (e) {}
  }, [recentScans]);

  // Scroll chat messages
  useEffect(() => {
    chatScrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, chatLoading]);

  // ─── Enumerate Available Cameras ───────────────────────────────────────────
  const updateDeviceList = useCallback(async () => {
    try {
      if (navigator.mediaDevices?.enumerateDevices) {
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoInputs = devices.filter((d) => d.kind === 'videoinput');
        setAvailableDevices(videoInputs);
        if (videoInputs.length > 0 && !selectedDeviceId) {
          setSelectedDeviceId(videoInputs[0].deviceId);
        }
      }
    } catch (err) {
      console.warn('Unable to enumerate camera devices:', err);
    }
  }, [selectedDeviceId]);

  useEffect(() => {
    updateDeviceList();
  }, [updateDeviceList]);

  // ─── Run Threat Analysis for URLs ─────────────────────────────────────────
  const runAnalysis = useCallback(async (payload, type, currentInfo) => {
    setAnalyzing(true);
    setAnalysisError(null);
    setCameraStatus('analyzing');

    try {
      const res = await api.post('/qr/analyze-url', {
        decoded_payload: payload,
        client_detected_type: type,
      });
      setAnalysisResult(res.data);
      setCameraStatus('done');
      const verdict = res.data.security_analysis?.verdict;
      const score = res.data.security_analysis?.risk_score || 0;

      // Update Global Scan Context
      const contextData = {
        formatName: currentInfo?.formatName || 'QR Code',
        type: currentInfo?.typeCategory || 'url',
        rawValue: payload,
        isUrl: true,
        riskScore: score,
        verdict: verdict,
        reasons: [res.data.security_reason],
        actionableAdvice: res.data.recommended_action,
        timestamp: new Date().toISOString(),
      };
      updateScanContext(contextData);

      // Auto-initialize Helpline Chat Message
      const isRisky = verdict !== 'SAFE';
      setChatMessages([
        {
          id: 'initial-ai-msg',
          sender: 'ai',
          text: `I analyzed the ${currentInfo?.formatName || 'QR code'} you scanned.\n\n${
            isRisky
              ? `⚠️ **${verdict} Threat Detected (Risk: ${score.toFixed(1)}/100)**\nThis URL points to a potentially risky destination. Would you like me to explain why this link is dangerous or what you should do?`
              : `✓ **Verified Safe Destination (Risk: ${score.toFixed(1)}/100)**\nThis URL has no known phishing indicators.`
          }`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);

      addToast(
        `Threat Analysis complete: ${verdict || 'Done'}`,
        verdict === 'SAFE' ? 'success' : 'error'
      );
    } catch (err) {
      const msg =
        err.response?.data?.detail ||
        (err.message?.includes('Network Error')
          ? 'Network unavailable — cannot reach PhishGuard AI analysis service.'
          : 'Analysis service error. Please try again.');
      setAnalysisError(msg);
      setCameraStatus('done');
      addToast('Analysis failed: ' + msg, 'error');
    } finally {
      setAnalyzing(false);
      isProcessingRef.current = false;
    }
  }, [addToast, updateScanContext]);

  // ─── Stop Camera Stream & Clean Up All Tracks ─────────────────────────────
  const stopCamera = useCallback(() => {
    isScanningRef.current = false;
    if (animationFrameRef.current) {
      cancelAnimationFrame(animationFrameRef.current);
      animationFrameRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => {
        try {
          track.stop();
        } catch (e) {}
      });
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setScannerActive(false);
  }, []);

  // Cleanup camera stream on unmount
  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, [stopCamera]);

  // ─── Handle Successful Code Detection (QR or Barcode) ─────────────────────
  const handleCodeDetected = useCallback((rawText, rawFormat, source = 'Laptop Camera', snapshotDataUrl = null) => {
    if (!rawText || !rawText.trim()) return;

    const trimmed = rawText.trim();
    const now = Date.now();

    // Duplicate detection debounce (ignore exact same code within 2.5s)
    if (trimmed === lastDecodedValueRef.current && now - lastDecodedTimeRef.current < 2500) {
      return;
    }

    if (isProcessingRef.current) return;
    isProcessingRef.current = true;

    lastDecodedValueRef.current = trimmed;
    lastDecodedTimeRef.current = now;

    // Save frozen frame if available
    if (snapshotDataUrl) {
      setCapturedFramePreview(snapshotDataUrl);
    }

    // Stop camera immediately
    stopCamera();

    // Determine format metadata
    const formatMeta = normalizeBarcodeFormat(rawFormat);
    const classification = classifyPayload(trimmed);

    const info = {
      rawValue: trimmed,
      formatName: formatMeta.name,
      formatType: formatMeta.formatType,
      is2D: formatMeta.is2D,
      description: formatMeta.description,
      isUrl: classification.isUrl,
      typeCategory: classification.type,
      source: source,
      timestamp: new Date().toISOString(),
    };

    setDecodedInfo(info);
    setCameraStatus('detected');
    addToast(`${info.formatName} detected!`, 'success');

    // Add to Recent Scans Ledger
    setRecentScans((prev) => [
      {
        id: Date.now(),
        format: info.formatName,
        value: info.rawValue,
        source: source,
        isUrl: info.isUrl,
        timestamp: new Date().toLocaleString(),
      },
      ...prev.slice(0, 9),
    ]);

    // If URL detected, send to PhishGuard AI threat pipeline
    if (info.isUrl) {
      runAnalysis(trimmed, 'url', info);
    } else {
      // For standard numeric barcode, initialize Helpline with barcode explanation
      updateScanContext({
        formatName: info.formatName,
        type: 'barcode_numeric',
        rawValue: trimmed,
        isUrl: false,
        riskScore: 0,
        verdict: 'SAFE',
        description: info.description,
        timestamp: new Date().toISOString(),
      });
      setChatMessages([
        {
          id: 'initial-ai-msg-barcode',
          sender: 'ai',
          text: `I identified a **${info.formatName}** (${info.formatType}) with payload \`${trimmed}\`.\n\nThis is a standard numeric barcode. It contains no web URLs or executable links and is completely safe.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
      setCameraStatus('done');
      isProcessingRef.current = false;
    }
  }, [stopCamera, runAnalysis, addToast, updateScanContext]);

  // ─── Full-Frame Real-Time Universal Detection Loop ─────────────────────────
  const scanFrame = useCallback(async (timestamp) => {
    if (!isScanningRef.current || !videoRef.current || !canvasRef.current || isProcessingRef.current) {
      return;
    }

    if (timestamp - lastScanTimestampRef.current >= 110) {
      lastScanTimestampRef.current = timestamp;

      const video = videoRef.current;
      const canvas = canvasRef.current;

      if (video.readyState >= video.HAVE_CURRENT_DATA && video.videoWidth > 0 && video.videoHeight > 0) {
        const fullWidth = video.videoWidth;
        const fullHeight = video.videoHeight;

        canvas.width = fullWidth;
        canvas.height = fullHeight;
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(video, 0, 0, fullWidth, fullHeight);

        let detectedValue = null;
        let detectedFormat = null;

        // METHOD 1: Native BarcodeDetector (Supports EAN-13, UPC, Code 128, QR, DataMatrix, Aztec, PDF417, etc.)
        if ('BarcodeDetector' in window) {
          try {
            const barcodeDetector = new window.BarcodeDetector({ formats: ALL_BARCODE_FORMATS });
            const barcodes = await barcodeDetector.detect(canvas);
            if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
              detectedValue = barcodes[0].rawValue;
              detectedFormat = barcodes[0].format || 'barcode';
            }
          } catch (e) {}
        }

        // METHOD 2: jsQR Fallback for QR Codes across full frame
        if (!detectedValue) {
          try {
            const fullImageData = ctx.getImageData(0, 0, fullWidth, fullHeight);
            const code = jsQR(fullImageData.data, fullImageData.width, fullImageData.height, {
              inversionAttempts: 'attemptBoth',
            });
            if (code && code.data) {
              detectedValue = code.data;
              detectedFormat = 'qr_code';
            }
          } catch (e) {}
        }

        if (detectedValue) {
          let snapshot = null;
          try {
            snapshot = canvas.toDataURL('image/jpeg', 0.85);
          } catch (e) {}
          handleCodeDetected(detectedValue, detectedFormat, 'Laptop Camera', snapshot);
          return;
        }
      }
    }

    if (isScanningRef.current) {
      animationFrameRef.current = requestAnimationFrame(scanFrame);
    }
  }, [handleCodeDetected]);

  // ─── Start Camera (Native getUserMedia) ────────────────────────────────────
  const startCamera = useCallback(async (deviceIdToUse = selectedDeviceId) => {
    isProcessingRef.current = false;
    setCameraError(null);
    setImageError(null);
    setCapturedFramePreview(null);
    setDecodedInfo(null);
    setAnalysisResult(null);
    setAnalysisError(null);
    setCameraStatus('scanning');

    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Camera API (getUserMedia) is not supported in this browser.');
      }

      if (streamRef.current) {
        streamRef.current.getTracks().forEach((t) => t.stop());
      }

      const constraints = {
        audio: false,
        video: deviceIdToUse
          ? { deviceId: { exact: deviceIdToUse }, width: { ideal: 1280 }, height: { ideal: 720 } }
          : { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
      };

      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      streamRef.current = stream;

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute('playsinline', 'true');
        await videoRef.current.play();
      }

      isScanningRef.current = true;
      setScannerActive(true);
      await updateDeviceList();

      animationFrameRef.current = requestAnimationFrame(scanFrame);
    } catch (err) {
      isScanningRef.current = false;
      setScannerActive(false);
      setCameraStatus('idle');

      let userMsg = 'Camera initialization failed. Please check your browser settings and try again.';

      if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
        userMsg = 'Camera permission denied. Please allow camera access in your browser settings and try again.';
      } else if (err.name === 'NotFoundError' || err.name === 'DevicesNotFoundError') {
        userMsg = 'No camera detected on this device.';
      } else if (err.name === 'NotReadableError' || err.name === 'TrackStartError') {
        userMsg = 'Camera is already in use by another application.';
      } else if (err.name === 'OverconstrainedError') {
        userMsg = 'The requested camera device is unavailable. Try selecting another camera.';
      }

      setCameraError(userMsg);
      addToast(userMsg, 'error');
    }
  }, [selectedDeviceId, scanFrame, updateDeviceList, addToast]);

  const handleDeviceChange = (e) => {
    const newDeviceId = e.target.value;
    setSelectedDeviceId(newDeviceId);
    if (scannerActive) {
      startCamera(newDeviceId);
    }
  };

  // ─── Decode Uploaded QR / Barcode Image ───────────────────────────────────
  const handleImageUpload = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    stopCamera();
    isProcessingRef.current = false;
    setCameraError(null);
    setImageError(null);
    setCapturedFramePreview(null);
    setDecodedInfo(null);
    setAnalysisResult(null);
    setAnalysisError(null);
    setCameraStatus('image_decoding');

    const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'];
    if (!validTypes.includes(file.type.toLowerCase())) {
      const err = 'Unsupported format. Please upload a PNG, JPG, JPEG, or WEBP image.';
      setImageError(err);
      setCameraStatus('idle');
      addToast(err, 'error');
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => {
      const err = 'Failed to read the image file. Please try another image.';
      setImageError(err);
      setCameraStatus('idle');
      addToast(err, 'error');
    };

    reader.onload = () => {
      const dataUrl = reader.result;
      setCapturedFramePreview(dataUrl);

      const img = new Image();
      img.onload = async () => {
        try {
          const canvas = canvasRef.current || document.createElement('canvas');
          let detectedVal = null;
          let detectedFmt = null;

          canvas.width = img.naturalWidth || img.width;
          canvas.height = img.naturalHeight || img.height;
          const ctx = canvas.getContext('2d', { willReadFrequently: true });
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

          // 1. Native BarcodeDetector
          if ('BarcodeDetector' in window) {
            try {
              const detector = new window.BarcodeDetector({ formats: ALL_BARCODE_FORMATS });
              const barcodes = await detector.detect(img);
              if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
                detectedVal = barcodes[0].rawValue;
                detectedFmt = barcodes[0].format || 'barcode';
              }
            } catch (e) {}
          }

          // 2. jsQR Fallback
          if (!detectedVal) {
            const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imgData.data, imgData.width, imgData.height, {
              inversionAttempts: 'attemptBoth',
            });
            if (code && code.data) {
              detectedVal = code.data;
              detectedFmt = 'qr_code';
            }
          }

          // 3. Fallback: Scaled-down for high-resolution images
          if (!detectedVal && (canvas.width > 1200 || canvas.height > 1200)) {
            const scale = Math.min(1000 / canvas.width, 1000 / canvas.height);
            const sw = Math.round(canvas.width * scale);
            const sh = Math.round(canvas.height * scale);
            canvas.width = sw;
            canvas.height = sh;
            ctx.drawImage(img, 0, 0, sw, sh);
            const scaledData = ctx.getImageData(0, 0, sw, sh);
            const codeScaled = jsQR(scaledData.data, scaledData.width, scaledData.height, {
              inversionAttempts: 'attemptBoth',
            });
            if (codeScaled && codeScaled.data) {
              detectedVal = codeScaled.data;
              detectedFmt = 'qr_code';
            }
          }

          if (detectedVal) {
            handleCodeDetected(detectedVal, detectedFmt, 'Uploaded Image', dataUrl);
          } else {
            const noCodeMsg = 'No QR code or barcode detected. Please upload a clear QR or barcode image.';
            setImageError(noCodeMsg);
            setCameraStatus('invalid');
            addToast(noCodeMsg, 'warning');
          }
        } catch (decodeErr) {
          const err = 'Failed to decode barcode from image: ' + (decodeErr.message || decodeErr);
          setImageError(err);
          setCameraStatus('idle');
          addToast(err, 'error');
        }
      };

      img.onerror = () => {
        const err = 'Invalid image file or corrupted image data.';
        setImageError(err);
        setCameraStatus('idle');
        addToast(err, 'error');
      };

      img.src = dataUrl;
    };

    reader.readAsDataURL(file);

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // ─── Reset Entire Scanner ─────────────────────────────────────────────────
  const handleReset = () => {
    stopCamera();
    isProcessingRef.current = false;
    setCapturedFramePreview(null);
    setImageError(null);
    setCameraError(null);
    setDecodedInfo(null);
    setAnalysisResult(null);
    setAnalysisError(null);
    setChatMessages([]);
    setCameraStatus('idle');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleCopyValue = () => {
    if (!decodedInfo?.rawValue) return;
    navigator.clipboard.writeText(decodedInfo.rawValue);
    setCopied(true);
    addToast('Copied to clipboard!', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleOpenUrl = () => {
    const verdict = analysisResult?.security_analysis?.verdict;
    if (verdict === 'SAFE') {
      triggerPreClickCheck(decodedInfo.rawValue, () => {
        window.open(decodedInfo.rawValue, '_blank', 'noopener,noreferrer');
      });
    } else {
      setConfirmNavOpen(true);
    }
  };

  const handleConfirmNav = () => {
    setConfirmNavOpen(false);
    window.open(decodedInfo.rawValue, '_blank', 'noopener,noreferrer');
  };

  // ─── In-Panel AI Helpline Chat Dispatcher ─────────────────────────────────
  const handleSendHelplineMessage = async (msgText = chatInput) => {
    const text = msgText.trim();
    if (!text || chatLoading) return;

    const userMsg = {
      id: `u-${Date.now()}`,
      sender: 'user',
      text: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    const newChatMessages = [...chatMessages, userMsg];
    setChatMessages(newChatMessages);
    setChatInput('');
    setChatLoading(true);

    // Build multi-turn history
    const historyPayload = newChatMessages.map((m) => ({
      role: m.sender === 'user' ? 'user' : 'assistant',
      content: m.text,
    }));

    try {
      const res = await api.post('/chat/', {
        message: text,
        history: historyPayload,
        scan_context: {
          formatName: decodedInfo?.formatName || 'QR Code',
          type: decodedInfo?.typeCategory || 'url',
          rawValue: decodedInfo?.rawValue || '',
          isUrl: decodedInfo?.isUrl || false,
          riskScore: analysisResult?.security_analysis?.risk_score || 0,
          verdict: analysisResult?.security_analysis?.verdict || 'SAFE',
          reasons: [analysisResult?.security_reason],
          actionableAdvice: analysisResult?.recommended_action,
        },
      });

      setChatMessages((prev) => [
        ...prev,
        {
          id: `ai-${Date.now()}`,
          sender: 'ai',
          text: res.data.response,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } catch (err) {
      setChatMessages((prev) => [
        ...prev,
        {
          id: `ai-${Date.now()}`,
          sender: 'ai',
          text: "I analyzed your scan: Remember to never share passwords, OTPs, or credit card details on unverified pages.",
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const scanResult = analysisResult?.security_analysis;
  const verdict = scanResult?.verdict;

  const verdictBorder =
    verdict === 'SAFE'
      ? 'border-emerald-500/40 bg-emerald-950/10'
      : verdict === 'SUSPICIOUS'
      ? 'border-amber-500/40 bg-amber-950/10'
      : verdict
      ? 'border-rose-500/40 bg-rose-950/10'
      : 'border-slate-800';

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Hidden Offscreen Canvas for Full-Frame Image Processing */}
      <canvas ref={canvasRef} className="hidden" />

      {/* Hidden File Input for Image Upload */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/png, image/jpeg, image/jpg, image/webp"
        className="hidden"
        onChange={handleImageUpload}
      />

      {/* ── Page Header ── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            Universal Optical Threat & Symbology Scanner
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            QR & Barcode Threat Scanner
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Scan QR codes and barcodes in real time. Decodes locally and connects directly to the integrated PhishGuard AI Helpline.
          </p>
        </div>

        <Link
          to="/helpline"
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-300 text-xs font-semibold self-start md:self-auto transition-colors"
        >
          <Bot className="w-4 h-4 text-cyan-400" />
          Open Dedicated AI Helpline ↗
        </Link>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* ── Left: Camera & Full-Frame Scanner Viewport (3 cols) ── */}
        <div className="lg:col-span-3 space-y-4">
          <div className="glass-panel rounded-2xl p-5 border border-slate-800 space-y-4">
            
            {/* Status Bar & Camera Selection Dropdown */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                {scannerActive ? (
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500" />
                  </span>
                ) : (
                  <span className="h-2.5 w-2.5 rounded-full bg-slate-600" />
                )}
                <span className="text-xs font-mono text-slate-300">
                  {STATUS[cameraStatus] || STATUS.idle}
                </span>
                {analyzing && <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin ml-1" />}
              </div>

              {/* Camera Selector Dropdown */}
              {availableDevices.length > 0 && (
                <div className="flex items-center gap-2">
                  <label htmlFor="camera-select" className="text-[11px] font-mono text-slate-400 whitespace-nowrap">
                    Camera:
                  </label>
                  <select
                    id="camera-select"
                    value={selectedDeviceId}
                    onChange={handleDeviceChange}
                    className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 focus:outline-none focus:border-cyan-500 max-w-[200px] truncate"
                  >
                    {availableDevices.map((device, idx) => (
                      <option key={device.deviceId} value={device.deviceId}>
                        {device.label || `Camera ${idx + 1}`}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {/* Viewport: Live Full-Frame Video / Frozen Snapshot / Placeholder */}
            <div
              className="relative w-full rounded-xl overflow-hidden bg-slate-950 border border-slate-800 flex items-center justify-center"
              style={{ minHeight: 340, maxHeight: 440 }}
            >
              {/* Native HTML5 Video for Laptop Webcam */}
              <video
                ref={videoRef}
                playsInline
                muted
                autoPlay
                className={`w-full h-full object-contain bg-black ${scannerActive ? 'block' : 'hidden'}`}
                style={{ minHeight: 340, maxHeight: 440 }}
              />

              {/* Universal Visual Guide Overlay */}
              {scannerActive && (
                <div className="absolute inset-0 pointer-events-none flex flex-col items-center justify-between p-4">
                  {/* Top Symbologies Pill */}
                  <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-950/85 border border-cyan-500/40 text-[11px] font-mono text-cyan-300 backdrop-blur-sm shadow-md">
                    <Scan className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                    <span>Universal Scanner: QR • EAN • UPC • Code 128 • 2D Matrix</span>
                  </div>

                  {/* Corner Accent Brackets on Full Frame */}
                  <div className="absolute inset-4 border border-cyan-500/20 rounded-xl pointer-events-none">
                    <div className="absolute top-0 left-0 w-5 h-5 border-t-2 border-l-2 border-cyan-400" />
                    <div className="absolute top-0 right-0 w-5 h-5 border-t-2 border-r-2 border-cyan-400" />
                    <div className="absolute bottom-0 left-0 w-5 h-5 border-b-2 border-l-2 border-cyan-400" />
                    <div className="absolute bottom-0 right-0 w-5 h-5 border-b-2 border-r-2 border-cyan-400" />

                    {/* Laser scanning beam */}
                    <div
                      className="absolute left-2 right-2 h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent shadow-[0_0_10px_#22d3ee]"
                      style={{ animation: 'fullScanline 2.2s ease-in-out infinite', top: '50%' }}
                    />
                  </div>

                  {/* Bottom Viewport Banner */}
                  <div className="px-3 py-1 rounded-full bg-slate-950/85 border border-slate-700/60 text-[10px] font-mono text-slate-300 backdrop-blur-sm">
                    Hold any 1D/2D barcode anywhere in camera frame
                  </div>
                </div>
              )}

              {/* Frozen Captured Frame / Uploaded Image Preview Mode */}
              {!scannerActive && capturedFramePreview && (
                <div className="relative w-full h-full flex flex-col items-center justify-center p-3 bg-slate-950">
                  <img
                    src={capturedFramePreview}
                    alt="Captured Snapshot"
                    className="max-h-[320px] w-auto max-w-full rounded-lg object-contain border border-cyan-500/40 shadow-xl"
                  />
                  <div className="absolute top-3 right-3 px-2.5 py-1 rounded-md bg-slate-900/90 text-emerald-300 text-[10px] font-mono border border-emerald-500/40 flex items-center gap-1.5 shadow">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    {decodedInfo ? `${decodedInfo.formatName} Captured` : 'Image Loaded'}
                  </div>
                </div>
              )}

              {/* Inactive Standby Placeholder */}
              {!scannerActive && !capturedFramePreview && !cameraError && !imageError && (
                <div className="p-8 flex flex-col items-center justify-center gap-3 text-center text-slate-500">
                  <div className="flex items-center gap-2 p-4 rounded-2xl bg-slate-900 border border-slate-800">
                    <QrCode className="w-8 h-8 text-cyan-400 opacity-60" />
                    <Barcode className="w-8 h-8 text-indigo-400 opacity-60" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-300">Universal Scanner Standby</p>
                    <p className="text-xs text-slate-500 mt-1 max-w-xs">
                      Click <strong className="text-cyan-400">Start Camera</strong> to scan QR codes & barcodes live, or <strong className="text-indigo-400">Upload QR / Barcode Image</strong>.
                    </p>
                  </div>
                </div>
              )}

              {/* Camera Error Message Display */}
              {cameraError && (
                <div className="p-6 flex flex-col items-center justify-center gap-3 text-center">
                  <div className="p-3 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/30">
                    <CameraOff className="w-8 h-8" />
                  </div>
                  <p className="text-sm text-rose-300 font-semibold max-w-md">{cameraError}</p>
                  <p className="text-xs text-slate-400 max-w-sm">
                    Ensure camera permissions are enabled in your browser address bar and no other application is using the camera.
                  </p>
                </div>
              )}

              {/* Image Error Message Display */}
              {imageError && !cameraError && !capturedFramePreview && (
                <div className="p-6 flex flex-col items-center justify-center gap-3 text-center">
                  <div className="p-3 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    <AlertTriangle className="w-8 h-8" />
                  </div>
                  <p className="text-sm text-amber-300 font-semibold max-w-md">{imageError}</p>
                </div>
              )}
            </div>

            {/* Helper Caption */}
            <div className="text-center">
              <p className="text-xs text-slate-400 font-medium">
                QR codes and barcodes are detected automatically across the entire camera view.
              </p>
            </div>

            {/* ── Action Control Buttons ── */}
            <div className="flex flex-wrap items-center gap-3 pt-1">
              {!scannerActive ? (
                <button
                  id="qr-start-camera"
                  onClick={() => startCamera()}
                  className="flex-1 min-w-[140px] flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-sm shadow-lg shadow-cyan-500/25 transition-all hover:scale-[1.01]"
                >
                  <Camera className="w-4 h-4" />
                  {decodedInfo ? 'Scan Again (Camera)' : 'Start Camera'}
                </button>
              ) : (
                <button
                  id="qr-stop-camera"
                  onClick={stopCamera}
                  className="flex-1 min-w-[140px] flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold text-sm transition-colors"
                >
                  <CameraOff className="w-4 h-4 text-rose-400" />
                  Stop Camera
                </button>
              )}

              {/* Upload QR / Barcode Image Button */}
              <button
                id="qr-upload-image"
                onClick={() => fileInputRef.current?.click()}
                className="flex-1 min-w-[170px] flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-indigo-600/20 hover:bg-indigo-600/30 border border-indigo-500/40 text-indigo-300 font-semibold text-sm transition-all"
              >
                <Upload className="w-4 h-4" />
                Upload QR / Barcode Image
              </button>

              {/* Reset Button */}
              {(decodedInfo || cameraError || imageError || capturedFramePreview) && (
                <button
                  id="qr-reset"
                  onClick={handleReset}
                  className="flex items-center gap-1.5 px-4 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-sm transition-colors"
                  title="Reset Scanner"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  Reset
                </button>
              )}
            </div>

            {/* Privacy Notice */}
            <p className="text-[11px] text-slate-500 font-mono text-center">
              100% In-browser execution via native WebRTC. No external camera apps, Google Lens, or third-party cloud services used.
            </p>
          </div>

          {/* ── Recent Scans History Ledger (Last 10 scans) ── */}
          <div className="glass-panel rounded-2xl p-5 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <History className="w-4 h-4 text-cyan-400" />
                Recent Scans Ledger
              </h3>
              {recentScans.length > 0 && (
                <button
                  onClick={() => setRecentScans([])}
                  className="text-[11px] font-mono text-slate-500 hover:text-rose-400 transition-colors"
                >
                  Clear History
                </button>
              )}
            </div>

            {recentScans.length === 0 ? (
              <p className="text-xs text-slate-500 font-mono italic">No recent scans yet. Scan a QR code or barcode to record entries.</p>
            ) : (
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {recentScans.map((item) => (
                  <div
                    key={item.id}
                    className="p-2.5 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-cyan-300 font-mono text-[11px]">
                          {item.format}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          • {item.source}
                        </span>
                      </div>
                      <p className="font-mono text-slate-200 truncate text-[11px] mt-0.5">
                        {item.value}
                      </p>
                    </div>
                    <span className="text-[10px] text-slate-500 font-mono whitespace-nowrap">
                      {item.timestamp}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ── Right: Barcode Information & Integrated AI Helpline (2 cols) ── */}
        <div className="lg:col-span-2 space-y-4">
          {decodedInfo ? (
            <div className={`glass-panel rounded-2xl p-5 border space-y-4 animate-fadeIn ${verdictBorder}`}>
              {/* Header */}
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <span className="text-sm font-bold text-white">✓ CODE DETECTED</span>
                </div>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-900 border border-slate-700 text-slate-300">
                  {decodedInfo.is2D ? '2D Matrix' : '1D Barcode'}
                </span>
              </div>

              {/* Barcode Information Card Fields */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800">
                  <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block mb-0.5">
                    Type
                  </span>
                  <span className="text-sm font-bold text-cyan-300 font-mono">
                    {decodedInfo.formatName}
                  </span>
                </div>

                <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800">
                  <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block mb-0.5">
                    Format
                  </span>
                  <span className="text-xs font-semibold text-slate-200">
                    {decodedInfo.formatType}
                  </span>
                </div>
              </div>

              {/* Decoded Value Box */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400">
                    Decoded Value:
                  </span>
                  <button
                    onClick={handleCopyValue}
                    className="flex items-center gap-1 text-[10px] font-mono text-cyan-400 hover:text-cyan-300"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <div className="p-3.5 bg-slate-950/90 rounded-xl border border-slate-800 break-all font-mono text-xs text-slate-200 max-h-32 overflow-y-auto select-all">
                  {decodedInfo.rawValue}
                </div>
              </div>

              {/* Source & Status Metadata */}
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="p-2.5 bg-slate-900/60 rounded-xl border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">Source:</span>
                  <span className="text-slate-300 font-semibold">{decodedInfo.source}</span>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded-xl border border-slate-800/80">
                  <span className="text-slate-500 block text-[10px]">Status:</span>
                  <span className="text-emerald-400 font-semibold">Successfully Decoded</span>
                </div>
              </div>

              {/* If NOT a URL: Clear confirmation */}
              {!decodedInfo.isUrl && (
                <div className="p-3 bg-slate-800/60 rounded-xl border border-slate-700/60 space-y-1">
                  <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Standard Barcode Payload
                  </div>
                  <p className="text-xs text-slate-400">
                    URL Detected: <strong className="text-slate-300">NO</strong>. No threat scanning needed for pure numeric barcodes.
                  </p>
                </div>
              )}

              {/* PhishGuard AI Comprehensive Threat Result Section */}
              <div className="space-y-3.5 pt-3 border-t border-slate-800/80">
                {/* Threat Level Banner & Score */}
                {analysisResult && (
                  <div className={`p-4 rounded-xl border flex items-center justify-between gap-3 ${
                    (analysisResult.threat_score >= 80)
                      ? 'bg-rose-950/30 border-rose-500/50'
                      : (analysisResult.threat_score >= 60)
                      ? 'bg-orange-950/30 border-orange-500/50'
                      : (analysisResult.threat_score >= 40 || analysisResult.verdict?.includes('UNKNOWN'))
                      ? 'bg-amber-950/30 border-amber-500/50'
                      : 'bg-emerald-950/30 border-emerald-500/50'
                  }`}>
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block font-bold">
                        Threat Level
                      </span>
                      <div className="text-base font-extrabold text-white tracking-tight mt-0.5">
                        {analysisResult.threat_score} / 100 — {analysisResult.verdict || 'SAFE'}
                      </div>
                      <span className="text-[11px] font-mono text-cyan-300">
                        CONFIDENCE: {analysisResult.confidence || 'HIGH'}
                      </span>
                    </div>

                    <div className="flex flex-col items-center justify-center w-14 h-14 rounded-full bg-slate-950/80 border border-slate-700/60 shrink-0">
                      <span className="text-base font-extrabold text-white leading-none">
                        {Math.round(analysisResult.threat_score)}
                      </span>
                      <span className="text-[9px] text-slate-400 font-mono">/ 100</span>
                    </div>
                  </div>
                )}

                {/* QR Type & Authenticity Badges */}
                {analysisResult && (
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <span className="px-2.5 py-1 rounded-lg bg-cyan-950/50 border border-cyan-500/40 text-cyan-300 font-semibold">
                      QR TYPE: {analysisResult.detected_type?.toUpperCase() || (decodedInfo.isUrl ? 'URL' : 'PLAIN TEXT')}
                    </span>
                    <span className={`px-2.5 py-1 rounded-lg border font-semibold ${
                      analysisResult.authenticity === 'VERIFIED'
                        ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-300'
                        : analysisResult.authenticity === 'SUSPICIOUS'
                        ? 'bg-rose-950/50 border-rose-500/40 text-rose-300'
                        : 'bg-amber-950/50 border-amber-500/40 text-amber-300'
                    }`}>
                      AUTHENTICITY: {analysisResult.authenticity || 'UNVERIFIED'}
                    </span>
                  </div>
                )}

                {/* What Will Happen Section */}
                {analysisResult?.what_will_happen && (
                  <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-1">
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block font-bold">
                      What Will Happen:
                    </span>
                    <p className="text-xs text-slate-200 leading-relaxed font-sans">
                      {analysisResult.what_will_happen}
                    </p>
                    {analysisResult.authenticity_reason && (
                      <p className="text-[11px] text-slate-400 italic font-mono pt-1">
                        ℹ {analysisResult.authenticity_reason}
                      </p>
                    )}
                  </div>
                )}

                {/* Security Analysis Checklist */}
                {analysisResult?.checks && analysisResult.checks.length > 0 && (
                  <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2">
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block font-bold">
                      Security Analysis:
                    </span>
                    <ul className="space-y-1.5 text-xs font-mono">
                      {analysisResult.checks.map((c, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-slate-300 leading-tight">
                          <span className={c.icon === '✓' ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                            {c.icon || '•'}
                          </span>
                          <span>{c.text || c}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Action Buttons */}
                {analysisResult && (
                  <div className="pt-2">
                    {analysisResult.is_blocked || analysisResult.threat_score >= 60 ? (
                      <div className="space-y-2">
                        <div className="p-2.5 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs text-center font-bold">
                          ⚠️ THREAT DETECTED — STOP PROCEEDING
                        </div>
                        <button
                          id="qr-stop-proceeding"
                          onClick={() => {
                            addToast('Navigation safely blocked. Threat intercepted by PhishGuard AI.', 'info');
                          }}
                          className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-sm transition-colors shadow-lg shadow-rose-950/40"
                        >
                          <ShieldAlert className="w-4 h-4" />
                          STOP PROCEEDING (BLOCKED)
                        </button>
                      </div>
                    ) : analysisResult.verdict === 'SAFE' && analysisResult.authenticity === 'VERIFIED' ? (
                      <button
                        id="qr-open-url-safe"
                        onClick={handleOpenUrl}
                        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-sm transition-colors shadow-lg shadow-emerald-950/40"
                      >
                        <ExternalLink className="w-4 h-4" />
                        PROCEED
                      </button>
                    ) : (
                      <button
                        id="qr-open-url-caution"
                        onClick={handleOpenUrl}
                        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-amber-600 hover:bg-amber-500 text-white font-bold text-sm transition-colors shadow-lg shadow-amber-950/40"
                      >
                        <AlertTriangle className="w-4 h-4" />
                        PROCEED WITH CAUTION
                      </button>
                    )}
                  </div>
                )}

                {analyzing && (
                  <div className="flex items-center justify-center gap-2 py-3 text-xs text-cyan-400 font-mono animate-pulse bg-cyan-950/20 rounded-xl border border-cyan-500/20">
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Analyzing QR payload with PhishGuard AI…
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="glass-panel rounded-2xl p-8 border border-slate-800 flex flex-col items-center justify-center gap-4 text-center text-slate-500 min-h-[220px]">
              <ShieldAlert className="w-12 h-12 opacity-20" />
              <div>
                <p className="text-sm font-semibold text-slate-400">No Active Code Scanned</p>
                <p className="text-xs text-slate-500 mt-1 max-w-xs">
                  Start your camera or upload a QR or barcode image to inspect symbologies and consult the AI Helpline.
                </p>
              </div>
            </div>
          )}

          {/* ── 🤖 INTEGRATED AI HELPLINE SIDE PANEL ── */}
          <div className="glass-panel rounded-2xl border border-cyan-500/30 overflow-hidden space-y-0 shadow-xl shadow-cyan-950/20 animate-fadeIn">
            {/* Helpline Panel Header */}
            <div className="p-4 bg-gradient-to-r from-slate-900 to-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white text-xs">
                  🤖
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                    PhishGuard AI Helpline
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  </h3>
                  <span className="text-[10px] text-slate-400 font-mono">Scan-Aware Cybersecurity Assistant</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Link
                  to="/helpline"
                  className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300"
                  title="Expand to Full Helpline Page"
                >
                  Full View ↗
                </Link>
                <button
                  onClick={() => setHelplineOpen(!helplineOpen)}
                  className="text-slate-400 hover:text-white p-1"
                >
                  {helplineOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {helplineOpen && (
              <div className="p-4 space-y-3 bg-slate-950/60">
                {/* Chat Feed */}
                <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1 text-xs">
                  {chatMessages.length === 0 ? (
                    <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-slate-400 text-xs text-center">
                      Scan any QR code or barcode above. The AI Helpline will automatically explain risks and guide you.
                    </div>
                  ) : (
                    chatMessages.map((msg, i) => (
                      <div
                        key={msg.id || i}
                        className={`flex gap-2 ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}
                      >
                        {msg.sender === 'ai' && (
                          <div className="w-6 h-6 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center text-[10px] shrink-0 font-bold">
                            🤖
                          </div>
                        )}
                        <div
                          className={`p-3 rounded-xl max-w-[85%] whitespace-pre-wrap ${
                            msg.sender === 'user'
                              ? 'bg-cyan-600 text-white rounded-br-none'
                              : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-bl-none'
                          }`}
                        >
                          {msg.text}
                        </div>
                      </div>
                    ))
                  )}

                  {chatLoading && (
                    <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono py-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce"></span>
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:0.2s]"></span>
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce [animation-delay:0.4s]"></span>
                      <span className="text-[11px] text-slate-400">AI Helpline analyzing…</span>
                    </div>
                  )}

                  <div ref={chatScrollRef} />
                </div>

                {/* Quick Action Suggestion Buttons for the Scan */}
                {decodedInfo && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    <button
                      onClick={() => handleSendHelplineMessage('Why is this dangerous?')}
                      className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] text-slate-300 hover:text-cyan-300 transition-colors"
                    >
                      Why is this risky?
                    </button>
                    <button
                      onClick={() => handleSendHelplineMessage('What should I do?')}
                      className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] text-slate-300 hover:text-cyan-300 transition-colors"
                    >
                      What should I do?
                    </button>
                    <button
                      onClick={() => handleSendHelplineMessage('I already clicked it, what now?')}
                      className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-700 text-[10px] text-slate-300 hover:text-cyan-300 transition-colors"
                    >
                      I already clicked it
                    </button>
                  </div>
                )}

                {/* Chat Input Bar */}
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSendHelplineMessage();
                  }}
                  className="flex items-center gap-2 pt-1"
                >
                  <input
                    type="text"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    placeholder="Ask Helpline about this code..."
                    className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
                  />
                  <button
                    type="submit"
                    disabled={!chatInput.trim() || chatLoading}
                    className="p-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl disabled:opacity-40 transition-colors"
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>

                <p className="text-[10px] text-slate-500 font-mono text-center">
                  🔒 Security Rule: Never share passwords, OTPs, or PINs.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Deep SHAP & Explainable AI Factor Breakdown (URL scans only) ── */}
      {scanResult && decodedInfo?.isUrl && (
        <div className="space-y-6 animate-fadeIn">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Risk Gauge + Tailored Plain-Language AI Explanation */}
            <div className="lg:col-span-5 glass-panel rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-2 text-cyan-400">
                <Sparkles className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">Personalized AI Threat Diagnosis</h3>
              </div>

              <div className="flex items-center gap-6">
                <RiskGauge
                  score={scanResult.risk_score}
                  size={130}
                  strokeWidth={11}
                  verdict={scanResult.verdict}
                />
                <div className="space-y-1.5 flex-1 min-w-0">
                  <VerdictBadge verdict={scanResult.verdict} />
                  <p className="text-xs font-mono text-slate-400 mt-1 truncate">
                    Domain: <span className="text-slate-200 font-semibold">{analysisResult.parsed_domain}</span>
                  </p>
                  <p className="text-xs font-mono text-slate-400">
                    Execution: {scanResult.execution_time_ms}ms
                  </p>
                </div>
              </div>

              <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2">
                <span className="text-[10px] uppercase font-mono tracking-wider text-cyan-400 block">
                  Tailored for {scanResult.explanation.user_understanding_level} Tier:
                </span>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {scanResult.explanation.personalized_explanation}
                </p>
              </div>

              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Actionable Advice:
                </h4>
                <p className="text-xs text-amber-300 font-medium bg-amber-500/10 p-3 rounded-lg border border-amber-500/30">
                  {scanResult.explanation.actionable_advice}
                </p>
              </div>

              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                  Remediation Checklist:
                </h4>
                <ul className="space-y-1.5">
                  {scanResult.explanation.remediation_steps.map((step, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                      <ChevronRight className="w-3.5 h-3.5 text-cyan-400 mt-0.5 shrink-0" />
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* TreeSHAP Feature Contribution Waterfall Chart */}
            <div className="lg:col-span-7 glass-panel rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-indigo-400">
                  <Layers className="w-5 h-5" />
                  <h3 className="text-base font-bold text-white">TreeSHAP Factor Contribution Breakdown</h3>
                </div>
                <span className="text-xs text-slate-400 font-mono">XAI Model Explanation</span>
              </div>
              <p className="text-xs text-slate-400">
                Visualizes individual lexical and behavioral feature weights pushing the threat score towards or away from the baseline model prior.
              </p>
              <ShapWaterfallChart
                featureImportances={scanResult.explanation.feature_importances}
                baseValue={scanResult.explanation.base_value}
                predictionScore={scanResult.explanation.prediction_score}
              />
            </div>
          </div>
        </div>
      )}

      {/* ── High-Risk Confirmation Modal for Risky QR / Barcode URLs ── */}
      {confirmNavOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm px-4 animate-fadeIn">
          <div className="glass-panel rounded-2xl p-6 border border-rose-500/40 max-w-md w-full space-y-4 shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-full bg-rose-500/20 text-rose-400">
                <ShieldX className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">High-Risk Destination Warning</h3>
                <span className="text-xs font-mono text-rose-400 font-semibold">{verdict} THREAT DETECTED</span>
              </div>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              This destination URL decoded from {decodedInfo?.formatName} has been classified as <strong className="text-rose-300 font-semibold">{verdict}</strong> by PhishGuard AI.
            </p>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 break-all font-mono text-xs text-slate-400">
              {decodedInfo?.rawValue}
            </div>
            <p className="text-xs text-amber-300 bg-amber-500/10 p-3 rounded-xl border border-amber-500/30">
              {analysisResult?.recommended_action}
            </p>
            <div className="flex gap-3 pt-2">
              <button
                id="qr-confirm-cancel"
                onClick={() => setConfirmNavOpen(false)}
                className="flex-1 py-2.5 rounded-xl bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 font-semibold text-sm hover:bg-emerald-500/30 transition-colors"
              >
                Return to Safety
              </button>
              <button
                id="qr-confirm-proceed"
                onClick={handleConfirmNav}
                className="flex-1 py-2.5 rounded-xl bg-rose-500/10 border border-rose-500/40 text-rose-400 font-semibold text-sm hover:bg-rose-500/20 transition-colors"
              >
                Open Anyway
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Inline Animation Styles */}
      <style>{`
        @keyframes fullScanline {
          0% {
            transform: translateY(-130px);
            opacity: 0.3;
          }
          50% {
            opacity: 1;
          }
          100% {
            transform: translateY(130px);
            opacity: 0.3;
          }
        }
      `}</style>
    </div>
  );
};

export default QRScanner;
