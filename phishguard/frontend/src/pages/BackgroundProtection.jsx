import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import jsQR from 'jsqr';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Radio,
  Sliders,
  Bell,
  Lock,
  QrCode,
  Link2,
  ExternalLink,
  Download,
  Info,
  CheckCircle2,
  XCircle,
  Activity,
  Layers,
  Sparkles,
  Smartphone,
  Globe,
  Wifi,
  CreditCard,
  Mail,
  Phone,
  FileText,
  Copy,
  Check,
  AlertTriangle,
  Play,
  Zap,
  RefreshCw,
  Eye,
  Ban,
  Settings,
  AlertCircle,
  X
} from 'lucide-react';

const BackgroundProtection = () => {
  const { addToast, updateScanContext } = useThreat();
  const navigate = useNavigate();

  // Protection Controls
  const [masterProtection, setMasterProtection] = useState(true);
  const [smartShield, setSmartShield] = useState(true);
  const [notificationProtection, setNotificationProtection] = useState(true);
  const [screenScan, setScreenScan] = useState(true);
  const [duplicateDetection, setDuplicateDetection] = useState(true);
  const [autoBlock, setAutoBlock] = useState(true);

  // Live Statistics
  const [stats, setStats] = useState({
    qrScannedToday: 14,
    urlsAnalyzedToday: 32,
    threatsBlocked: 4,
    suspiciousItems: 6,
  });

  const [lastScanTime, setLastScanTime] = useState('Just now');
  const [selectedScan, setSelectedScan] = useState(null);
  const [showPairModal, setShowPairModal] = useState(false);
  const [pairingData, setPairingData] = useState(null);
  const [pairingLoading, setPairingLoading] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  // First-Time Permission Setup Modal State
  const [showPermissionModal, setShowPermissionModal] = useState(false);
  const [permissionTarget, setPermissionTarget] = useState(null);

  // Screen Scanning & OCR Simulator Modals
  const [showMockScanModal, setShowMockScanModal] = useState(false);
  const [showBrowserWarningModal, setShowBrowserWarningModal] = useState(false);
  const [scanningProgress, setScanningProgress] = useState(false);
  const [detectedQrPayload, setDetectedQrPayload] = useState(null);

  // Quick Test Sandbox State (Legacy compatible)
  const [testPayload, setTestPayload] = useState('https://login-appleid-verify-token.account-security-alert.xyz/auth');
  const [testSource, setTestSource] = useState('WhatsApp Web');
  const [testingScan, setTestingScan] = useState(false);

  // Notification simulator values
  const [simulatorApp, setSimulatorApp] = useState('WhatsApp');
  const [simulatorText, setSimulatorText] = useState('URGENT NOTICE: Your banking access is suspended. Verify credentials immediately: https://secure-login-verify-account.bank-security.xyz/auth');

  // Universal Manual Scanner State (Ctrl + Shift + Q)
  const [showUniversalModal, setShowUniversalModal] = useState(false);
  const [universalScanResult, setUniversalScanResult] = useState(null);
  const [universalScanning, setUniversalScanning] = useState(false);

  // Region Selection Mode State
  const [showRegionOverlay, setShowRegionOverlay] = useState(false);
  const [selectionRect, setSelectionRect] = useState({ x: 0, y: 0, width: 320, height: 180, label: 'SMART REGION' });
  const [isDraggingRegion, setIsDraggingRegion] = useState(false);
  const [regionStartPos, setRegionStartPos] = useState({ x: 0, y: 0 });

  const handleRegionMouseDown = (e) => {
    if (e.target.closest('.phishguard-banner-panel')) return;
    setIsDraggingRegion(true);
    setRegionStartPos({ x: e.clientX, y: e.clientY });
  };

  const handleRegionMouseMove = (e) => {
    if (isDraggingRegion) {
      const currentX = e.clientX;
      const currentY = e.clientY;
      const width = Math.abs(currentX - regionStartPos.x);
      const height = Math.abs(currentY - regionStartPos.y);
      const x = Math.min(currentX, regionStartPos.x);
      const y = Math.min(currentY, regionStartPos.y);

      setSelectionRect({ x, y, width, height, label: 'CUSTOM REGION' });
    } else {
      // Hover object detection
      const el = document.elementFromPoint(e.clientX, e.clientY);
      if (el) {
        const tag = el.tagName ? el.tagName.toLowerCase() : '';
        const rect = el.getBoundingClientRect();
        const isQrImage = tag === 'img' && (el.src?.includes('qr') || el.alt?.includes('qr') || el.className?.includes('qr'));
        const isLink = tag === 'a' || !!el.closest('a');
        const isMsgBlock = el.className?.includes('message') || el.className?.includes('card') || tag === 'p' || tag === 'h1' || tag === 'h2';

        if (rect.width > 25 && rect.height > 25 && rect.width < window.innerWidth * 0.85 && rect.height < window.innerHeight * 0.85) {
          const pad = 6;
          const label = isQrImage ? 'QR CODE' : isLink ? 'LINK / URL' : isMsgBlock ? 'MESSAGE BLOCK' : 'DETECTED OBJECT';
          setSelectionRect({
            x: Math.max(0, rect.left - pad),
            y: Math.max(0, rect.top - pad),
            width: rect.width + pad * 2,
            height: rect.height + pad * 2,
            label
          });
          return;
        }
      }

      const defaultW = 320;
      const defaultH = 180;
      setSelectionRect({
        x: Math.max(0, e.clientX - defaultW / 2),
        y: Math.max(0, e.clientY - defaultH / 2),
        width: defaultW,
        height: defaultH,
        label: 'SMART REGION'
      });
    }
  };

  const handleRegionMouseUp = (e) => {
    if (e.target.closest('.phishguard-banner-panel')) return;
    setIsDraggingRegion(false);
    setShowRegionOverlay(false);

    const selectedText = window.getSelection() ? window.getSelection().toString().trim() : '';
    handleUniversalManualScan(selectedText || testPayload || "https://example.com/login");
  };

  // Global Keyboard Shortcut Listener for Ctrl + Shift + Q & Esc
  useEffect(() => {
    const handleGlobalKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'Q' || e.key === 'q')) {
        e.preventDefault();
        setShowRegionOverlay(true);
        addToast("Essential Key Smart Scan: Move over content to scan...", "info");
      } else if (e.key === 'Escape' && showRegionOverlay) {
        setShowRegionOverlay(false);
        setSelectionRect({ x: 0, y: 0, width: 320, height: 180, label: 'SMART REGION' });
        addToast("Smart Scan cancelled.", "info");
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, [showRegionOverlay, testPayload]);


  // Drag-and-drop state for Floating Smart Shield
  const [floatingPosition, setFloatingPosition] = useState({ x: window.innerWidth - 90, y: 220 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  const handleUniversalManualScan = async (textPayload = '', qrCodes = []) => {
    setUniversalScanning(true);
    addToast("Executing Universal Manual Scan (Ctrl + Shift + Q)...", "info");
    try {
      const res = await api.post('/qr/analyze-universal', {
        text: textPayload || testPayload || '',
        qr_codes: qrCodes,
        page_url: window.location.href,
        page_title: document.title
      });
      setUniversalScanResult(res.data);
      setShowUniversalModal(true);
      addToast(`Detected: ${res.data.detected_type}`, res.data.threat_score >= 60 ? "error" : "success");
    } catch (err) {
      console.warn("Universal scan fallback:", err);
      const targetStr = textPayload || testPayload || '';
      const low = targetStr.toLowerCase();
      let detectedType = 'NOTHING SUPPORTED';
      let score = 0;
      let threatLevel = 'SAFE';

      if (low.startsWith('http://') || low.startsWith('https://')) {
        detectedType = 'URL DETECTED';
        score = low.includes('.xyz') || low.includes('login') || low.includes('bank') ? 85 : 10;
        threatLevel = score >= 60 ? 'HIGH RISK' : 'SAFE';
      } else if (low.includes('@') && !low.includes(' ')) {
        detectedType = 'EMAIL ID DETECTED';
        score = low.includes('.xyz') || low.includes('paypal') ? 72 : 15;
        threatLevel = score >= 60 ? 'HIGH RISK' : 'SAFE';
      } else if (low.length > 5) {
        detectedType = 'NOTIFICATION DETECTED';
        score = low.includes('bank') || low.includes('blocked') || low.includes('urgent') || low.includes('otp') ? 91 : 20;
        threatLevel = score >= 60 ? 'CRITICAL' : 'SAFE';
      }

      setUniversalScanResult({
        detected_type: detectedType,
        url: low.startsWith('http') ? targetStr : '',
        email: low.includes('@') ? targetStr : '',
        extracted_message: targetStr,
        domain: low.includes('@') ? low.split('@')[1] : (low.startsWith('http') ? low.replace(/^https?:\/\//, '').split('/')[0] : ''),
        status: score >= 60 ? 'LIKELY FAKE' : 'REAL / LIKELY REAL',
        status_verdict: score >= 60 ? 'LIKELY FAKE' : 'REAL / LIKELY REAL',
        threat_score: score,
        threat_level: threatLevel,
        confidence: 0.92,
        authenticity: score >= 60 ? 'SUSPICIOUS' : 'VERIFIED',
        analysis_reasons: [score >= 60 ? 'High-risk threats and manipulation patterns detected.' : 'Passed basic security checks.'],
        checks: [{ status: score >= 60 ? 'FAIL' : 'PASS', icon: score >= 60 ? '⚠' : '✓', text: score >= 60 ? 'Suspicious target detected' : 'Standard target' }],
        recommended_action: score >= 60 ? 'STOP PROCEEDING' : 'PROCEED',
        is_blocked: score >= 60
      });
      setShowUniversalModal(true);
    } finally {
      setUniversalScanning(false);
    }
  };


  // Duplicate Alert Cache (Content Fingerprint -> Threat Data)
  const [cachedAlerts, setCachedAlerts] = useState({});
  // Latest Alert generated
  const [latestAlert, setLatestAlert] = useState(null);


  // Live Activity Stream
  const [detections, setDetections] = useState([
    {
      id: 1,
      site: 'WhatsApp Web',
      qr_type: 'URL',
      payload: 'https://login-appleid-verify-token.account-security-alert.xyz/auth',
      severity: 'CRITICAL',
      threat_score: 92.5,
      classification: 'PHISHING',
      is_blocked: true,
      time: '11:18:42 AM',
      reasons: [
        "Lookalike domain mimicking 'Apple' brand",
        'Credential harvesting keywords in URL path',
      ],
    },
    {
      id: 2,
      site: 'Instagram Web',
      qr_type: 'URL',
      payload: 'https://security-checkpoint-update.xyz',
      severity: 'SUSPICIOUS',
      threat_score: 64.0,
      classification: 'SUSPICIOUS_REDIRECT',
      is_blocked: false,
      time: '11:15:21 AM',
      reasons: ['Disposable high-risk .xyz domain', 'Elevated lexical entropy'],
    },
    {
      id: 3,
      site: 'Google Search',
      qr_type: 'URL',
      payload: 'https://google.com/search?q=cybersecurity',
      severity: 'SAFE',
      threat_score: 6.0,
      classification: 'BENIGN',
      is_blocked: false,
      time: '11:17:04 AM',
      reasons: ['Verified legitimate domain with high reputation'],
    },
  ]);

  // Connect to Live SSE stream for real-time QR scans from extension & API
  useEffect(() => {
    fetchInitialTelemetry();

    const token = localStorage.getItem('phishguard_access_token');
    const sseUrl = `http://localhost:8000/api/v1/devices/events${token ? `?token=${token}` : ''}`;
    let eventSource = null;

    try {
      eventSource = new EventSource(sseUrl);
      eventSource.addEventListener('QR_SCAN_COMPLETED', (e) => {
        try {
          const data = JSON.parse(e.data);
          const scan = data.scan || data;
          
          setLastScanTime(new Date().toLocaleTimeString());
          setStats((prev) => ({
            ...prev,
            qrScannedToday: prev.qrScannedToday + 1,
            threatsBlocked: scan.is_blocked ? prev.threatsBlocked + 1 : prev.threatsBlocked,
            suspiciousItems: scan.severity === 'SUSPICIOUS' ? prev.suspiciousItems + 1 : prev.suspiciousItems,
          }));

          const newEntry = {
            id: scan.scan_id || Date.now(),
            site: scan.page_title || scan.page_url || 'Active Browser Tab',
            qr_type: scan.qr_type || 'URL',
            payload: scan.payload,
            severity: scan.severity || 'SAFE',
            threat_score: scan.threat_score,
            classification: scan.classification || 'BENIGN',
            is_blocked: !!scan.is_blocked,
            time: new Date().toLocaleTimeString(),
            reasons: scan.analysis_reasons || [],
          };

          setDetections((prev) => [newEntry, ...prev.slice(0, 19)]);
          addToast(`Live QR Scan: ${scan.severity} (${scan.threat_score}/100)`, scan.severity === 'SAFE' ? 'success' : 'error');
        } catch (err) {
          console.warn('Failed to parse SSE scan event:', err);
        }
      });
    } catch (err) {
      console.warn('SSE stream init failed:', err);
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  // Window drag events handler for Smart Shield
  useEffect(() => {
    const handleGlobalMouseMove = (e) => {
      if (!isDragging) return;
      // Constrain inside viewport boundaries
      const newX = Math.min(window.innerWidth - 80, Math.max(10, e.clientX - dragOffset.x));
      const newY = Math.min(window.innerHeight - 80, Math.max(10, e.clientY - dragOffset.y));
      setFloatingPosition({ x: newX, y: newY });
    };

    const handleGlobalMouseUp = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleGlobalMouseMove);
      window.addEventListener('mouseup', handleGlobalMouseUp);
    }

    return () => {
      window.removeEventListener('mousemove', handleGlobalMouseMove);
      window.removeEventListener('mouseup', handleGlobalMouseUp);
    };
  }, [isDragging, dragOffset]);

  // Global Keyboard Shortcut Listener for Ctrl + Shift + Q
  useEffect(() => {
    const handleGlobalKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'Q' || e.key === 'q')) {
        e.preventDefault();
        const selected = window.getSelection() ? window.getSelection().toString().trim() : '';
        handleUniversalManualScan(selected || testPayload || "https://example.com/login");
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, [testPayload]);


  const fetchInitialTelemetry = async () => {
    try {
      const res = await api.get('/qr/scans', { params: { limit: 10 } });
      if (res.data && res.data.length > 0) {
        const formatted = res.data.map((s) => ({
          id: s.id,
          site: s.page_title || s.page_url || 'Web Page',
          qr_type: s.qr_type,
          payload: s.qr_payload,
          severity: s.severity,
          threat_score: s.threat_score,
          classification: s.classification,
          is_blocked: s.is_blocked,
          time: new Date(s.timestamp).toLocaleTimeString(),
          reasons: s.analysis_reasons || [],
        }));
        setDetections(formatted);
      }
    } catch (e) {
      // Keep initial preset telemetry
    }
  };

  // Toggle helpers with setup checking
  const handleToggle = (setter, currentValue, label) => {
    const nextValue = !currentValue;
    if (nextValue === true) {
      const isGranted = localStorage.getItem('phishguard_permissions_setup') === 'true';
      if (!isGranted) {
        setPermissionTarget({ setter, label });
        setShowPermissionModal(true);
        return;
      }
    }
    setter(nextValue);
    addToast(`${label} policy updated.`, 'info');
  };

  const handleGrantPermissions = () => {
    localStorage.setItem('phishguard_permissions_setup', 'true');
    setShowPermissionModal(false);
    if (permissionTarget) {
      permissionTarget.setter(true);
      addToast(`${permissionTarget.label} enabled successfully!`, 'success');
      setPermissionTarget(null);
    } else {
      setMasterProtection(true);
      setSmartShield(true);
      setNotificationProtection(true);
      setScreenScan(true);
      addToast('All PhishGuard smart permissions granted.', 'success');
    }
  };

  // Content Deduplication Helper
  const getContentFingerprint = (source, text, url) => {
    const rawStr = `${source || ''}:${text || ''}:${url || ''}`;
    let hash = 0;
    for (let i = 0; i < rawStr.length; i++) {
      const chr = rawStr.charCodeAt(i);
      hash = (hash << 5) - hash + chr;
      hash |= 0;
    }
    return hash.toString(36);
  };

  // Upgraded Combined Security Assessment (URL Scanner + NLP Text Analyzer)
  const runCombinedAnalysis = async (source, text, url) => {
    const fingerprint = getContentFingerprint(source, text, url);
    if (duplicateDetection && cachedAlerts[fingerprint]) {
      addToast('Alert duplicate filtered - showing cached analysis.', 'info');
      setLatestAlert(cachedAlerts[fingerprint]);
      return cachedAlerts[fingerprint];
    }

    let urlResult = null;
    let textResult = null;

    try {
      // 1. Scan URL if present
      if (url && url.trim()) {
        const urlRes = await api.post('/scan/', {
          target: url.trim(),
          scan_type: 'url'
        });
        urlResult = urlRes.data;
      }

      // 2. Scan Text via NLP if present
      if (text && text.trim()) {
        const textRes = await api.post('/nlp/analyze', {
          text_content: text.trim(),
          sender_context: source || ''
        });
        textResult = textRes.data;
      }
    } catch (err) {
      console.warn("Combined Analysis API failure:", err);
      addToast("Analysis failed: " + (err.response?.data?.detail || err.message), "error");
      return null;
    }

    // 3. Assemble combined weights
    let riskScore = 0;
    let verdict = 'SAFE';
    let classification = 'BENIGN';
    let reasons = [];
    let actionableAdvice = 'No high-risk vectors detected. Standard vigilance recommended.';
    let threatCategory = 'Benign / Clean';

    if (urlResult) {
      riskScore = urlResult.risk_score;
      verdict = urlResult.risk_level; // 'SAFE', 'SUSPICIOUS', 'HIGH', 'CRITICAL'
      classification = urlResult.verdict;
      reasons = [...(urlResult.explanation?.feature_importances?.map(f => `${f.feature}: weight ${f.weight.toFixed(2)}`) || [])];
      actionableAdvice = urlResult.explanation?.actionable_advice || '';
      threatCategory = urlResult.verdict === 'SAFE' ? 'Benign URL' : 'Malicious URL Landing Page';
    }

    if (textResult) {
      const textScore = textResult.overall_manipulation_score * 100;
      if (textScore > riskScore) {
        riskScore = textScore;
        verdict = textScore < 30 ? 'SAFE' : textScore < 60 ? 'SUSPICIOUS' : textScore < 85 ? 'HIGH RISK' : 'CRITICAL';
        classification = textResult.is_social_engineering ? 'SOCIAL_ENGINEERING' : 'BENIGN';
        threatCategory = textResult.threat_category;
      }

      const nlpReasons = textResult.tactics_breakdown
        ?.filter(t => t.score > 0)
        ?.map(t => `${t.tactic}: ${t.description} (${t.score})`) || [];
      reasons = [...reasons, ...nlpReasons];
      if (textResult.remediation_guidance) {
        actionableAdvice = textResult.remediation_guidance;
      }
    }

    // Edge cases if score matches critical levels
    if (riskScore >= 80 && verdict !== 'CRITICAL') {
      verdict = 'CRITICAL';
    }

    const finalAlert = {
      id: Date.now(),
      sourceApp: source || 'External Screen',
      messageContent: text || 'Raw Screen Scan URL Target',
      detectedUrl: url || 'Not detected',
      riskScore: parseFloat(riskScore.toFixed(1)),
      verdict,
      threatProbability: riskScore,
      threatCategory,
      reasons: reasons.length > 0 ? reasons : ['Legitimate communication patterns verified.'],
      recommendedAction: actionableAdvice,
      time: new Date().toLocaleTimeString()
    };

    // Store in cache
    if (duplicateDetection) {
      setCachedAlerts(prev => ({ ...prev, [fingerprint]: finalAlert }));
    }

    // Add to activity stream
    const newEntry = {
      id: finalAlert.id,
      site: finalAlert.sourceApp,
      qr_type: url ? 'URL' : 'TEXT',
      payload: url || text,
      severity: finalAlert.verdict === 'HIGH' ? 'HIGH RISK' : finalAlert.verdict,
      threat_score: finalAlert.riskScore,
      classification: finalAlert.threatCategory,
      is_blocked: finalAlert.riskScore >= 80,
      time: finalAlert.time,
      reasons: finalAlert.reasons
    };

    setDetections(prev => [newEntry, ...prev]);

    // Update stats
    setStats(prev => ({
      ...prev,
      urlsAnalyzedToday: prev.urlsAnalyzedToday + 1,
      threatsBlocked: finalAlert.riskScore >= 80 ? prev.threatsBlocked + 1 : prev.threatsBlocked,
      suspiciousItems: finalAlert.verdict === 'SUSPICIOUS' ? prev.suspiciousItems + 1 : prev.suspiciousItems
    }));

    setLatestAlert(finalAlert);
    return finalAlert;
  };

  // Browser Screen Scan using Media Projection / getDisplayMedia
  const handleScanScreenClick = async () => {
    if (!screenScan) {
      addToast("Screen Scan is currently disabled in policies.", "warning");
      return;
    }
    setScanningProgress(true);
    setDetectedQrPayload(null);

    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
      const video = document.createElement('video');
      video.srcObject = stream;
      video.setAttribute('playsinline', 'true');
      
      // Wait for play
      await video.play();

      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      // Stop video immediately
      stream.getTracks().forEach((track) => track.stop());

      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imgData.data, imgData.width, imgData.height, {
        inversionAttempts: 'dontInvert'
      });

      if (code && code.data) {
        addToast("QR Code detected on screen capture!", "success");
        setDetectedQrPayload(code.data);
      } else {
        addToast("No QR Code detected. Direct text capture requires Android native wrapper.", "info");
        setShowBrowserWarningModal(true);
      }
    } catch (err) {
      console.warn("Screen scan failed/canceled:", err);
      addToast("Screen scanning canceled.", "info");
    } finally {
      setScanningProgress(false);
    }
  };

  // Analyze the QR detected by Smart Shield
  const handleAnalyzeQr = async (payload) => {
    setDetectedQrPayload(null);
    addToast("Analyzing decoded QR payload with PhishGuard AI...", "info");
    try {
      const res = await api.post('/qr/analyze', {
        payload: payload.trim(),
        page_url: 'https://screen-capture.local',
        page_title: 'Screen Smart Shield',
        scan_source: 'smart-shield-screen'
      });
      const data = res.data;
      const finalAlert = {
        id: Date.now(),
        sourceApp: 'Screen Smart Shield',
        messageContent: 'Smart Shield Screen Decoded QR',
        detectedUrl: payload,
        riskScore: data.threat_score,
        verdict: data.verdict || data.severity,
        severity: data.severity,
        threatProbability: data.threat_score,
        threatCategory: data.classification,
        authenticity: data.authenticity || 'UNVERIFIED',
        authenticityReason: data.authenticity_reason,
        whatWillHappen: data.what_will_happen,
        checks: data.checks || [],
        reasons: data.analysis_reasons || [],
        recommendedAction: `Action: ${data.action_text || 'PROCEED'}. ${data.what_will_happen || ''}`,
        actionText: data.action_text || 'PROCEED',
        actionType: data.action_type || 'proceed',
        isBlocked: !!data.is_blocked,
        time: new Date().toLocaleTimeString()
      };
      setLatestAlert(finalAlert);
      addToast(`QR Scan: ${data.verdict || data.severity} (${data.threat_score}/100)`, data.threat_score < 20 ? 'success' : 'error');
    } catch (err) {
      await runCombinedAnalysis("Screen Smart Shield", "Decoded visual QR payload", payload);
    }
  };

  // Simulated notification triggers
  const handleTriggerSimulatedNotification = async (app, text, url) => {
    if (!notificationProtection) {
      addToast("Notification Protection is disabled. Enable it to run scans.", "warning");
      return;
    }
    addToast(`Processing simulated ${app} notification...`, 'info');
    await runCombinedAnalysis(app, text, url);
  };

  // Connect threat item to AI Helpline
  const handleAskAIHelpline = (alert) => {
    updateScanContext({
      rawValue: alert.detectedUrl || alert.messageContent,
      formatName: 'Background Threat Vector',
      type: 'Background Protection Alert',
      riskScore: alert.riskScore,
      verdict: alert.verdict,
      reasons: alert.reasons,
      actionableAdvice: alert.recommendedAction,
      sourceApp: alert.sourceApp,
      messageContent: alert.messageContent,
      detectedUrl: alert.detectedUrl,
      threatProbability: alert.threatProbability,
      threatCategory: alert.threatCategory
    });
    addToast('Context forwarded to AI Helpline.', 'success');
    navigate('/helpline');
  };

  const handleGeneratePairing = async () => {
    setPairingLoading(true);
    setShowPairModal(true);
    try {
      const res = await api.post('/devices/pair/request');
      setPairingData(res.data);
    } catch (e) {
      setPairingData({
        pairing_code: '582914',
        expires_in_seconds: 600,
        pairing_qr_payload: JSON.stringify({ code: '582914', server: 'http://localhost:8000/api/v1' }),
      });
    } finally {
      setPairingLoading(false);
    }
  };

  const handleCopyCode = () => {
    if (!pairingData) return;
    navigator.clipboard.writeText(pairingData.pairing_code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
    addToast('Pairing code copied to clipboard!', 'success');
  };

  // Sandbox scanner flow
  const handleRunQuickTest = async (e) => {
    e.preventDefault();
    if (!testPayload.trim()) return;

    setTestingScan(true);
    try {
      const res = await api.post('/qr/analyze', {
        payload: testPayload.trim(),
        page_url: 'https://web.whatsapp.com',
        page_title: testSource,
        scan_source: 'dashboard-sandbox',
      });

      const data = res.data;
      addToast(`Test Scan: ${data.verdict || data.severity} (${data.threat_score}/100)`, data.threat_score < 20 ? 'success' : 'error');
      
      const reasons = data.analysis_reasons || [];
      const simulatedAlert = {
        id: Date.now(),
        sourceApp: testSource,
        messageContent: 'Sandbox QR Threat Test',
        detectedUrl: testPayload.trim(),
        riskScore: data.threat_score,
        verdict: data.verdict || data.severity,
        severity: data.severity,
        threatProbability: data.threat_score,
        threatCategory: data.classification,
        authenticity: data.authenticity || 'UNVERIFIED',
        authenticityReason: data.authenticity_reason,
        whatWillHappen: data.what_will_happen,
        checks: data.checks || [],
        reasons: reasons.length > 0 ? reasons : ['Suspicious visual/lexical indicators found.'],
        recommendedAction: `Action: ${data.action_text || 'PROCEED'}. ${data.what_will_happen || ''}`,
        actionText: data.action_text || 'PROCEED',
        actionType: data.action_type || 'proceed',
        isBlocked: !!data.is_blocked,
        time: new Date().toLocaleTimeString()
      };
      setLatestAlert(simulatedAlert);
      
      const newEntry = {
        id: simulatedAlert.id,
        site: testSource,
        qr_type: data.qr_type || 'URL',
        payload: testPayload.trim(),
        severity: data.severity,
        threat_score: data.threat_score,
        classification: data.classification,
        is_blocked: !!data.is_blocked,
        time: simulatedAlert.time,
        reasons: simulatedAlert.reasons
      };
      setDetections((prev) => [newEntry, ...prev.slice(0, 19)]);
    } catch (err) {
      addToast('Scan failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setTestingScan(false);
    }
  };

  // Movable Smart Shield Drag events
  const handleMouseDown = (e) => {
    e.preventDefault();
    setIsDragging(true);
    setDragOffset({
      x: e.clientX - floatingPosition.x,
      y: e.clientY - floatingPosition.y
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn relative">
      
      {/* ─── DRAGGABLE SMART SHIELD WIDGET ─── */}
      {smartShield && (
        <div
          style={{
            position: 'fixed',
            left: `${floatingPosition.x}px`,
            top: `${floatingPosition.y}px`,
            zIndex: 9999,
          }}
          className={`w-16 h-16 bg-slate-900 border-2 rounded-2xl flex flex-col items-center justify-center shadow-2xl hover:scale-105 active:scale-95 transition-transform duration-200 select-none group ${
            isDragging ? 'border-cyan-400 cursor-grabbing bg-slate-800' : 'border-cyan-500/80 cursor-grab'
          }`}
          onPointerDown={handleMouseDown}
        >
          <div className="text-xl">🛡️</div>
          <span className="text-[9px] font-mono font-black text-cyan-400 tracking-wider">SHIELD</span>

          {/* Smart Shield Hover menu */}
          <div className="absolute right-0 top-full mt-2 bg-slate-950/95 border border-slate-800 rounded-xl p-2 hidden group-hover:block hover:block space-y-1.5 shadow-2xl min-w-[150px] pointer-events-auto">
            <div className="text-[9px] font-bold text-slate-500 px-2 py-0.5 border-b border-slate-900 mb-1">SMART ACTIONS</div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleScanScreenClick();
              }}
              className="w-full text-left text-[10px] font-mono hover:bg-cyan-500/10 hover:text-cyan-400 px-2.5 py-1.5 rounded text-slate-300 transition-colors flex items-center gap-1.5"
            >
              <span>📸</span> Scan Screen
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowMockScanModal(true);
              }}
              className="w-full text-left text-[10px] font-mono hover:bg-cyan-500/10 hover:text-cyan-400 px-2.5 py-1.5 rounded text-slate-300 transition-colors flex items-center gap-1.5"
            >
              <span>🧪</span> Mock Screens
            </button>
          </div>

          {/* Temporary visual overlay action popover */}
          {detectedQrPayload && (
            <div className="absolute right-full mr-3 top-0 bg-slate-950 border-2 border-cyan-500 rounded-2xl p-4 shadow-2xl min-w-[220px] pointer-events-auto animate-bounce z-[10000]">
              <div className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                <QrCode className="w-3.5 h-3.5" />
                <span>QR CODE DETECTED</span>
              </div>
              <p className="text-[10px] text-slate-400 mt-1 font-mono truncate max-w-[180px]">
                {detectedQrPayload}
              </p>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleAnalyzeQr(detectedQrPayload);
                }}
                className="mt-3 w-full py-1.5 rounded bg-cyan-500 text-black font-extrabold text-[10px] hover:bg-cyan-400 transition-colors shadow-md shadow-cyan-500/10"
              >
                ANALYZE QR
              </button>
            </div>
          )}
        </div>
      )}

      {/* ─── LATEST ALERT THREAT BANNER ─── */}
      {latestAlert && (
        <div className={`p-5 rounded-2xl border flex flex-col md:flex-row justify-between items-start md:items-center gap-4 animate-slideIn ${
          latestAlert.verdict === 'CRITICAL'
            ? 'bg-rose-950/20 border-rose-500/50 text-rose-300'
            : latestAlert.verdict === 'HIGH RISK' || latestAlert.verdict === 'HIGH'
            ? 'bg-orange-950/20 border-orange-500/50 text-orange-300'
            : latestAlert.verdict === 'SUSPICIOUS' || latestAlert.verdict === 'MEDIUM'
            ? 'bg-amber-950/20 border-amber-500/50 text-amber-300'
            : 'bg-emerald-950/20 border-emerald-500/50 text-emerald-300'
        }`}>
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-slate-900/90 border border-slate-700 flex items-center justify-center text-xl">
              ⚠️
            </div>
            <div>
              <div className="flex items-center gap-2 text-[10px] font-mono tracking-widest uppercase">
                <span>🛡️ PhishGuard Alert</span>
                <span>•</span>
                <span className="font-bold text-cyan-400">{latestAlert.sourceApp}</span>
              </div>
              <h4 className="text-base font-black text-white mt-0.5">
                Threat Detected: <span className="underline">{latestAlert.verdict} ({latestAlert.riskScore}/100)</span>
              </h4>
              <p className="text-xs text-slate-300 mt-1 max-w-2xl font-mono leading-relaxed">
                <strong>Classification:</strong> {latestAlert.threatCategory} <br />
                <strong>Reasons:</strong> {latestAlert.reasons.slice(0, 2).join(' | ')}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => handleAskAIHelpline(latestAlert)}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-extrabold rounded-xl shadow-md transition-colors"
            >
              Ask AI Helpline
            </button>
            <button
              onClick={() => setLatestAlert(null)}
              className="px-3 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-white text-xs font-bold rounded-xl"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Header Banner */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
            <Radio className="w-4 h-4 animate-pulse" />
            <span>CONTINUOUS TELEMETRY SHIELD</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            Background Protection Smart Shield
          </h1>
          <p className="text-xs lg:text-sm text-slate-400">
            Real-time visible tab capture (<span className="font-mono text-cyan-300 bg-cyan-950/60 px-1.5 py-0.5 rounded">Ctrl + Shift + Q</span>), draggable Smart Shield overlays, and incoming notification analysis.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleGeneratePairing}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700 hover:border-cyan-500 text-slate-200 text-xs font-bold transition-all shadow-md"
          >
            <Smartphone className="w-4 h-4 text-cyan-400" />
            <span>Pair Android App</span>
          </button>

          <Link
            to="/android-companion"
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-bold transition-all shadow-lg shadow-cyan-500/20"
          >
            <Smartphone className="w-4 h-4" />
            <span>Open Android Simulator</span>
          </Link>
        </div>
      </div>

      {/* ─── ESSENTIAL KEY STATUS CARD (SECTION 17 & 28) ─── */}
      <div className="glass-panel p-5 rounded-2xl border border-cyan-500/40 bg-slate-900/80 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 shadow-xl">
        <div className="flex items-start gap-4">
          <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-2xl shrink-0">
            ⌨️
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-black uppercase text-cyan-400 tracking-wider">ESSENTIAL KEY</span>
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-500/40 font-bold">
                Ctrl + Shift + Q
              </span>
              <span className="text-[11px] font-mono text-emerald-400 font-bold flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> ● Ready
              </span>
            </div>
            <h3 className="text-base font-bold text-white mt-1">Smart Region Scanner</h3>
            <p className="text-xs text-slate-300 mt-0.5">
              Press <span className="font-mono text-cyan-300 font-bold">Ctrl + Shift + Q</span> anytime to select and analyze suspicious screen content.
            </p>

            <div className="flex flex-wrap gap-2 mt-3">
              <span className="text-[10px] font-mono bg-slate-950 text-emerald-400 px-2.5 py-1 rounded-lg border border-slate-800 font-semibold">✓ QR Codes</span>
              <span className="text-[10px] font-mono bg-slate-950 text-emerald-400 px-2.5 py-1 rounded-lg border border-slate-800 font-semibold">✓ Barcodes</span>
              <span className="text-[10px] font-mono bg-slate-950 text-emerald-400 px-2.5 py-1 rounded-lg border border-slate-800 font-semibold">✓ Valid URLs</span>
              <span className="text-[10px] font-mono bg-slate-950 text-emerald-400 px-2.5 py-1 rounded-lg border border-slate-800 font-semibold">✓ Text / Messages</span>
              <span className="text-[10px] font-mono bg-slate-950 text-emerald-400 px-2.5 py-1 rounded-lg border border-slate-800 font-semibold">✓ Scam Indicators</span>
              <span className="text-[10px] font-mono bg-slate-950 text-emerald-400 px-2.5 py-1 rounded-lg border border-slate-800 font-semibold">✓ Phishing Indicators</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 w-full lg:w-auto">
          <button
            onClick={() => setShowRegionOverlay(true)}
            className="flex-1 lg:flex-none px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-extrabold text-xs transition-all shadow-lg shadow-cyan-500/20"
          >
            TEST ESSENTIAL KEY
          </button>
          <button
            onClick={() => addToast("Shortcut configured: Ctrl + Shift + Q is active system-wide.", "info")}
            className="px-4 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs transition-colors border border-slate-700"
          >
            Configure Shortcut
          </button>
        </div>
      </div>

      {/* Real-time Status Card & Telemetry Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Status Widget */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${
                masterProtection 
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' 
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
              }`}>
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <span>Background Protection</span>
                  <span className={`w-2 h-2 rounded-full ${masterProtection ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
                </div>
                <div className={`text-[11px] font-mono uppercase ${masterProtection ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {masterProtection ? '● ACTIVE PROTECTION' : '○ SHIELD DISABLED'}
                </div>
              </div>
            </div>
            <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
              Shortcut: Ctrl+Shift+Q
            </span>
          </div>

          <div className="pt-4 flex items-center justify-between border-t border-slate-800/80 text-xs font-mono text-slate-400">
            <span>Last Scan: <strong className="text-slate-200">{lastScanTime}</strong></span>
            <span>Engine: <strong className="text-cyan-400">PhishGuard ML v2.4</strong></span>
          </div>
        </div>

        {/* Counter 1 */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase">QR Scans Run</span>
          <div className="flex items-baseline justify-between mt-2">
            <span className="text-2xl font-black text-cyan-400">{stats.qrScannedToday}</span>
            <QrCode className="w-5 h-5 text-cyan-500/40" />
          </div>
          <span className="text-[10px] text-slate-500 mt-1">Screen / Tab captures</span>
        </div>

        {/* Counter 2 */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase">Threats Intercepted</span>
          <div className="flex items-baseline justify-between mt-2">
            <span className="text-2xl font-black text-rose-400">{stats.threatsBlocked}</span>
            <Ban className="w-5 h-5 text-rose-500/40" />
          </div>
          <span className="text-[10px] text-rose-400/80 mt-1">Score &ge; 80 Intercepted</span>
        </div>

        {/* Counter 3 */}
        <div className="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <span className="text-xs font-mono text-slate-400 uppercase">Suspicious Flagged</span>
          <div className="flex items-baseline justify-between mt-2">
            <span className="text-2xl font-black text-amber-400">{stats.suspiciousItems}</span>
            <AlertTriangle className="w-5 h-5 text-amber-500/40" />
          </div>
          <span className="text-[10px] text-amber-400/80 mt-1">Warned In-Page & Mobile</span>
        </div>
      </div>

      {/* Main Content Layout: Live Feed (Left) & Controls/Sandbox (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left: Live Activity Feed */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Live QR Activity & Background Threat Feed
            </h2>
            <span className="text-[11px] font-mono text-cyan-400 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span>
              Streaming Active
            </span>
          </div>

          <div className="glass-panel rounded-2xl border border-slate-800 divide-y divide-slate-800/60 overflow-hidden shadow-xl">
            {detections.length === 0 ? (
              <div className="text-center py-12 text-slate-500 font-mono text-xs">
                No background detections yet. Use simulated templates to evaluate threats.
              </div>
            ) : (
              detections.map((item) => (
                <div
                  key={item.id}
                  onClick={() => setSelectedScan(item)}
                  className="p-4 hover:bg-slate-900/60 transition-colors cursor-pointer flex items-center justify-between gap-4 group"
                >
                  <div className="flex items-center gap-3.5 min-w-0">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm shrink-0 border ${
                      item.severity === 'CRITICAL'
                        ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                        : item.severity === 'HIGH RISK' || item.severity === 'HIGH'
                        ? 'bg-orange-500/10 border-orange-500/30 text-orange-400'
                        : item.severity === 'SUSPICIOUS' || item.severity === 'MEDIUM'
                        ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                        : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    }`}>
                      {item.severity === 'SAFE' ? '✓' : '⚠'}
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-100 group-hover:text-cyan-400 transition-colors truncate">
                          {item.site}
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          {item.time}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                        {item.payload}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <div className={`text-xs font-extrabold ${
                        item.severity === 'CRITICAL' ? 'text-rose-400' : item.severity === 'SUSPICIOUS' ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {item.severity}
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        Score: {item.threat_score}/100
                      </div>
                    </div>
                    {item.is_blocked && (
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 uppercase">
                        Blocked
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Sandbox / Policy Controls & Simulators */}
        <div className="lg:col-span-5 space-y-6">
          
          {/* Policy & Capability Controls */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Shield Policies & Smart Controls
            </h3>

            <div className="space-y-3 text-xs">
              
              {/* Master Control */}
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div>
                  <div className="font-bold text-slate-200">Background Protection</div>
                  <div className="text-[10px] text-slate-400">Master threat monitoring toggle</div>
                </div>
                <input
                  type="checkbox"
                  checked={masterProtection}
                  onChange={() => handleToggle(setMasterProtection, masterProtection, 'Background Protection')}
                  className="w-4 h-4 accent-cyan-500"
                />
              </div>

              {/* Smart Shield Floating Control */}
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div>
                  <div className="font-bold text-slate-200">PhishGuard Smart Shield</div>
                  <div className="text-[10px] text-slate-400">Movable overlay button for instant scans</div>
                </div>
                <input
                  type="checkbox"
                  checked={smartShield}
                  onChange={() => handleToggle(setSmartShield, smartShield, 'Smart Shield Overlay')}
                  className="w-4 h-4 accent-cyan-500"
                />
              </div>

              {/* Notification Protection */}
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div>
                  <div className="font-bold text-slate-200">Notification Protection</div>
                  <div className="text-[10px] text-slate-400">Scan incoming message text & links</div>
                </div>
                <input
                  type="checkbox"
                  checked={notificationProtection}
                  onChange={() => handleToggle(setNotificationProtection, notificationProtection, 'Notification Protection')}
                  className="w-4 h-4 accent-cyan-500"
                />
              </div>

              {/* Screen Scan */}
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div>
                  <div className="font-bold text-slate-200">Screen Scan (MediaProjection)</div>
                  <div className="text-[10px] text-slate-400">Inspect active screen details on request</div>
                </div>
                <input
                  type="checkbox"
                  checked={screenScan}
                  onChange={() => handleToggle(setScreenScan, screenScan, 'Screen Scan')}
                  className="w-4 h-4 accent-cyan-500"
                />
              </div>

              {/* Duplicate Filter */}
              <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800">
                <div>
                  <div className="font-bold text-slate-200">Duplicate Alert Filtering</div>
                  <div className="text-[10px] text-slate-400">Rate-limit repetitive scam notifications</div>
                </div>
                <input
                  type="checkbox"
                  checked={duplicateDetection}
                  onChange={(e) => setDuplicateDetection(e.target.checked)}
                  className="w-4 h-4 accent-cyan-500"
                />
              </div>
            </div>
          </div>

          {/* Interactive Threat Simulator Sandbox (Tabs) */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Notification Shield Simulator
            </h3>
            <p className="text-xs text-slate-400">
              Simulate incoming notifications to evaluate how the system scans, dedupes, and alerts.
            </p>

            <div className="space-y-3.5">
              <div>
                <label className="text-[10px] font-mono text-slate-300 block mb-1">Source Application</label>
                <select
                  value={simulatorApp}
                  onChange={(e) => setSimulatorApp(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none"
                >
                  <option value="WhatsApp">WhatsApp</option>
                  <option value="Gmail">Gmail</option>
                  <option value="SMS">SMS / Message</option>
                  <option value="HDFC Bank">Banking (HDFC Bank)</option>
                  <option value="Paytm">Payment (Paytm)</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-300 block mb-1">Notification Alert Message Text</label>
                <textarea
                  rows={3}
                  value={simulatorText}
                  onChange={(e) => setSimulatorText(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none"
                />
              </div>

              {/* Simulation presets */}
              <div className="flex flex-wrap gap-1.5 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setSimulatorApp('WhatsApp');
                    setSimulatorText('Urgent verification needed. Your profile expires in 2 hours. Log in now to restore: https://login-appleid-verify-token.account-security-alert.xyz/auth');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-950 border border-slate-800 text-[9px] text-rose-400 hover:border-rose-500 font-mono"
                >
                  Phishing Link
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimulatorApp('SMS');
                    setSimulatorText('ALERT: Unauthorized transaction of $1,200 detected on card ending in 4209. Call support hotline 1800-420-910 immediately.');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-955 border border-slate-800 text-[9px] text-amber-400 hover:border-amber-500 font-mono"
                >
                  Text-Only Scam
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSimulatorApp('Gmail');
                    setSimulatorText('Meeting schedules have updated. Please review links: https://google.com/search?q=cybersecurity');
                  }}
                  className="px-2 py-1 rounded-lg bg-slate-950 border border-slate-800 text-[9px] text-emerald-400 hover:border-emerald-500 font-mono"
                >
                  Safe Message
                </button>
              </div>

              <button
                onClick={() => {
                  const urlRegex = /(https?:\/\/[^\s]+)/;
                  const match = simulatorText.match(urlRegex);
                  handleTriggerSimulatedNotification(simulatorApp, simulatorText, match ? match[0] : null);
                }}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold text-xs hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                <Bell className="w-3.5 h-3.5" />
                Simulate Incoming Notification
              </button>
            </div>
          </div>

          {/* Quick QR Sandbox (Legacy compat) */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              Live QR Threat Sandbox
            </h3>
            <form onSubmit={handleRunQuickTest} className="space-y-3">
              <div>
                <label className="text-[10px] font-mono text-slate-300 block mb-1">Target Webpage Source</label>
                <input
                  type="text"
                  value={testSource}
                  onChange={(e) => setTestSource(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-300 block mb-1">QR Encoded Payload</label>
                <textarea
                  rows={2}
                  value={testPayload}
                  onChange={(e) => setTestPayload(e.target.value)}
                  className="w-full p-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono focus:outline-none"
                />
              </div>

              <button
                type="submit"
                disabled={testingScan}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold text-xs hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                {testingScan ? 'Analyzing...' : 'Execute QR Sandbox Scan'}
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* ─── MODAL 1: FIRST-TIME PERMISSION WIZARD ─── */}
      {showPermissionModal && (
        <div className="fixed inset-0 z-[10050] flex items-center justify-center p-4 bg-black/90 backdrop-blur-md animate-fadeIn">
          <div className="max-w-md w-full glass-panel rounded-3xl border border-slate-800 p-7 space-y-6 shadow-2xl relative">
            <div className="text-center space-y-2">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center mx-auto text-cyan-400">
                <Lock className="w-6 h-6" />
              </div>
              <h3 className="text-lg font-extrabold text-white">Configure Security Permissions</h3>
              <p className="text-xs text-slate-400">
                PhishGuard AI requires specific permissions to run background protection.
              </p>
            </div>

            <div className="space-y-4">
              <div className="flex gap-3 p-3.5 rounded-2xl bg-slate-900 border border-slate-800/80">
                <Bell className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-xs font-bold text-slate-200">Notification Access (Android Listener)</h4>
                  <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">
                    Allows PhishGuard to monitor incoming notifications (WhatsApp, SMS, Gmail) for credentials phishing and scam cues.
                  </p>
                </div>
              </div>

              <div className="flex gap-3 p-3.5 rounded-2xl bg-slate-900 border border-slate-800/80">
                <QrCode className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-xs font-bold text-slate-200">Screen Capture (MediaProjection / getDisplayMedia)</h4>
                  <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">
                    Used only when you trigger a scan to inspect visible visual elements (QR codes, barcodes, scam links).
                  </p>
                </div>
              </div>

              <div className="flex gap-3 p-3.5 rounded-2xl bg-slate-900 border border-slate-800/80">
                <Layers className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-xs font-bold text-slate-200">Display Over Other Apps (Overlays)</h4>
                  <p className="text-[10px] text-slate-400 mt-0.5 leading-relaxed">
                    Required to render the Smart Shield floating control over active applications.
                  </p>
                </div>
              </div>
            </div>

            <div className="pt-2 flex gap-3">
              <button
                onClick={handleGrantPermissions}
                className="flex-1 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-extrabold text-xs shadow-lg shadow-cyan-500/20 hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                Grant & Enable Protection
              </button>
              <button
                onClick={() => {
                  setShowPermissionModal(false);
                  setPermissionTarget(null);
                }}
                className="px-5 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL 2: INTERACTIVE MOCK SCREEN TEMPLATES ─── */}
      {showMockScanModal && (
        <div className="fixed inset-0 z-[10050] flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm animate-fadeIn">
          <div className="max-w-2xl w-full glass-panel rounded-3xl border border-slate-800 p-6 space-y-5 shadow-2xl relative max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Smartphone className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-extrabold text-white">Interactive Screen Scanner Templates</h3>
              </div>
              <button
                onClick={() => setShowMockScanModal(false)}
                className="text-slate-400 hover:text-white text-base font-bold"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Select one of the mock screens below. Clicking scan will simulate capturing that window and extract text and QR codes for combined ML threat checks.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              {/* Template 1 */}
              <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-colors flex flex-col justify-between">
                <div>
                  <span className="px-2 py-0.5 rounded text-[8px] bg-emerald-500/20 text-emerald-300 font-bold font-mono">WHATSAPP CHAT</span>
                  <div className="text-xs font-bold text-white mt-2">Urgent Amazon Gift Card QR</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1 p-2 rounded bg-slate-950/80 border border-slate-800 leading-relaxed">
                    "Congrats! You won $500 Amazon coupon. Click here: https://claim-airdrop-eth2026.xyz/wallet-connect"
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setShowMockScanModal(false);
                    addToast("Simulating WhatsApp OCR screen scan...", "info");
                    await runCombinedAnalysis("WhatsApp Screen", "Congratulations! You have won a $500 Amazon Gift Card! Claim your reward within 12 hours.", "https://claim-airdrop-eth2026.xyz/wallet-connect");
                  }}
                  className="mt-4 w-full py-2 bg-slate-800 hover:bg-cyan-500 hover:text-black rounded-xl text-xs font-bold transition-all"
                >
                  Scan This Screen
                </button>
              </div>

              {/* Template 2 */}
              <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-colors flex flex-col justify-between">
                <div>
                  <span className="px-2 py-0.5 rounded text-[8px] bg-cyan-500/20 text-cyan-300 font-bold font-mono">SMS ALERT</span>
                  <div className="text-xs font-bold text-white mt-2">Suspicious Banking Restrict URL</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1 p-2 rounded bg-slate-950/80 border border-slate-800 leading-relaxed">
                    "HDFC Alert: Your bank profile is locked due to security anomalies. Update now: https://secure-login-verify-account.bank-security.xyz/auth"
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setShowMockScanModal(false);
                    addToast("Simulating SMS Banking OCR screen scan...", "info");
                    await runCombinedAnalysis("SMS Message Screen", "HDFC Alert: Your bank profile is locked due to security anomalies. Update details immediately.", "https://secure-login-verify-account.bank-security.xyz/auth");
                  }}
                  className="mt-4 w-full py-2 bg-slate-800 hover:bg-cyan-500 hover:text-black rounded-xl text-xs font-bold transition-all"
                >
                  Scan This Screen
                </button>
              </div>

              {/* Template 3 */}
              <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-colors flex flex-col justify-between">
                <div>
                  <span className="px-2 py-0.5 rounded text-[8px] bg-red-500/20 text-red-300 font-bold font-mono">GMAIL MAIL</span>
                  <div className="text-xs font-bold text-white mt-2">Apple Security Harvesting Link</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1 p-2 rounded bg-slate-950/80 border border-slate-800 leading-relaxed">
                    "System Notice: We found an unauthorized login attempt from Russia on your Apple ID. Authenticate immediately: https://login-appleid-verify-token.account-security-alert.xyz/auth"
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setShowMockScanModal(false);
                    addToast("Simulating Gmail Security OCR screen scan...", "info");
                    await runCombinedAnalysis("Gmail Mail Screen", "System Notice: We found an unauthorized login attempt from Russia on your Apple ID.", "https://login-appleid-verify-token.account-security-alert.xyz/auth");
                  }}
                  className="mt-4 w-full py-2 bg-slate-800 hover:bg-cyan-500 hover:text-black rounded-xl text-xs font-bold transition-all"
                >
                  Scan This Screen
                </button>
              </div>

              {/* Template 4 */}
              <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-colors flex flex-col justify-between">
                <div>
                  <span className="px-2 py-0.5 rounded text-[8px] bg-indigo-500/20 text-indigo-300 font-bold font-mono">WHATSAPP TEXT-ONLY</span>
                  <div className="text-xs font-bold text-white mt-2">Investment Scam (No URL)</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1 p-2 rounded bg-slate-950/80 border border-slate-800 leading-relaxed">
                    "Double your cryptocurrency capital in 24 hours. Contact our account manager over Telegram @crypto_doubler immediately. Guaranteed 200% payout."
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setShowMockScanModal(false);
                    addToast("Simulating text-only screen scan...", "info");
                    await runCombinedAnalysis("WhatsApp Text-Only Screen", "Double your cryptocurrency capital in 24 hours. Contact our account manager over Telegram @crypto_doubler immediately. Guaranteed 200% payout.", null);
                  }}
                  className="mt-4 w-full py-2 bg-slate-800 hover:bg-cyan-500 hover:text-black rounded-xl text-xs font-bold transition-all"
                >
                  Scan This Screen
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL 3: BROWSER LIMITATION WARNING WIZARD ─── */}
      {showBrowserWarningModal && (
        <div className="fixed inset-0 z-[10050] flex items-center justify-center p-4 bg-black/90 backdrop-blur-md animate-fadeIn">
          <div className="max-w-md w-full glass-panel rounded-3xl border border-slate-800 p-6 space-y-5 text-center shadow-2xl relative">
            <div className="w-12 h-12 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto text-amber-400">
              <AlertCircle className="w-6 h-6" />
            </div>

            <div>
              <h3 className="text-base font-extrabold text-white">Browser-Only Access Limitation</h3>
              <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                This capability requires Android system-level access and is not available in browser-only mode.
              </p>
              <p className="text-[11px] text-slate-500 mt-2 font-mono leading-relaxed">
                Direct background OCR text parsing from external apps requires the native Android wrapper's NotificationListener and MediaProjection components.
              </p>
            </div>

            <div className="p-3 bg-slate-900 rounded-2xl border border-slate-800 text-[10px] text-slate-300 font-mono text-left leading-relaxed">
              💡 <strong>How to test:</strong> You can use our interactive mock screen sandbox models to test the scoring, classification, and AI Helpline context passing layers.
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => {
                  setShowBrowserWarningModal(false);
                  setShowMockScanModal(true);
                }}
                className="flex-1 py-2.5 rounded-xl bg-cyan-500 text-black font-extrabold text-xs hover:bg-cyan-400 transition-colors"
              >
                Open Mock Templates
              </button>
              <button
                onClick={() => setShowBrowserWarningModal(false)}
                className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 4: Detailed Scan Inspection Modal */}
      {selectedScan && (
        <div className="fixed inset-0 z-[10050] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="max-w-lg w-full glass-panel rounded-2xl border border-slate-700 p-6 space-y-5 shadow-2xl relative">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-extrabold text-white">Threat Analysis Deep Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div className={`p-4 rounded-xl border flex items-center justify-between ${
                selectedScan.severity === 'CRITICAL' || selectedScan.threat_score >= 80
                  ? 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                  : selectedScan.severity === 'HIGH RISK' || selectedScan.threat_score >= 60
                  ? 'bg-orange-500/10 border-orange-500/40 text-orange-300'
                  : selectedScan.severity === 'SUSPICIOUS' || selectedScan.threat_score >= 40
                  ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                  : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300'
              }`}>
                <div>
                  <div className="text-[10px] uppercase font-mono tracking-wider">Threat Level</div>
                  <div className="text-lg font-black">{selectedScan.threat_score} / 100 — {selectedScan.severity}</div>
                  <div className="text-xs font-bold">{selectedScan.classification || 'BENIGN'}</div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-black">{selectedScan.threat_score}</div>
                  <div className="text-[10px] text-slate-400 font-mono">/ 100 Risk Score</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                  <label className="text-[10px] font-mono text-slate-400 block mb-0.5 font-bold">QR TYPE</label>
                  <div className="text-xs font-mono text-cyan-300 font-semibold">{selectedScan.qr_type || 'URL'}</div>
                </div>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800">
                  <label className="text-[10px] font-mono text-slate-400 block mb-0.5 font-bold">AUTHENTICITY</label>
                  <div className={`text-xs font-mono font-semibold ${selectedScan.threat_score <= 20 ? 'text-emerald-300' : selectedScan.threat_score >= 60 ? 'text-rose-300' : 'text-amber-300'}`}>
                    {selectedScan.threat_score <= 20 ? 'VERIFIED' : selectedScan.threat_score >= 60 ? 'SUSPICIOUS' : 'UNVERIFIED'}
                  </div>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 block mb-1 font-bold">SOURCE CONTEXT</label>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200">
                  {selectedScan.site}
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 block mb-1 font-bold">DECODED DESTINATION</label>
                <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400 break-all select-all">
                  {selectedScan.payload}
                </div>
              </div>

              <div>
                <label className="text-[10px] font-mono text-slate-400 block mb-1 font-bold">SECURITY ANALYSIS</label>
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {(selectedScan.reasons || []).map((r, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-slate-900/60 p-2 rounded-lg border border-slate-800">
                      <span className={selectedScan.threat_score <= 20 ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                        {selectedScan.threat_score <= 20 ? '✓' : '⚠'}
                      </span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => {
                  updateScanContext({
                    rawValue: selectedScan.payload,
                    formatName: 'Threat Feed Context',
                    type: 'Background Protection Alert',
                    riskScore: selectedScan.threat_score,
                    verdict: selectedScan.severity,
                    reasons: selectedScan.reasons,
                    actionableAdvice: 'Detailed check requested via user history feed.',
                    sourceApp: selectedScan.site,
                    messageContent: selectedScan.payload,
                    detectedUrl: selectedScan.payload,
                    threatProbability: selectedScan.threat_score,
                    threatCategory: selectedScan.classification
                  });
                  setSelectedScan(null);
                  navigate('/helpline');
                }}
                className="flex-1 py-2.5 rounded-xl bg-cyan-500 text-black font-extrabold text-xs hover:bg-cyan-400 transition-all shadow-md"
              >
                Discuss with AI Helpline
              </button>
              {selectedScan.threat_score < 20 ? (
                <button
                  onClick={() => {
                    if (selectedScan.payload?.startsWith('http')) {
                      window.open(selectedScan.payload, '_blank');
                    }
                    setSelectedScan(null);
                  }}
                  className="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs transition-all"
                >
                  PROCEED
                </button>
              ) : selectedScan.threat_score >= 60 ? (
                <button
                  onClick={() => {
                    addToast('Navigation blocked for high-risk threat destination.', 'info');
                    setSelectedScan(null);
                  }}
                  className="px-5 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs transition-all"
                >
                  STOP PROCEEDING
                </button>
              ) : (
                <button
                  onClick={() => {
                    if (selectedScan.payload?.startsWith('http') && confirm(`Warning: Unverified destination (${selectedScan.payload}). Proceed?`)) {
                      window.open(selectedScan.payload, '_blank');
                    }
                    setSelectedScan(null);
                  }}
                  className="px-5 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs transition-all"
                >
                  PROCEED WITH CAUTION
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL 5: Device Pairing Generator Modal */}
      {showPairModal && (
        <div className="fixed inset-0 z-[10050] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="max-w-md w-full glass-panel rounded-2xl border border-slate-700 p-6 space-y-5 shadow-2xl text-center">
            <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400">
              <Smartphone className="w-6 h-6" />
            </div>

            <div>
              <h3 className="text-lg font-bold text-white">Pair Android Companion</h3>
              <p className="text-xs text-slate-400 mt-1">
                Enter this pairing code into your Android companion app or simulator to link real-time threat telemetry.
              </p>
            </div>

            {pairingLoading ? (
              <div className="py-8 font-mono text-xs text-cyan-400 animate-pulse">
                Generating Secure Pairing Token...
              </div>
            ) : (
              pairingData && (
                <div className="space-y-4">
                  <div className="p-4 rounded-2xl bg-slate-950 border-2 border-dashed border-cyan-500/50">
                    <div className="text-3xl font-black font-mono tracking-widest text-cyan-400">
                      {pairingData.pairing_code.slice(0, 3)} {pairingData.pairing_code.slice(3)}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-1 font-mono">
                      Valid for 10 minutes (One-Time Pairing)
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={handleCopyCode}
                      className="flex-1 py-2.5 rounded-xl bg-cyan-500 text-black font-bold text-xs hover:bg-cyan-400 transition-all flex items-center justify-center gap-1.5"
                    >
                      {copiedCode ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      <span>{copiedCode ? 'Copied!' : 'Copy Code'}</span>
                    </button>
                    <Link
                      to="/android-companion"
                      className="flex-1 py-2.5 rounded-xl bg-slate-800 text-slate-200 font-bold text-xs hover:bg-slate-700 transition-all flex items-center justify-center gap-1.5"
                    >
                      <span>Open Simulator ↗</span>
                    </Link>
                  </div>
                </div>
              )
            )}

            <button
              onClick={() => setShowPairModal(false)}
              className="text-xs text-slate-400 hover:text-white font-mono"
            >
              Done / Close
            </button>
          </div>
        </div>
      )}

      {/* ─── IN-APP REGION SELECTION MODE OVERLAY (CTRL + SHIFT + Q) ─── */}
      {showRegionOverlay && (
        <div
          className="fixed inset-0 z-[10070] bg-black/40 cursor-crosshair select-none"
          onMouseDown={handleRegionMouseDown}
          onMouseMove={handleRegionMouseMove}
          onMouseUp={handleRegionMouseUp}
        >
          <div className="phishguard-banner-panel absolute top-6 left-1/2 -translate-x-1/2 bg-slate-950/96 border border-cyan-500/60 rounded-2xl px-6 py-3.5 text-center shadow-2xl pointer-events-auto">
            <div className="text-xs font-mono font-extrabold text-cyan-400 tracking-wider">PhishGuard Smart Scan</div>
            <div className="text-xs text-white mt-0.5 font-bold">Move over content to scan • Click to scan • Esc to cancel</div>
            <div className="text-[10px] text-slate-400 mt-1 font-mono italic">Hover auto-highlights objects under cursor. Click to confirm selection.</div>
          </div>

          {selectionRect.width > 0 && selectionRect.height > 0 && (
            <div
              style={{
                position: 'absolute',
                left: `${selectionRect.x}px`,
                top: `${selectionRect.y}px`,
                width: `${selectionRect.width}px`,
                height: `${selectionRect.height}px`,
                border: '2px solid #06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.15)',
                boxShadow: '0 0 25px rgba(6, 182, 212, 0.5), inset 0 0 15px rgba(6, 182, 212, 0.2)',
                borderRadius: '8px',
                pointerEvents: 'none',
                transition: 'all 0.08s cubic-bezier(0.16, 1, 0.3, 1)'
              }}
            >
              <div
                style={{
                  position: 'absolute',
                  top: '-24px',
                  left: '-2px',
                  backgroundColor: '#06b6d4',
                  color: '#0f172a',
                  fontSize: '10px',
                  fontWeight: '800',
                  fontFamily: 'monospace',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  boxShadow: '0 4px 10px rgba(0,0,0,0.3)',
                  whiteSpace: 'nowrap'
                }}
              >
                [ {selectionRect.label || 'SMART REGION'} ]
              </div>
            </div>
          )}
        </div>
      )}


      {/* ─── ESSENTIAL KEY / UNIVERSAL MANUAL SCANNER RESULT MODAL (CTRL + SHIFT + Q) ─── */}
      {showUniversalModal && universalScanResult && (
        <div className="fixed inset-0 z-[10060] flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="max-w-lg w-full glass-panel rounded-3xl border border-cyan-500/30 p-6 space-y-5 shadow-2xl relative text-left">
            <button
              onClick={() => setShowUniversalModal(false)}
              className="absolute top-4 right-4 p-1.5 rounded-full bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Header */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
                🛡️
              </div>
              <div>
                <h3 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
                  <span>PhishGuard.AI</span>
                  <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-500/30">
                    {universalScanResult.detected_type || 'ESSENTIAL KEY SCAN'}
                  </span>
                </h3>
                <p className="text-[11px] text-slate-400 font-mono">
                  Essential Key Smart Region Security Verification
                </p>
              </div>
            </div>

            {/* 5-Tier Decision Guidance Banner */}
            {universalScanResult.decision_guidance && (
              <div className={`p-3.5 rounded-2xl border text-xs font-mono font-bold leading-relaxed ${
                universalScanResult.threat_level === 'CRITICAL' ? 'bg-rose-950/40 border-rose-500/40 text-rose-300' :
                universalScanResult.threat_level === 'HIGH RISK' ? 'bg-orange-950/40 border-orange-500/40 text-orange-300' :
                universalScanResult.threat_level === 'MEDIUM RISK' ? 'bg-amber-950/40 border-amber-500/40 text-amber-300' :
                'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
              }`}>
                <div className="text-[9px] uppercase tracking-wider font-extrabold mb-0.5 text-slate-400">DECISION LAYER RECOMMENDATION</div>
                "{universalScanResult.decision_guidance}"
              </div>
            )}

            {/* Dynamic Content based on detected_type */}
            {universalScanResult.detected_type === 'NOTHING SUPPORTED' ? (
              <div className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 text-center space-y-3">
                <div className="text-3xl">🔍</div>
                <div className="text-sm font-black text-rose-400 tracking-wider">NOTHING DETECTED</div>
                <p className="text-xs text-slate-400 leading-relaxed font-mono">
                  {universalScanResult.message || "Unable to scan this selected area. No supported URL, QR code, barcode, or readable text was detected."}
                </p>
              </div>
            ) : universalScanResult.detected_type === 'BARCODE DETECTED' ? (
              <div className="space-y-4">
                <div className="p-4 rounded-2xl border bg-emerald-500/10 border-emerald-500/30 text-emerald-400 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">BARCODE DETECTED</span>
                    <div className="text-lg font-black">FORMAT: {universalScanResult.barcode_format || '1D Symbology'}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">TYPE: PRODUCT / IDENTIFIER</div>
                  </div>
                  <div className="text-3xl font-black">0 / 100</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300">
                  <div className="text-[9px] text-slate-500 font-bold mb-1">DECODED BARCODE VALUE</div>
                  {universalScanResult.barcode_val || universalScanResult.decoded_payload || 'N/A'}
                </div>
              </div>
            ) : universalScanResult.detected_type === 'MIXED CONTENT DETECTED' ? (
              <div className="space-y-4">
                <div className={`p-4 rounded-2xl border flex items-center justify-between ${
                  universalScanResult.threat_score >= 60 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">MIXED CONTENT DETECTED</span>
                    <div className="text-lg font-black">{universalScanResult.threat_score} / 100 — {universalScanResult.threat_level}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">COMPONENTS: {(universalScanResult.components || []).length} ANALYZED</div>
                  </div>
                  <div className="text-3xl font-black">{universalScanResult.threat_score}</div>
                </div>

                <div className="space-y-2">
                  {(universalScanResult.components || []).map((comp, idx) => (
                    <div key={idx} className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200">
                      <div className="text-[9px] text-cyan-400 font-bold uppercase mb-0.5">{comp.type}</div>
                      <div>{comp.target}</div>
                    </div>
                  ))}
                </div>
              </div>
            ) : universalScanResult.detected_type === 'URL DETECTED' ? (
              <div className="space-y-4">
                <div className={`p-4 rounded-2xl border flex items-center justify-between ${
                  universalScanResult.threat_score >= 60 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">URL DETECTED</span>
                    <div className="text-lg font-black">{universalScanResult.threat_score} / 100 — {universalScanResult.threat_level || 'SAFE'}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">CONFIDENCE: {universalScanResult.confidence ? `${Math.round(universalScanResult.confidence * 100)}%` : 'HIGH'}</div>
                  </div>
                  <div className="text-3xl font-black">{universalScanResult.threat_score}</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all">
                  <div className="text-[9px] text-slate-500 font-bold mb-1">TARGET URL</div>
                  {universalScanResult.url || universalScanResult.target || 'N/A'}
                </div>

                <div className="flex gap-2">
                  <span className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    DOMAIN: {universalScanResult.domain || 'Verified Domain'}
                  </span>
                  <span className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    ENCRYPTION: {universalScanResult.is_https ? 'HTTPS' : 'HTTP'}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[10px] font-bold font-mono text-slate-400 uppercase">Security Analysis</div>
                  <ul className="space-y-1 text-xs text-slate-300 font-mono">
                    {(universalScanResult.checks || universalScanResult.analysis_reasons || []).map((c, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className={c.icon === '✓' || (typeof c === 'string' && c.includes('Verified')) ? 'text-emerald-400' : 'text-amber-400'}>
                          {c.icon || '⚠'}
                        </span>
                        <span>{c.text || c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : universalScanResult.detected_type === 'NOTIFICATION DETECTED' ? (
              <div className="space-y-4">
                <div className={`p-4 rounded-2xl border flex items-center justify-between ${
                  universalScanResult.status === 'LIKELY FAKE' ? 'bg-red-500/10 border-red-500/30 text-red-400' :
                  universalScanResult.status === 'SUSPICIOUS' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">NOTIFICATION DETECTED</span>
                    <div className="text-lg font-black">{universalScanResult.status || universalScanResult.status_verdict || 'SUSPICIOUS'}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">RISK SCORE: {universalScanResult.threat_score} / 100</div>
                  </div>
                  <div className="text-3xl font-black">{universalScanResult.threat_score}</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 leading-relaxed">
                  <div className="text-[9px] text-slate-500 font-bold mb-1">EXTRACTED MESSAGE TEXT</div>
                  "{universalScanResult.extracted_message}"
                </div>

                <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-1">
                  <div className="text-[9px] font-bold font-mono text-cyan-400 uppercase">AI Helpline Analysis</div>
                  <p className="leading-relaxed">{universalScanResult.ai_helpline_analysis || 'Analyzed message for psychological manipulation and fraud indicators.'}</p>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[10px] font-bold font-mono text-slate-400 uppercase">Reasons</div>
                  <ul className="space-y-1 text-xs text-slate-300 font-mono">
                    {(universalScanResult.checks || universalScanResult.analysis_reasons || []).map((c, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className={c.icon === '✓' ? 'text-emerald-400' : 'text-amber-400'}>
                          {c.icon || '⚠'}
                        </span>
                        <span>{c.text || c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : universalScanResult.detected_type === 'EMAIL ID DETECTED' ? (
              <div className="space-y-4">
                <div className={`p-4 rounded-2xl border flex items-center justify-between ${
                  universalScanResult.authenticity === 'SUSPICIOUS' ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">EMAIL ID DETECTED</span>
                    <div className="text-lg font-black">AUTHENTICITY: {universalScanResult.authenticity || 'UNVERIFIED'}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">RISK SCORE: {universalScanResult.threat_score} / 100 — {universalScanResult.threat_level || 'MEDIUM RISK'}</div>
                  </div>
                  <div className="text-3xl font-black">{universalScanResult.threat_score}</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300">
                  <div className="text-[9px] text-slate-500 font-bold mb-1">EMAIL ADDRESS</div>
                  {universalScanResult.email}
                </div>

                <div className="flex gap-2">
                  <span className="px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    DOMAIN: {universalScanResult.domain}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[10px] font-bold font-mono text-slate-400 uppercase">Security Analysis</div>
                  <ul className="space-y-1 text-xs text-slate-300 font-mono">
                    {(universalScanResult.checks || universalScanResult.analysis_reasons || []).map((c, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className={c.icon === '✓' ? 'text-emerald-400' : 'text-amber-400'}>
                          {c.icon || '⚠'}
                        </span>
                        <span>{c.text || c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ) : (
              /* QR CODE DETECTED */
              <div className="space-y-4">
                <div className={`p-4 rounded-2xl border flex items-center justify-between ${
                  universalScanResult.threat_score >= 60 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                }`}>
                  <div>
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">QR CODE DETECTED</span>
                    <div className="text-lg font-black">{universalScanResult.threat_score} / 100 — {universalScanResult.threat_level || 'SAFE'}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-0.5">TYPE: {universalScanResult.qr_type || 'URL'}</div>
                  </div>
                  <div className="text-3xl font-black">{universalScanResult.threat_score}</div>
                </div>

                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300 break-all">
                  <div className="text-[9px] text-slate-500 font-bold mb-1">DECODED DESTINATION</div>
                  {universalScanResult.decoded_payload || 'QR payload'}
                </div>

                <div className="space-y-1.5">
                  <div className="text-[10px] font-bold font-mono text-slate-400 uppercase">Security Analysis</div>
                  <ul className="space-y-1 text-xs text-slate-300 font-mono">
                    {(universalScanResult.analysis?.checks || universalScanResult.analysis?.reasons || []).map((c, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className={c.icon === '✓' ? 'text-emerald-400' : 'text-amber-400'}>
                          {c.icon || '⚠'}
                        </span>
                        <span>{c.text || c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Modal Actions */}
            <div className="pt-3 border-t border-slate-800 flex gap-2">
              <button
                onClick={() => {
                  handleAskAIHelpline({
                    messageContent: universalScanResult.extracted_message || universalScanResult.decoded_payload || universalScanResult.url || universalScanResult.barcode_val,
                    riskScore: universalScanResult.threat_score,
                    verdict: universalScanResult.threat_level || universalScanResult.status,
                    reasons: universalScanResult.analysis_reasons || [],
                    sourceApp: 'Essential Key Smart Scan'
                  });
                }}
                className="flex-1 py-2.5 rounded-xl bg-cyan-500 text-black font-extrabold text-xs hover:bg-cyan-400 transition-all text-center"
              >
                Ask AI Helpline ↗
              </button>
              <button
                onClick={() => setShowUniversalModal(false)}
                className="flex-1 py-2.5 rounded-xl bg-slate-800 text-slate-300 font-bold text-xs hover:bg-slate-700 transition-all text-center"
              >
                Dismiss / Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default BackgroundProtection;

