import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import {
  Smartphone,
  ShieldCheck,
  ShieldAlert,
  Radio,
  Bell,
  RefreshCw,
  Clock,
  ExternalLink,
  Ban,
  CheckCircle,
  AlertTriangle,
  QrCode,
  Wifi,
  Battery,
  Layers,
  ArrowRight,
  Sparkles,
} from 'lucide-react';

const AndroidCompanion = () => {
  const { user } = useAuth();
  const { addToast } = useThreat();

  const [connected, setConnected] = useState(true);
  const [activeTab, setActiveTab] = useState('shield'); // 'shield' | 'history' | 'pair'
  const [pairingCodeInput, setPairingCodeInput] = useState('');
  const [pairingStatus, setPairingStatus] = useState(null);

  // Latest live scan state
  const [latestScan, setLatestScan] = useState({
    scan_id: 87,
    payload: 'https://login-appleid-verify-token.account-security-alert.xyz/auth',
    qr_type: 'URL',
    domain: 'account-security-alert.xyz',
    threat_score: 92.5,
    severity: 'CRITICAL',
    classification: 'PHISHING',
    confidence: 0.96,
    is_blocked: true,
    timestamp: new Date().toISOString(),
    analysis_reasons: [
      "Lookalike domain mimicking 'Apple' authentication service",
      "Credential harvesting indicators found in URL path: [login, auth, token]",
      "High-risk top-level domain (.xyz) frequently associated with disposable quishing lures",
    ],
  });

  // Incoming mobile notification banner
  const [mobileNotification, setMobileNotification] = useState(null);

  // Scan history list
  const [scanHistory, setScanHistory] = useState([
    {
      id: 87,
      payload: 'https://login-appleid-verify-token.account-security-alert.xyz/auth',
      domain: 'account-security-alert.xyz',
      threat_score: 92.5,
      severity: 'CRITICAL',
      classification: 'PHISHING',
      is_blocked: true,
      time: 'Just now',
    },
    {
      id: 86,
      payload: 'https://claim-airdrop-eth2026.xyz/wallet-connect',
      domain: 'claim-airdrop-eth2026.xyz',
      threat_score: 88.0,
      severity: 'CRITICAL',
      classification: 'PAYMENT_FRAUD',
      is_blocked: true,
      time: '12 mins ago',
    },
    {
      id: 85,
      payload: 'https://google.com/search?q=cybersecurity',
      domain: 'google.com',
      threat_score: 6.0,
      severity: 'SAFE',
      classification: 'BENIGN',
      is_blocked: false,
      time: '1 hour ago',
    },
  ]);

  // Connect to SSE stream
  useEffect(() => {
    fetchLatestScan();
    const token = localStorage.getItem('phishguard_access_token');
    const sseUrl = `http://localhost:8000/api/v1/devices/events${token ? `?token=${token}` : ''}`;
    
    let eventSource = null;
    try {
      eventSource = new EventSource(sseUrl);
      
      eventSource.addEventListener('connected', () => {
        setConnected(true);
      });

      eventSource.addEventListener('QR_SCAN_COMPLETED', (e) => {
        try {
          const data = JSON.parse(e.data);
          const scan = data.scan || data;
          setLatestScan(scan);
          
          // Trigger simulated mobile push banner on high severity
          if (scan.severity === 'CRITICAL' || scan.severity === 'HIGH RISK' || scan.severity === 'SUSPICIOUS') {
            setMobileNotification({
              title: `🚨 ${scan.severity} QR Threat Detected`,
              body: `Threat Score ${scan.threat_score}/100 detected on your laptop.`,
              time: 'Just now',
            });
            setTimeout(() => setMobileNotification(null), 8000);
          }

          // Prepend to history
          setScanHistory((prev) => [
            {
              id: scan.scan_id || Date.now(),
              payload: scan.payload,
              domain: scan.domain || scan.payload.replace(/^https?:\/\//, '').split('/')[0],
              threat_score: scan.threat_score,
              severity: scan.severity,
              classification: scan.classification,
              is_blocked: scan.is_blocked,
              time: 'Just now',
            },
            ...prev.slice(0, 19),
          ]);
        } catch (err) {
          console.warn('Failed to parse SSE scan event:', err);
        }
      });

      eventSource.onerror = () => {
        setConnected(false);
      };
    } catch (e) {
      console.warn('SSE connection init failed:', e);
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  const fetchLatestScan = async () => {
    try {
      const res = await api.get('/devices/latest-scan');
      if (res.data?.latest_scan) {
        setLatestScan(res.data.latest_scan);
      }
    } catch (e) {
      // Use initial state
    }
  };

  const handlePairSubmit = async (e) => {
    e.preventDefault();
    if (!pairingCodeInput.trim()) return;
    try {
      const code = pairingCodeInput.replace(/\s+/g, '');
      const res = await api.post('/devices/pair/confirm', {
        pairing_code: code,
        device_name: 'Samsung Galaxy S24 (Companion)',
        device_id: `android_${Date.now()}`,
        device_type: 'android',
      });
      setPairingStatus('Device successfully paired with laptop shield!');
      setConnected(true);
      addToast('Android Companion Paired Successfully!', 'success');
      setTimeout(() => setActiveTab('shield'), 1500);
    } catch (err) {
      setPairingStatus('Pairing failed: Invalid or expired code.');
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
            <Smartphone className="w-4 h-4" />
            <span>CROSS-DEVICE DEFENSE PROTOCOL</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            PhishGuard.AI Android Companion
          </h1>
          <p className="text-xs lg:text-sm text-slate-400">
            Real-time companion app synchronized with your laptop browser shield.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className={`px-3.5 py-1.5 rounded-full border text-xs font-bold flex items-center gap-2 ${
            connected
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
              : 'bg-rose-500/10 border-rose-500/30 text-rose-400'
          }`}>
            <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`}></span>
            <span>{connected ? '● LIVE SYNC ACTIVE' : '○ CONNECTING...'}</span>
          </div>
        </div>
      </div>

      {/* Main Grid: Android Mockup & Documentation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left: Interactive Phone Mockup */}
        <div className="lg:col-span-5 flex justify-center">
          <div className="w-[340px] h-[680px] bg-slate-950 rounded-[48px] p-4 border-4 border-slate-700 shadow-2xl shadow-cyan-950/40 relative flex flex-col justify-between overflow-hidden">
            {/* Phone Speaker Notch */}
            <div className="absolute top-2 left-1/2 -translate-x-1/2 w-28 h-5 bg-slate-900 rounded-b-xl z-30 flex items-center justify-center">
              <div className="w-10 h-1 bg-slate-700 rounded-full"></div>
            </div>

            {/* Mobile Screen Container */}
            <div className="flex-1 bg-[#090d16] rounded-[36px] overflow-hidden flex flex-col relative text-slate-100 font-sans pt-6">
              {/* Status Bar */}
              <div className="px-5 py-1 flex items-center justify-between text-[10px] font-mono text-slate-400 z-20">
                <span>11:18</span>
                <div className="flex items-center gap-1.5">
                  <Wifi className="w-3 h-3" />
                  <Radio className="w-3 h-3 text-cyan-400" />
                  <Battery className="w-3 h-3" />
                </div>
              </div>

              {/* Simulated OS Notification Popup */}
              {mobileNotification && (
                <div className="mx-3 mt-1 p-3 rounded-2xl bg-slate-900/95 border border-rose-500/60 shadow-xl backdrop-blur-md animate-bounce z-40">
                  <div className="flex items-center justify-between text-[9px] font-bold text-rose-400 mb-1">
                    <span className="flex items-center gap-1">🛡️ PhishGuard.AI Alert</span>
                    <span>{mobileNotification.time}</span>
                  </div>
                  <div className="text-[11px] font-bold text-white">{mobileNotification.title}</div>
                  <div className="text-[10px] text-slate-300 mt-0.5">{mobileNotification.body}</div>
                </div>
              )}

              {/* App Bar */}
              <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center text-xs font-bold text-white shadow-md">
                    🛡️
                  </div>
                  <div>
                    <div className="text-xs font-bold text-white">PhishGuard.AI</div>
                    <div className="text-[9px] text-cyan-400 flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                      Shield Companion
                    </div>
                  </div>
                </div>
                <div className="flex gap-1 bg-slate-900 p-0.5 rounded-lg border border-slate-800 text-[10px]">
                  <button
                    onClick={() => setActiveTab('shield')}
                    className={`px-2 py-1 rounded-md font-bold transition-all ${
                      activeTab === 'shield' ? 'bg-cyan-500 text-black' : 'text-slate-400'
                    }`}
                  >
                    Shield
                  </button>
                  <button
                    onClick={() => setActiveTab('history')}
                    className={`px-2 py-1 rounded-md font-bold transition-all ${
                      activeTab === 'history' ? 'bg-cyan-500 text-black' : 'text-slate-400'
                    }`}
                  >
                    History
                  </button>
                  <button
                    onClick={() => setActiveTab('pair')}
                    className={`px-2 py-1 rounded-md font-bold transition-all ${
                      activeTab === 'pair' ? 'bg-cyan-500 text-black' : 'text-slate-400'
                    }`}
                  >
                    Pair
                  </button>
                </div>
              </div>

              {/* Tab Content */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {activeTab === 'shield' && (
                  <>
                    {/* Live Shield Status Card */}
                    <div className="p-3.5 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                          <Radio className="w-5 h-5 animate-pulse" />
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-400 uppercase font-mono">Background Shield</div>
                          <div className="text-xs font-bold text-white flex items-center gap-1">
                            ● Connected to Laptop
                          </div>
                        </div>
                      </div>
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold">
                        SYNCED
                      </span>
                    </div>

                    {/* Latest QR Scan Card */}
                    <div className="space-y-2">
                      <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center justify-between">
                        <span>Latest QR Detection</span>
                        <span className="text-cyan-400">Real-Time</span>
                      </div>

                      {latestScan ? (
                        <div className="p-4 rounded-2xl bg-slate-900 border border-slate-800 space-y-3 shadow-lg">
                          <div className="flex items-center justify-between">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-extrabold tracking-wider ${
                              latestScan.severity === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                : latestScan.severity === 'HIGH RISK'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                : latestScan.severity === 'SUSPICIOUS'
                                ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                            }`}>
                              {latestScan.severity}
                            </span>
                            <div className="text-right">
                              <span className="text-base font-black text-white">{latestScan.threat_score}</span>
                              <span className="text-[9px] text-slate-500">/100</span>
                            </div>
                          </div>

                          <div>
                            <div className="text-[10px] text-slate-400 uppercase font-mono">Classification</div>
                            <div className="text-xs font-bold text-slate-100">{latestScan.classification}</div>
                          </div>

                          <div className="p-2 rounded-xl bg-slate-950 border border-slate-800">
                            <div className="text-[9px] text-slate-500 uppercase font-mono">Scanned URL</div>
                            <div className="text-[10px] font-mono text-cyan-400 break-all line-clamp-2">
                              {latestScan.payload}
                            </div>
                          </div>

                          <div className="space-y-1">
                            <div className="text-[9px] text-slate-400 uppercase font-mono">Analysis Reasons</div>
                            <ul className="text-[10px] text-slate-300 space-y-1">
                              {(latestScan.analysis_reasons || []).slice(0, 2).map((r, i) => (
                                <li key={i} className="flex items-start gap-1.5">
                                  <span className="text-amber-400 font-bold">⚠</span>
                                  <span className="line-clamp-2">{r}</span>
                                </li>
                              ))}
                            </ul>
                          </div>

                          {latestScan.is_blocked && (
                            <div className="px-3 py-1.5 rounded-xl bg-rose-500/20 border border-rose-500/30 text-[10px] text-rose-300 font-bold flex items-center gap-1.5">
                              <span>🛑 Blocked by Laptop Shield</span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="text-center py-8 text-xs text-slate-500 font-mono">
                          Waiting for first QR scan from laptop...
                        </div>
                      )}
                    </div>
                  </>
                )}

                {activeTab === 'history' && (
                  <div className="space-y-3">
                    <div className="text-[10px] font-mono text-slate-400 uppercase">Recent Quishing Checks</div>
                    {scanHistory.map((item) => (
                      <div key={item.id} className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
                            item.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-300'
                              : item.severity === 'SUSPICIOUS'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-emerald-500/20 text-emerald-300'
                          }`}>
                            {item.severity} ({item.threat_score})
                          </span>
                          <span className="text-[9px] text-slate-500">{item.time}</span>
                        </div>
                        <div className="text-[10px] font-mono text-cyan-400 break-all line-clamp-1">
                          {item.domain}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {activeTab === 'pair' && (
                  <div className="space-y-4">
                    <div className="text-[10px] font-mono text-slate-400 uppercase">Pair New Device</div>
                    <form onSubmit={handlePairSubmit} className="space-y-3">
                      <div>
                        <label className="text-[10px] text-slate-300 block mb-1">Enter 6-Digit Pairing Code</label>
                        <input
                          type="text"
                          value={pairingCodeInput}
                          onChange={(e) => setPairingCodeInput(e.target.value)}
                          placeholder="e.g. 482 910"
                          className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-700 text-center font-mono text-base tracking-widest text-cyan-400 focus:outline-none focus:border-cyan-500"
                        />
                      </div>
                      <button
                        type="submit"
                        className="w-full py-2.5 rounded-xl bg-cyan-500 text-black font-bold text-xs shadow-md hover:bg-cyan-400 transition-all"
                      >
                        Pair with Laptop Shield
                      </button>
                    </form>

                    {pairingStatus && (
                      <div className="text-[10px] p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-center text-slate-200">
                        {pairingStatus}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Bottom Home Indicator */}
              <div className="py-2 flex justify-center">
                <div className="w-24 h-1 bg-slate-700 rounded-full"></div>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Companion Architecture & Features */}
        <div className="lg:col-span-7 space-y-6">
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-cyan-400" />
              Real-Time Android Shield Synchronization
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Whenever you press <span className="font-mono text-cyan-300 bg-cyan-950/60 px-1.5 py-0.5 rounded">Ctrl + Shift + Q</span> on your laptop, the captured visible tab is analyzed in-memory and immediately broadcast over encrypted Server-Sent Events (SSE) to your Android device.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Bell className="w-3.5 h-3.5 text-rose-400" />
                  Instant High-Risk Alerts
                </div>
                <p className="text-[11px] text-slate-400">
                  Critical & Suspicious QR codes trigger push notifications directly on Android.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1">
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                  Dual-Screen Quishing Guard
                </div>
                <p className="text-[11px] text-slate-400">
                  Compare desktop QR landing pages with mobile threat telemetry in real-time.
                </p>
              </div>
            </div>
          </div>

          {/* Android Project Source Reference */}
          <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-cyan-400" />
              Native Android Project Codebase (Kotlin / Jetpack Compose)
            </h3>
            <p className="text-xs text-slate-400">
              The companion application is also provided as a native Android project in the <code className="text-cyan-300">android/</code> repository directory with Retrofit, Room DB, and Android NotificationManager.
            </p>
            <div className="pt-2">
              <a
                href="/background-protection"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white text-xs font-bold hover:from-cyan-400 hover:to-blue-500 transition-all shadow-lg shadow-cyan-500/20"
              >
                Go to Background Protection Dashboard
                <ArrowRight className="w-4 h-4" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AndroidCompanion;
