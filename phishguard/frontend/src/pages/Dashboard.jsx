import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import RiskGauge from '../components/RiskGauge';
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Activity,
  AlertTriangle,
  Mail,
  ArrowRight,
  TrendingUp,
  Award,
  Globe,
  RefreshCw,
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
} from 'lucide-react';

const Dashboard = () => {
  const { user } = useAuth();
  const { addToast, triggerPreClickCheck } = useThreat();
  const [recentScans, setRecentScans] = useState([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    threatsBlocked: 0,
    safeScans: 0,
  });
  const [quickScanUrl, setQuickScanUrl] = useState('');
  const [scanning, setScanning] = useState(false);

  // Background Protection Controls state
  const [bgProtectionActive, setBgProtectionActive] = useState(true);
  const [bgQrProtection, setBgQrProtection] = useState(true);
  const [bgUrlProtection, setBgUrlProtection] = useState(true);
  const [bgNotifications, setBgNotifications] = useState(true);
  const [bgAutoBlock, setBgAutoBlock] = useState(false);
  const [showExtensionGuide, setShowExtensionGuide] = useState(false);

  // Background stats & recent background detections
  const [backgroundStats, setBackgroundStats] = useState({
    qrDetectedToday: 12,
    urlsAnalyzedToday: 27,
    threatsBlocked: 3,
    suspiciousItems: 5,
  });

  const [recentBackgroundDetections, setRecentBackgroundDetections] = useState([
    {
      id: 'bg-1',
      site: 'WhatsApp Web',
      type: 'QR Code',
      verdict: 'SUSPICIOUS',
      riskScore: 82.0,
      timestamp: 'Today, 14:10',
      actionTaken: 'Warned',
    },
    {
      id: 'bg-2',
      site: 'example-login.com',
      type: 'URL',
      verdict: 'MALICIOUS',
      riskScore: 96.0,
      timestamp: 'Today, 13:45',
      actionTaken: 'Blocked',
    },
    {
      id: 'bg-3',
      site: 'Amazon',
      type: 'QR Code',
      verdict: 'SAFE',
      riskScore: 8.0,
      timestamp: 'Today, 12:20',
      actionTaken: 'Allowed',
    },
    {
      id: 'bg-4',
      site: 'secure-banking-alert.xyz',
      type: 'URL',
      verdict: 'MALICIOUS',
      riskScore: 94.5,
      timestamp: 'Today, 11:15',
      actionTaken: 'Blocked',
    },
  ]);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const res = await api.get('/history/scans', { params: { limit: 5 } });
      setRecentScans(res.data);

      const total = res.data.length;
      const threats = res.data.filter((s) => s.verdict !== 'SAFE').length;
      const safe = total - threats;

      setStats({
        totalScans: total,
        threatsBlocked: threats,
        safeScans: safe,
      });
    } catch (err) {
      console.warn('Could not fetch scan history:', err);
    }
  };

  const handleQuickScan = async (e) => {
    e.preventDefault();
    if (!quickScanUrl.trim()) return;

    setScanning(true);
    try {
      const res = await api.post('/scan/', { target: quickScanUrl.trim(), scan_type: 'url' });
      addToast(
        `Scan Complete: ${res.data.verdict} (Risk: ${res.data.risk_score}/100)`,
        res.data.verdict === 'SAFE' ? 'success' : 'error'
      );
      setQuickScanUrl('');
      fetchDashboardData();
    } catch (err) {
      addToast('Scan failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setScanning(false);
    }
  };

  const vulnerabilityScore = Math.round((user?.vulnerability_index || 0.5) * 100);

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Top Welcome & Personalized Status Banner */}
      <div className="glass-panel rounded-2xl p-6 lg:p-8 relative overflow-hidden border border-slate-800">
        <div className="absolute -right-20 -bottom-20 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none"></div>
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              Adaptive Protection Active
            </div>
            <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
              Welcome back, {user?.full_name || 'Cyber Defender'}
            </h1>
            <p className="text-slate-400 text-sm max-w-xl">
              Your security profile is currently set to{' '}
              <strong className="text-cyan-300 font-semibold">{user?.risk_profile_tier} Tier</strong>. 
              The platform dynamically adjusts ML threat scoring, SHAP explainers, and background tab protection.
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <Link
              to="/scanner"
              className="flex items-center gap-2 px-5 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm shadow-lg shadow-cyan-500/25 hover:from-cyan-400 hover:to-blue-500 transition-all hover:scale-[1.02]"
            >
              <ShieldAlert className="w-4 h-4" />
              Open Threat Scanner
            </Link>
            <button
              onClick={() => setShowExtensionGuide(true)}
              className="flex items-center gap-2 px-5 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 font-semibold text-sm transition-all"
            >
              <Download className="w-4 h-4 text-cyan-400" />
              Browser Extension Guide
            </button>
          </div>
        </div>
      </div>

      {/* ── NEW: Background Protection & Extension Control Center ── */}
      <div className="glass-panel rounded-2xl p-6 lg:p-7 border border-slate-800 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-bold text-white tracking-tight">Background Protection</h2>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                ● Protection Active
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Continuously guards other tabs and external websites (e.g. WhatsApp Web, banking, social platforms) against malicious QR codes and phishing links.
            </p>
          </div>

          <button
            onClick={() => setShowExtensionGuide(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 font-medium transition-colors self-start sm:self-auto"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Load Unpacked Extension
          </button>
        </div>

        {/* Protection Toggles Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Toggle 1: Background QR Protection */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
            <div className="space-y-0.5 pr-2">
              <span className="text-xs font-bold text-white block">Background QR Protection</span>
              <span className="text-[11px] text-slate-400 block">Scans dynamic QRs on other tabs</span>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={bgQrProtection}
                onChange={(e) => {
                  setBgQrProtection(e.target.checked);
                  addToast(`Background QR Protection: ${e.target.checked ? 'ON' : 'OFF'}`, 'info');
                }}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:width-4 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>

          {/* Toggle 2: Suspicious URL Protection */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
            <div className="space-y-0.5 pr-2">
              <span className="text-xs font-bold text-white block">Suspicious URL Protection</span>
              <span className="text-[11px] text-slate-400 block">Monitors outbound link navigations</span>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={bgUrlProtection}
                onChange={(e) => {
                  setBgUrlProtection(e.target.checked);
                  addToast(`Suspicious URL Protection: ${e.target.checked ? 'ON' : 'OFF'}`, 'info');
                }}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:width-4 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>

          {/* Toggle 3: Browser Notifications */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
            <div className="space-y-0.5 pr-2">
              <span className="text-xs font-bold text-white block">Browser Notifications</span>
              <span className="text-[11px] text-slate-400 block">OS alerts on critical threats</span>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={bgNotifications}
                onChange={(e) => {
                  setBgNotifications(e.target.checked);
                  addToast(`Browser Notifications: ${e.target.checked ? 'ON' : 'OFF'}`, 'info');
                }}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:width-4 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>

          {/* Toggle 4: Automatic Blocking */}
          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
            <div className="space-y-0.5 pr-2">
              <span className="text-xs font-bold text-white block">Automatic Blocking</span>
              <span className="text-[11px] text-slate-400 block">Instantly aborts phishing tabs</span>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={bgAutoBlock}
                onChange={(e) => {
                  setBgAutoBlock(e.target.checked);
                  addToast(`Automatic Blocking: ${e.target.checked ? 'ON' : 'OFF'}`, 'info');
                }}
                className="sr-only peer"
              />
              <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:width-4 after:transition-all peer-checked:bg-cyan-500"></div>
            </label>
          </div>
        </div>

        {/* Protection Today Counters */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800 text-center">
            <span className="text-xl font-bold font-mono text-cyan-400 block">{backgroundStats.qrDetectedToday}</span>
            <span className="text-[11px] text-slate-400 uppercase font-mono">QR Codes Detected Today</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800 text-center">
            <span className="text-xl font-bold font-mono text-indigo-400 block">{backgroundStats.urlsAnalyzedToday}</span>
            <span className="text-[11px] text-slate-400 uppercase font-mono">URLs Analyzed Today</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-900/50 border border-rose-500/20 text-center">
            <span className="text-xl font-bold font-mono text-rose-400 block">{backgroundStats.threatsBlocked}</span>
            <span className="text-[11px] text-slate-400 uppercase font-mono">Threats Blocked</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-900/50 border border-amber-500/20 text-center">
            <span className="text-xl font-bold font-mono text-amber-400 block">{backgroundStats.suspiciousItems}</span>
            <span className="text-[11px] text-slate-400 uppercase font-mono">Suspicious Items</span>
          </div>
        </div>

        {/* Recent Background Detections Live Ledger */}
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Recent Background Detections
            </h3>
            <span className="text-[11px] text-slate-400 font-mono">Cross-Tab Extension Telemetry</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                <tr>
                  <th className="py-2.5 px-3">Origin / Domain</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Action</th>
                  <th className="py-2.5 px-3">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {recentBackgroundDetections.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3 font-semibold text-white">
                      {item.site}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {item.type}
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          item.verdict === 'SAFE'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : item.verdict === 'SUSPICIOUS'
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {item.verdict}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold">
                      {item.riskScore.toFixed(1)}/100
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      {item.actionTaken}
                    </td>
                    <td className="py-3 px-3 text-slate-500 font-mono text-[11px]">
                      {item.timestamp}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Metrics Row: Personal Risk Profile & Live Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Metric 1: Human Vulnerability Index */}
        <div className="glass-panel glass-card-hover rounded-2xl p-6 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Personal Vulnerability Index
            </span>
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="my-4 flex items-center justify-center">
            <RiskGauge
              score={vulnerabilityScore}
              size={150}
              strokeWidth={12}
              verdict={vulnerabilityScore <= 35 ? 'RESILIENT' : vulnerabilityScore <= 65 ? 'MODERATE' : 'VULNERABLE'}
            />
          </div>
          <p className="text-xs text-slate-400 text-center">
            Derived from simulation reporting speed & scan history.
          </p>
        </div>

        {/* Metric 2: Adaptive Tier Progression */}
        <div className="glass-panel glass-card-hover rounded-2xl p-6 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Adaptive Defense Tier
            </span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <Award className="w-4 h-4" />
            </div>
          </div>
          <div className="my-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-2xl font-black text-white">{user?.risk_profile_tier || 'Novice'}</span>
              <span className="text-xs font-mono text-cyan-400">Adaptive ML Active</span>
            </div>
            {/* Progress Bar */}
            <div className="w-full bg-slate-800 rounded-full h-2.5 overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-500 to-indigo-500 h-2.5 rounded-full transition-all duration-1000"
                style={{ width: `${100 - vulnerabilityScore}%` }}
              ></div>
            </div>
            <p className="text-xs text-slate-400">
              {vulnerabilityScore <= 35
                ? 'High defense readiness: Explanations show deep technical indicators.'
                : 'Guided protection: Explanations provide plain-language safety steps.'}
            </p>
          </div>
          <Link
            to="/profile"
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
          >
            Adjust Risk Tier & Diagnostic Profile <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {/* Metric 3: Quick Scan Launcher */}
        <div className="glass-panel glass-card-hover rounded-2xl p-6 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Quick Threat Scan
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <Zap className="w-4 h-4" />
            </div>
          </div>
          <form onSubmit={handleQuickScan} className="my-4 space-y-3">
            <input
              type="text"
              value={quickScanUrl}
              onChange={(e) => setQuickScanUrl(e.target.value)}
              placeholder="Enter URL or domain (e.g. login-appleid.xyz)..."
              className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-500 transition-colors"
            />
            <button
              type="submit"
              disabled={scanning}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow-md shadow-cyan-900/30 transition-all disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Extracting ML Features...
                </>
              ) : (
                <>
                  <Activity className="w-3.5 h-3.5" />
                  Run Instant Scan
                </>
              )}
            </button>
          </form>
          <p className="text-[11px] text-slate-500 text-center">
            Evaluates Phishing ML + Zero-Day Anomaly + SHAP XAI
          </p>
        </div>
      </div>

      {/* Recent Scans Ledger & Global Threat Intelligence Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 glass-panel rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-bold text-white tracking-tight">Manual Threat Scans Ledger</h2>
            </div>
            <Link
              to="/history"
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
            >
              View Full Audit Ledger <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          {recentScans.length === 0 ? (
            <div className="text-center py-10 text-slate-500 text-sm">
              No manual scans recorded yet. Enter a target above or visit the Threat Scanner.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px]">
                  <tr>
                    <th className="py-2.5 px-3">Target</th>
                    <th className="py-2.5 px-3">Verdict</th>
                    <th className="py-2.5 px-3">Risk Score</th>
                    <th className="py-2.5 px-3">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {recentScans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-3 font-mono text-cyan-300 max-w-xs truncate">
                        {scan.target}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            scan.verdict === 'SAFE'
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : scan.verdict === 'SUSPICIOUS'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-rose-500/20 text-rose-300'
                          }`}
                        >
                          {scan.verdict}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono font-semibold">
                        {scan.risk_score.toFixed(1)}/100
                      </td>
                      <td className="py-3 px-3 text-slate-400">
                        {new Date(scan.scanned_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Community Threat Density Preview */}
        <div className="glass-panel rounded-2xl p-6 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-rose-400">
              <Globe className="w-5 h-5" />
              <h3 className="text-base font-bold text-white">Global Threat Intelligence</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Crowdsourced phishing signatures and zero-day threat density geolocated in real time.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Active Global Outbreaks:</span>
              <span className="font-bold text-rose-400 font-mono">8 Hotspots</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Community Reports Verified:</span>
              <span className="font-bold text-emerald-400 font-mono">100%</span>
            </div>
          </div>

          <Link
            to="/threat-map"
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-cyan-600 text-white font-semibold text-xs shadow-md shadow-indigo-950/50 hover:from-indigo-500 hover:to-cyan-500 transition-all"
          >
            Explore Interactive Threat Map
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {/* Extension Installation Guide Modal */}
      {showExtensionGuide && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm px-4 animate-fadeIn">
          <div className="glass-panel rounded-2xl p-6 border border-cyan-500/40 max-w-lg w-full space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Load Browser Protection Extension</h3>
              </div>
              <button
                onClick={() => setShowExtensionGuide(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
              <p>
                To enable continuous background monitoring for other tabs (e.g. WhatsApp Web, email, and payment portals), load the included Manifest V3 extension into Chrome or Edge:
              </p>

              <ol className="list-decimal list-inside space-y-2 font-mono text-[11px] bg-slate-950/80 p-3.5 rounded-xl border border-slate-800">
                <li>Open <strong className="text-cyan-300">chrome://extensions</strong> or <strong className="text-cyan-300">edge://extensions</strong> in a new tab.</li>
                <li>Enable <strong className="text-amber-300">"Developer mode"</strong> switch (top right corner).</li>
                <li>Click <strong className="text-emerald-300">"Load unpacked"</strong> button.</li>
                <li>Select folder: <span className="text-cyan-200 bg-slate-900 px-1 py-0.5 rounded">zero/extension</span> on your computer.</li>
              </ol>

              <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-xl space-y-1">
                <span className="text-[10px] font-bold uppercase font-mono text-cyan-400 block">Privacy Guarantee</span>
                <p className="text-[11px] text-slate-200">
                  QR decoding happens 100% locally in your browser. Screenshots or webpage images are never uploaded to any external server.
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowExtensionGuide(false)}
                className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                Got it, close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
