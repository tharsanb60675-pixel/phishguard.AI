import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import RiskGauge from '../components/RiskGauge';
import ShapWaterfallChart from '../components/ShapWaterfallChart';
import { isValidUrl } from '../utils/urlValidator';
import {
  ShieldAlert,
  Search,
  Globe,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Zap,
  Info,
  Clock,
  Sparkles,
  Layers,
  ChevronRight,
  XCircle,
} from 'lucide-react';

const Scanner = () => {
  const { user } = useAuth();
  const { addToast, triggerPreClickCheck } = useThreat();

  const [targetInput, setTargetInput] = useState('');
  const [validationError, setValidationError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  // Strictly validated complete URL quick test presets
  const samplePresets = [
    {
      label: 'Brand Phishing (Apple ID)',
      val: 'https://login-appleid-verify-token.account-security-alert.xyz/auth',
    },
    {
      label: 'Zero-Day DGA Anomaly',
      val: 'https://xk92-m09-auth.secure-update-node78.top/login',
    },
    {
      label: 'Legitimate Domain (Google)',
      val: 'https://google.com/search?q=cybersecurity',
    },
    {
      label: 'Suspicious Banking Portal',
      val: 'https://secure-login-verify-account.bank-security.xyz/auth',
    },
  ];

  const handleScan = async (e) => {
    if (e) e.preventDefault();

    const trimmed = targetInput.trim();

    // 1. Strict URL Validation before ANY threat analysis or API call
    if (!trimmed || !isValidUrl(trimmed)) {
      setValidationError('It is not a valid URL');
      setScanResult(null);
      return;
    }

    // 2. Clear any prior validation error and start analysis
    setValidationError(null);
    setLoading(true);
    setScanResult(null);

    try {
      // 3. Send validated URL to backend threat analysis engine
      const res = await api.post('/scan/', {
        target: trimmed,
        scan_type: 'url',
      });

      setScanResult(res.data);
      addToast(
        `Threat Scan Complete: ${res.data.verdict} (${res.data.risk_score.toFixed(1)}/100)`,
        res.data.verdict === 'SAFE' ? 'success' : 'error'
      );
    } catch (err) {
      addToast('Scan failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    setTargetInput(e.target.value);
    // Clear validation error when user begins correcting the input
    if (validationError) {
      setValidationError(null);
    }
  };

  const handleSelectPreset = (presetUrl) => {
    setTargetInput(presetUrl);
    setValidationError(null);
  };

  const handlePreClickTest = () => {
    const trimmed = targetInput.trim();
    if (!trimmed || !isValidUrl(trimmed)) {
      setValidationError('It is not a valid URL');
      setScanResult(null);
      return;
    }

    setValidationError(null);
    triggerPreClickCheck(trimmed, () => {
      addToast('Pre-click check passed: Destination URL allowed.', 'success');
    });
  };

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            Multi-Model AI Threat Scanner
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            Analyze Destination URLs & Web Threat Vectors
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Real-time zero-day quishing, brand impersonation, and phishing heuristic inspection.
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-400">
          <Globe className="w-4 h-4" />
          <span>Strict URL Mode (HTTP / HTTPS)</span>
        </div>
      </div>

      {/* Input Box & Presets */}
      <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-4 shadow-xl">
        <form onSubmit={handleScan} className="space-y-4">
          <div className="space-y-2">
            <div className="relative">
              <input
                type="text"
                value={targetInput}
                onChange={handleInputChange}
                placeholder="Enter complete URL (e.g. https://example.com/login)..."
                className={`w-full pl-11 pr-32 py-4 rounded-xl bg-slate-950/80 text-slate-100 placeholder-slate-500 text-sm font-mono focus:outline-none transition-all ${
                  validationError
                    ? 'border-2 border-rose-500/80 focus:border-rose-500 focus:ring-2 focus:ring-rose-500/20'
                    : 'border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500'
                }`}
              />
              <Search className="w-5 h-5 text-slate-500 absolute left-4 top-4" />
            </div>

            {/* Strict Validation Error Notice */}
            {validationError && (
              <div className="flex items-start gap-2.5 p-3 rounded-xl bg-rose-500/10 border border-rose-500/40 text-rose-300 animate-fadeIn">
                <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-bold text-rose-200">
                    {validationError}
                  </div>
                  <div className="text-[11px] text-rose-300/80 mt-0.5">
                    Please enter a complete URL starting with <code className="bg-slate-950 px-1 py-0.5 rounded font-mono text-cyan-300">http://</code> or <code className="bg-slate-950 px-1 py-0.5 rounded font-mono text-cyan-300">https://</code>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] text-slate-400 font-mono">Test Presets:</span>
              {samplePresets.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSelectPreset(preset.val)}
                  className="px-2.5 py-1 rounded-lg text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 hover:border-cyan-500/40 transition-colors font-mono"
                >
                  {preset.label}
                </button>
              ))}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handlePreClickTest}
                className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition-colors"
              >
                Simulate Pre-Click Intercept
              </button>

              <button
                type="submit"
                disabled={loading}
                className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50 active:scale-95"
              >
                {loading ? 'Evaluating AI Models...' : 'Run Deep Threat Analysis'}
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* URL SCAN RESULTS & SHAP EXPLANATION */}
      {scanResult && !validationError && (
        <div className="space-y-6 animate-fadeIn">
          {/* Top Verdict Overview Card */}
          <div
            className={`glass-panel rounded-2xl p-6 border ${
              scanResult.verdict === 'SAFE'
                ? 'border-emerald-500/40 bg-emerald-950/10'
                : scanResult.verdict === 'SUSPICIOUS'
                ? 'border-amber-500/40 bg-amber-950/10'
                : 'border-rose-500/40 bg-rose-950/10'
            }`}
          >
            <div className="flex flex-col lg:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-6">
                <RiskGauge
                  score={scanResult.risk_score}
                  size={150}
                  strokeWidth={12}
                  verdict={scanResult.verdict}
                />
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider ${
                        scanResult.verdict === 'SAFE'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : scanResult.verdict === 'SUSPICIOUS'
                          ? 'bg-amber-500/20 text-amber-300'
                          : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {scanResult.verdict} THREAT
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Severity: {scanResult.risk_level}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold text-white font-mono break-all max-w-xl">
                    {scanResult.target}
                  </h2>
                  <p className="text-xs text-slate-400 font-mono flex items-center gap-4">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      Inference: {scanResult.execution_time_ms}ms
                    </span>
                    <span>•</span>
                    <span>Target Type: {scanResult.scan_type.toUpperCase()}</span>
                  </p>
                </div>
              </div>

              {/* Multi-Model Breakdown Badges */}
              <div className="grid grid-cols-2 gap-3 w-full lg:w-auto font-mono text-xs">
                <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Phishing Classifier:</span>
                  <span className="font-bold text-white text-sm">
                    {(scanResult.breakdown.phishing_probability * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Zero-Day Anomaly:</span>
                  <span className="font-bold text-white text-sm">
                    {(scanResult.breakdown.zero_day_anomaly_score * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Social Eng Score:</span>
                  <span className="font-bold text-white text-sm">
                    {(scanResult.breakdown.social_engineering_score * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">User Tier Modifier:</span>
                  <span className="font-bold text-cyan-400 text-sm">
                    {scanResult.breakdown.user_risk_modifier}x ({user?.risk_profile_tier})
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Explainable AI (SHAP) Section */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Plain-Language Personalized Explanation */}
            <div className="lg:col-span-5 glass-panel rounded-2xl p-6 space-y-4">
              <div className="flex items-center gap-2 text-cyan-400">
                <Sparkles className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">
                  Personalized AI Explanation
                </h3>
              </div>

              <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2">
                <span className="text-[10px] uppercase font-mono tracking-wider text-cyan-400 block">
                  Tailored for {scanResult.explanation.user_understanding_level} Tier:
                </span>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {scanResult.explanation.personalized_explanation}
                </p>
              </div>

              {/* Actionable Advice & Remediation */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Actionable Advice:
                </h4>
                <p className="text-xs text-amber-300 font-medium bg-amber-500/10 p-3 rounded-lg border border-amber-500/30">
                  {scanResult.explanation.actionable_advice}
                </p>
              </div>

              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                  Remediation Steps:
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

            {/* SHAP Waterfall Chart */}
            <div className="lg:col-span-7 glass-panel rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-indigo-400">
                  <Layers className="w-5 h-5" />
                  <h3 className="text-base font-bold text-white">
                    SHAP Factor Contribution Breakdown
                  </h3>
                </div>
                <span className="text-xs text-slate-400 font-mono">TreeSHAP XAI Engine</span>
              </div>

              <p className="text-xs text-slate-400">
                Visualizes the mathematical weight that each lexical and behavioral feature contributed to shifting the prediction from the baseline model prior.
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
    </div>
  );
};

export default Scanner;
