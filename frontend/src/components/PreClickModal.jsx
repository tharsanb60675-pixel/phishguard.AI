import React from 'react';
import { useThreat } from '../context/ThreatContext';
import { ShieldAlert, AlertTriangle, ExternalLink, X, ArrowLeft } from 'lucide-react';

const PreClickModal = () => {
  const { preClickModalState, closePreClickModal } = useThreat();

  if (!preClickModalState.isOpen) return null;

  const { url, data, onProceed } = preClickModalState;

  const handleProceedAnyway = () => {
    closePreClickModal();
    if (onProceed) onProceed();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div className="relative w-full max-w-lg bg-slate-900 border-2 border-rose-500/80 rounded-2xl shadow-2xl shadow-rose-900/40 overflow-hidden">
        {/* Top Warning Banner */}
        <div className="bg-rose-500/10 border-b border-rose-500/30 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-rose-500/20 text-rose-400">
              <ShieldAlert className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white tracking-tight">
                Pre-Click Threat Interceptor
              </h3>
              <p className="text-xs text-rose-300 font-mono">
                HIGH-RISK DESTINATION DETECTED
              </p>
            </div>
          </div>
          <button
            onClick={closePreClickModal}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-4">
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 break-all font-mono text-xs text-cyan-300">
            <span className="text-slate-500 block mb-1 uppercase text-[10px] tracking-wider">
              Intercepted Target URL:
            </span>
            {url}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-300 font-medium">Model Threat Score:</span>
              <span className="font-bold text-rose-400 font-mono text-base">
                {data?.risk_score || 85}/100 ({data?.verdict || 'MALICIOUS'})
              </span>
            </div>

            <div className="p-4 bg-slate-800/60 rounded-xl border border-slate-700/60 text-sm text-slate-200">
              <p className="font-semibold text-rose-300 flex items-center gap-1.5 mb-1">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Why this was blocked:
              </p>
              <p className="text-slate-300 text-xs leading-relaxed">
                {data?.explanation_summary ||
                  'The target exhibits characteristics of credential phishing and zero-day domain spoofing.'}
              </p>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="pt-2 flex flex-col sm:flex-row gap-3">
            <button
              onClick={closePreClickModal}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 text-white font-semibold shadow-lg shadow-emerald-900/30 hover:from-emerald-500 hover:to-teal-500 transition-all text-sm"
            >
              <ArrowLeft className="w-4 h-4" />
              Return to Safety (Recommended)
            </button>

            <button
              onClick={handleProceedAnyway}
              className="px-4 py-3 rounded-xl bg-slate-800 hover:bg-rose-950/40 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-500/40 transition-colors text-xs font-mono"
            >
              Bypass Shield (Unsafe)
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PreClickModal;
