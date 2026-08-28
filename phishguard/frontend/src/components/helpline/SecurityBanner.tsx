import React from 'react';
import { Lock, ShieldAlert } from 'lucide-react';

export const SecurityBanner: React.FC = () => {
  return (
    <div className="w-full rounded-2xl bg-gradient-to-r from-amber-500/10 via-slate-900/80 to-cyan-500/10 border border-amber-500/30 p-3.5 sm:p-4 flex items-start sm:items-center justify-between gap-3 shadow-lg shadow-black/40 animate-fadeIn">
      <div className="flex items-start sm:items-center gap-3">
        <div className="w-8 h-8 rounded-xl bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0 mt-0.5 sm:mt-0">
          <Lock className="w-4 h-4" />
        </div>
        <div>
          <span className="text-[11px] sm:text-xs font-bold text-amber-300 flex items-center gap-1.5">
            <span>Security Rule:</span>
          </span>
          <p className="text-[11px] sm:text-xs text-slate-300 leading-relaxed mt-0.5">
            The AI Helpline will <strong className="text-white font-semibold">never</strong> ask for your passwords, OTPs, PINs, or CVVs. Never disclose sensitive secrets in chat.
          </p>
        </div>
      </div>

      <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-900/90 border border-slate-700/80 text-[10px] font-mono text-cyan-400 shrink-0">
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
        <span>E2E Guardrails Active</span>
      </div>
    </div>
  );
};

export default SecurityBanner;
