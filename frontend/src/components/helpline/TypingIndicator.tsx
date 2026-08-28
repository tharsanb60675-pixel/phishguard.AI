import React from 'react';
import { Bot, Sparkles } from 'lucide-react';

export const TypingIndicator: React.FC = () => {
  return (
    <div className="flex items-start gap-3 animate-fadeIn">
      {/* Bot Avatar */}
      <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 border border-cyan-400/40 flex items-center justify-center text-white shadow-md shadow-cyan-500/20 shrink-0">
        <Bot className="w-4 h-4" />
      </div>

      {/* Typing Bubble */}
      <div className="rounded-2xl rounded-tl-sm bg-slate-900/90 border border-cyan-500/30 p-3.5 shadow-xl shadow-cyan-950/20 max-w-[85%] sm:max-w-md">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0ms' }}></span>
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '150ms' }}></span>
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '300ms' }}></span>
          </div>
          <span className="text-xs font-mono font-bold text-cyan-300 flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-cyan-400 animate-spin" />
            AI is analyzing...
          </span>
        </div>
      </div>
    </div>
  );
};

export default TypingIndicator;
