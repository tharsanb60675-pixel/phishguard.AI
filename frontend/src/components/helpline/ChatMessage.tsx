import React, { useState } from 'react';
import { Bot, User, Copy, Check, ShieldCheck, ShieldAlert, AlertTriangle, Info, Sparkles } from 'lucide-react';
import { ChatMessage as ChatMessageType } from '../../types/chat';

interface ChatMessageProps {
  message: ChatMessageType;
  onCopy?: (text: string) => void;
}

export const ChatMessage: React.FC<ChatMessageProps> = ({ message, onCopy }) => {
  const isUser = message.sender === 'user';
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(message.text);
    setCopied(true);
    if (onCopy) onCopy(message.text);
    setTimeout(() => setCopied(false), 2000);
  };

  // Simple Markdown-style formatter (handles bold, code snippets, lists, and tables cleanly)
  const formatMessageContent = (content: string) => {
    const lines = content.split('\n');
    return lines.map((line, idx) => {
      // Headers
      if (line.startsWith('### ')) {
        return (
          <h4 key={idx} className="text-sm font-bold text-cyan-300 mt-2 mb-1">
            {line.replace('### ', '')}
          </h4>
        );
      }
      if (line.startsWith('## ')) {
        return (
          <h3 key={idx} className="text-base font-extrabold text-white mt-3 mb-1.5">
            {line.replace('## ', '')}
          </h3>
        );
      }
      // Bullet points
      if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
        const itemText = line.trim().substring(2);
        return (
          <li key={idx} className="flex items-start gap-2 ml-1 text-slate-300 text-xs sm:text-sm">
            <span className="text-cyan-400 font-bold leading-5">•</span>
            <span>{renderFormattedText(itemText)}</span>
          </li>
        );
      }
      // Divider
      if (line.trim() === '---') {
        return <hr key={idx} className="border-slate-800 my-2" />;
      }
      // Empty line
      if (!line.trim()) {
        return <div key={idx} className="h-1.5" />;
      }

      return (
        <p key={idx} className="text-xs sm:text-sm leading-relaxed text-slate-200">
          {renderFormattedText(line)}
        </p>
      );
    });
  };

  const renderFormattedText = (text: string) => {
    // Replace **bold** with strong elements
    const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={i} className="text-white font-bold">
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code key={i} className="px-1.5 py-0.5 rounded bg-slate-950/80 border border-slate-700/80 text-cyan-300 font-mono text-[11px]">
            {part.slice(1, -1)}
          </code>
        );
      }
      return part;
    });
  };

  return (
    <div
      className={`flex items-start gap-3 w-full animate-fadeIn ${
        isUser ? 'flex-row-reverse justify-start' : 'justify-start'
      }`}
    >
      {/* Avatar */}
      <div
        className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 shadow-md ${
          isUser
            ? 'bg-gradient-to-tr from-cyan-600 to-cyan-400 text-black font-bold'
            : 'bg-gradient-to-tr from-blue-700 to-cyan-600 text-white border border-cyan-400/40'
        }`}
      >
        {isUser ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
      </div>

      {/* Bubble Container */}
      <div
        className={`max-w-[85%] sm:max-w-[78%] rounded-2xl p-4 sm:p-5 relative group transition-all ${
          isUser
            ? 'bg-gradient-to-br from-cyan-600 to-blue-700 text-white rounded-tr-sm shadow-xl shadow-cyan-950/30'
            : 'bg-slate-900/90 border border-slate-800 text-slate-100 rounded-tl-sm shadow-2xl shadow-black/40 hover:border-slate-700/80'
        }`}
      >
        {/* Top Header for AI Message */}
        {!isUser && (
          <div className="flex items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5 mb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                PhishGuard Assistant
              </span>
              {message.isLiveAi && (
                <span className="px-2 py-0.5 rounded-full text-[9px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 font-bold">
                  ● LIVE AI
                </span>
              )}
            </div>

            {/* Copy Button */}
            <button
              onClick={handleCopy}
              className="p-1 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors text-[10px] flex items-center gap-1"
              title="Copy message text"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        )}

        {/* Message Body */}
        <div className="space-y-2">{formatMessageContent(message.text)}</div>

        {/* Bottom Footer: Timestamp & Sources */}
        <div
          className={`flex items-center justify-between gap-3 text-[10px] mt-3 pt-2 border-t ${
            isUser ? 'border-cyan-500/30 text-cyan-100/80' : 'border-slate-800/60 text-slate-500'
          }`}
        >
          <span className="font-mono">{message.timestamp}</span>

          {!isUser && message.sources && message.sources.length > 0 && (
            <span className="font-mono truncate max-w-[200px]" title={message.sources.join(', ')}>
              Source: {message.sources[0]}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

export default ChatMessage;
