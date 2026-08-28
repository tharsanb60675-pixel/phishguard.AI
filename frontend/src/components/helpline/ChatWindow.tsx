import React, { useRef, useEffect } from 'react';
import { Bot, Trash2, Radio, MessageSquare, Sparkles } from 'lucide-react';
import { ChatMessage as ChatMessageType } from '../../types/chat';
import ChatMessage from './ChatMessage';
import TypingIndicator from './TypingIndicator';

interface ChatWindowProps {
  messages: ChatMessageType[];
  loading: boolean;
  onClearClick: () => void;
  messageCount: number;
}

export const ChatWindow: React.FC<ChatWindowProps> = ({
  messages,
  loading,
  onClearClick,
  messageCount,
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  // Smooth auto-scroll to latest message
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, loading]);

  return (
    <div className="w-full flex-1 flex flex-col glass-panel rounded-3xl border border-slate-800 shadow-2xl overflow-hidden min-h-[500px] max-h-[680px]">
      {/* Session Top Bar */}
      <div className="px-5 py-4 bg-slate-900/90 border-b border-slate-800/80 flex items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-white tracking-wide">
                Live Cybersecurity Assistant Session
              </h2>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-bold">
                {messageCount} {messageCount === 1 ? 'Message' : 'Messages'}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>AI Threat Helpline Active</span>
            </div>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={onClearClick}
            disabled={messages.length <= 1 && !loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800/60 hover:bg-rose-500/20 text-slate-400 hover:text-rose-300 border border-slate-700/60 hover:border-rose-500/40 text-xs font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            title="Clear current conversation"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Clear Chat</span>
          </button>
        </div>
      </div>

      {/* Messages Scroll Viewport */}
      <div
        ref={scrollRef}
        className="flex-1 p-4 sm:p-6 overflow-y-auto space-y-4 sm:space-y-5 bg-[#080c14]/60 scroll-smooth"
      >
        {messages.map((msg) => (
          <ChatMessage key={msg.id} message={msg} />
        ))}

        {loading && <TypingIndicator />}
      </div>
    </div>
  );
};

export default ChatWindow;
