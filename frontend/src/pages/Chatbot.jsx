import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import {
  MessageSquareCode,
  Send,
  Bot,
  User,
  ShieldAlert,
  Sparkles,
  HelpCircle,
  AlertTriangle,
  Lightbulb,
} from 'lucide-react';

const Chatbot = () => {
  const { user } = useAuth();
  const { addToast } = useThreat();

  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: `Hello ${user?.full_name?.split(' ')[0] || 'Defender'}! I am your AI Cyber-Safety Advisor. You can ask me about suspicious emails, SMS smishing, deepfake voices, crypto investment safety, or paste a link/message for instant risk consultation.`,
      detectedThreats: ['System Ready'],
      recommendedAction: 'Ask any cybersecurity question or paste suspicious communication.',
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(null);

  const messagesEndRef = useRef(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const quickPrompts = [
    'How do I spot an SMS parcel delivery smishing scam?',
    'Someone claiming to be my CEO asked for urgent gift cards.',
    'Is it possible for scammers to clone a voice using AI deepfakes?',
    'What should I do if I entered my password on a suspicious site?',
  ];

  const handleSendMessage = async (msgText = null) => {
    const text = msgText || inputMessage;
    if (!text.trim() || loading) return;

    const userMsg = { role: 'user', content: text };
    setMessages((prev) => [...prev, userMsg]);
    if (!msgText) setInputMessage('');
    setLoading(true);

    try {
      const res = await api.post('/chat/', {
        message: text,
        session_id: sessionId,
      });

      setSessionId(res.data.session_id);
      const assistantMsg = {
        role: 'assistant',
        content: res.data.response,
        detectedThreats: res.data.detected_threats,
        recommendedAction: res.data.recommended_action,
        sources: res.data.sources,
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      addToast('Chat error: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-4 lg:px-8 py-8 space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            Domain-Trained Cyber Advisor
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            AI Cyber-Safety Interactive Assistant
          </h1>
        </div>
        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-xl border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          Threat Corpus Online
        </div>
      </div>

      {/* Main Chat Interface */}
      <div className="glass-panel rounded-2xl border border-slate-800 flex flex-col h-[600px] overflow-hidden">
        {/* Messages Scroll Area */}
        <div className="flex-1 p-6 overflow-y-auto space-y-4">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex items-start gap-3 ${
                msg.role === 'user' ? 'justify-end' : 'justify-start'
              }`}
            >
              {msg.role === 'assistant' && (
                <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white shrink-0 shadow-md shadow-cyan-500/20">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div
                className={`max-w-xl rounded-2xl p-4 space-y-2 text-sm leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-tr-none'
                    : 'bg-slate-900/90 text-slate-200 border border-slate-800 rounded-tl-none'
                }`}
              >
                <p>{msg.content}</p>

                {/* Assistant Advice & Threat Tag Pills */}
                {msg.role === 'assistant' && msg.recommendedAction && (
                  <div className="pt-2 border-t border-slate-800/80 space-y-2">
                    {msg.detectedThreats && (
                      <div className="flex flex-wrap gap-1.5">
                        {msg.detectedThreats.map((threat, tIdx) => (
                          <span
                            key={tIdx}
                            className="px-2 py-0.5 rounded-md bg-rose-500/10 text-rose-300 border border-rose-500/30 text-[10px] font-mono"
                          >
                            {threat}
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 flex items-start gap-2">
                      <Lightbulb className="w-4 h-4 shrink-0 mt-0.5 text-amber-400" />
                      <span>{msg.recommendedAction}</span>
                    </div>
                  </div>
                )}
              </div>

              {msg.role === 'user' && (
                <div className="w-8 h-8 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 shrink-0 uppercase font-bold text-xs">
                  {user?.full_name?.charAt(0) || 'U'}
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-cyan-500/20 text-cyan-400 flex items-center justify-center animate-pulse">
                <Bot className="w-4 h-4" />
              </div>
              <div className="px-4 py-3 bg-slate-900 rounded-2xl text-xs text-slate-400 font-mono flex items-center gap-2 border border-slate-800">
                <span className="animate-spin w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full"></span>
                Evaluating threat context against cybersecurity corpus...
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Suggested Quick Prompts */}
        <div className="p-3 bg-slate-950/60 border-t border-slate-800/80 flex items-center gap-2 overflow-x-auto">
          <span className="text-[10px] text-slate-500 font-mono shrink-0">Quick Queries:</span>
          {quickPrompts.map((prompt, pIdx) => (
            <button
              key={pIdx}
              onClick={() => handleSendMessage(prompt)}
              className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-cyan-300 text-xs border border-slate-800 hover:border-cyan-500/30 shrink-0 transition-colors"
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="p-4 bg-slate-950 border-t border-slate-800 flex items-center gap-3"
        >
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Ask a security question, paste a link or describe a suspicious message..."
            className="flex-1 px-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 transition-colors"
          />
          <button
            type="submit"
            disabled={!inputMessage.trim() || loading}
            className="p-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20 disabled:opacity-50 transition-all"
          >
            <Send className="w-5 h-5" />
          </button>
        </form>
      </div>
    </div>
  );
};

export default Chatbot;
