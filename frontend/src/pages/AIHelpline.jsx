import React, { useState, useEffect } from 'react';
import { useThreat } from '../context/ThreatContext';
import { sendMessage } from '../services/aiService';
import SecurityBanner from '../components/helpline/SecurityBanner';
import ChatWindow from '../components/helpline/ChatWindow';
import QuickActions from '../components/helpline/QuickActions';
import ChatInput from '../components/helpline/ChatInput';
import ClearChatModal from '../components/helpline/ClearChatModal';
import { Bot, Sparkles, ShieldAlert, Cpu } from 'lucide-react';

const INITIAL_WELCOME_MESSAGE = {
  id: 'welcome-default',
  sender: 'ai',
  text: `Hi! I'm your **PhishGuard AI Helpline**.\n\nI can help you check suspicious QR codes, URLs, messages, emails, SMS, WhatsApp messages, payment requests, and social-engineering attacks.\n\nHow can I help you today?`,
  timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  threatLevel: 'INFO',
  isLiveAi: false,
  sources: ['PhishGuard AI Safety Engine'],
};

export const AIHelpline = () => {
  const { scanContext, addToast } = useThreat();

  const [messages, setMessages] = useState([INITIAL_WELCOME_MESSAGE]);
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState(`sess_${Date.now()}`);
  const [showClearModal, setShowClearModal] = useState(false);

  // Initialize or update with scan context if arriving from scanner
  useEffect(() => {
    if (scanContext) {
      const isBgAlert = scanContext.type === 'Background Protection Alert' || scanContext.sourceApp;
      const codeType = scanContext.formatName || scanContext.type || 'Scanned Target';
      const risk = scanContext.riskScore || 0;
      const verdict = scanContext.verdict || 'UNKNOWN';

      let contextIntro = '';
      if (isBgAlert) {
        contextIntro = `I analyzed the item intercepted by **PhishGuard Background Protection**:\n\n` +
          `• **Source:** ${scanContext.sourceApp || 'Screen Scan'}\n` +
          `• **Threat Level:** ${verdict}\n` +
          `• **Risk Score:** ${risk.toFixed(1)} / 100\n` +
          `• **Probability:** ${scanContext.threatProbability ? scanContext.threatProbability.toFixed(0) + '%' : 'N/A'}\n` +
          `• **Classification:** ${scanContext.threatCategory || 'Potential Threat'}\n` +
          (scanContext.messageContent ? `• **Message Preview:** _"${scanContext.messageContent}"_\n` : '') +
          (scanContext.detectedUrl ? `• **Detected URL:** \`${scanContext.detectedUrl}\`\n` : '') +
          (scanContext.qrContent ? `• **Decoded QR:** \`${scanContext.qrContent}\`\n` : '') +
          `\n`;
      } else {
        contextIntro = `I analyzed the item you just scanned.\n\n` +
          `• **Target Type:** ${codeType}\n` +
          `• **Verdict:** ${verdict}\n` +
          `• **Risk Score:** ${risk.toFixed(1)} / 100\n` +
          `• **Target:** \`${scanContext.rawValue || scanContext.target}\`\n\n`;
      }

      if (verdict === 'MALICIOUS' || verdict === 'CRITICAL' || risk >= 70 || verdict === 'HIGH RISK') {
        contextIntro += `⚠️ **Critical Threat Alert:** This item appears to be a high-risk security threat. Ask me why it is dangerous or what containment steps you should take.`;
      } else if (verdict === 'SUSPICIOUS' || risk >= 40 || verdict === 'MEDIUM RISK') {
        contextIntro += `⚠️ **Caution:** Elevated risk characteristics detected. You can ask me to explain these indicators or how to verify the sender safely.`;
      } else {
        contextIntro += `✓ **Verified Safe:** No known malicious signatures, scam indicators, or phishing matches detected. Ask me any security questions about this content.`;
      }

      setMessages([
        {
          id: `scan-context-${Date.now()}`,
          sender: 'ai',
          text: contextIntro,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          threatLevel: verdict === 'MALICIOUS' || verdict === 'CRITICAL' || verdict === 'HIGH RISK' || risk >= 70 ? 'CRITICAL' : verdict === 'SUSPICIOUS' || verdict === 'MEDIUM RISK' ? 'HIGH' : 'SAFE',
          isLiveAi: false,
          sources: ['PhishGuard Threat Intelligence Engine'],
        },
      ]);
    }
  }, [scanContext]);

  // Main message sender using aiService adapter
  const handleSendMessage = async (textToSend) => {
    const query = textToSend.trim();
    if (!query || loading) return;

    const userMsg = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    // 1. Immediately append user message to UI
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    setLoading(true);

    try {
      // 2. Call configured AI API service adapter
      const aiResponse = await sendMessage(query, updatedMessages, scanContext, sessionId);

      // 3. Append AI response
      const aiMsg = {
        id: `ai-${Date.now()}`,
        sender: 'ai',
        text: aiResponse.response,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        threatLevel: aiResponse.threat_level || 'INFO',
        isLiveAi: aiResponse.is_live_ai ?? true,
        sources: aiResponse.sources || ['PhishGuard AI Helpline'],
        detectedThreats: aiResponse.detected_threats,
        recommendedAction: aiResponse.recommended_action,
      };

      setMessages((prev) => [...prev, aiMsg]);
      if (aiResponse.session_id) {
        setSessionId(aiResponse.session_id);
      }
    } catch (err) {
      console.error('[PhishGuard AI Helpline] Error generating response:', err);
      const fallbackMsg = {
        id: `ai-err-${Date.now()}`,
        sender: 'ai',
        text: "I'm temporarily unable to reach the cybersecurity AI service. Please try again in a moment.\n\n**Immediate Safety Notice:** Never share passwords, OTPs, or financial details with unverified contacts.",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        threatLevel: 'INFO',
        isLiveAi: false,
      };
      setMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setLoading(false);
    }
  };

  // Clear conversation handler
  const handleConfirmClear = () => {
    setMessages([INITIAL_WELCOME_MESSAGE]);
    setSessionId(`sess_${Date.now()}`);
    setShowClearModal(false);
    addToast('Conversation history cleared.', 'info');
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-5 animate-fadeIn min-h-[calc(100vh-80px)] flex flex-col justify-between">
      {/* 1. Page Header & Security Notice */}
      <div className="space-y-3 shrink-0">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
              <Bot className="w-4 h-4" />
              <span>AI CYBERSECURITY INCIDENT HELPLINE</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2.5">
              <span>PhishGuard AI Helpline</span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-bold hidden sm:inline-flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-cyan-400" />
                24/7 Threat Assistant
              </span>
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
              Get immediate expert guidance on suspicious messages, phishing URLs, fake bank alerts, and social engineering.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="px-3 py-1.5 rounded-xl bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Model: <strong className="text-cyan-400">Groq LLM</strong></span>
            </div>
          </div>
        </div>

        {/* 2. Security Banner */}
        <SecurityBanner />
      </div>

      {/* 3. Main Chat Panel */}
      <div className="flex-1 flex flex-col my-2">
        <ChatWindow
          messages={messages}
          loading={loading}
          onClearClick={() => setShowClearModal(true)}
          messageCount={messages.length}
        />
      </div>

      {/* 4. Quick Actions & Input Bar */}
      <div className="space-y-3 shrink-0 pt-2">
        <QuickActions
          onSelectAction={handleSendMessage}
          disabled={loading}
        />

        <ChatInput
          onSendMessage={handleSendMessage}
          loading={loading}
        />
      </div>

      {/* 5. Clear Conversation Confirmation Modal */}
      <ClearChatModal
        isOpen={showClearModal}
        onClose={() => setShowClearModal(false)}
        onConfirm={handleConfirmClear}
      />
    </div>
  );
};

export default AIHelpline;
