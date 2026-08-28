/**
 * PhishGuard AI Helpline — Clean AI API Service Layer & Adapter
 *
 * Configurable via environment variables (e.g. VITE_AI_API_URL, VITE_AI_API_KEY).
 * Securely proxies chat requests to the PhishGuard backend AI engine (Groq LLM).
 */

import axios from 'axios';
import { ChatMessage, APIRequest, APIResponse } from '../types/chat';

// ─── Environment & Configuration Defaults ─────────────────────────────────────
const DEFAULT_API_URL = 'http://localhost:8000/api/v1/chat';
const API_URL = import.meta.env.VITE_AI_API_URL || DEFAULT_API_URL;
const API_KEY = import.meta.env.VITE_AI_API_KEY || 'YOUR_API_KEY';

/**
 * Clean Adapter Function: sendMessage
 *
 * Sends user prompt and prior turns to the configured AI API and normalizes the response.
 *
 * @param message User message text
 * @param conversationHistory Prior chat messages in session
 * @param scanContext Optional active scan/threat evaluation context
 * @param sessionId Unique session identifier
 * @returns Promise<APIResponse>
 */
export async function sendMessage(
  message: string,
  conversationHistory: ChatMessage[] = [],
  scanContext?: any,
  sessionId?: string
): Promise<APIResponse> {
  const cleanMessage = message.trim();
  if (!cleanMessage) {
    throw new Error('Message content cannot be empty.');
  }

  // Format conversation history for multi-turn context (last 10 turns)
  const historyPayload = conversationHistory.slice(-10).map((msg) => ({
    role: (msg.sender === 'user' ? 'user' : 'assistant') as 'user' | 'assistant',
    content: msg.text,
  }));

  const payload: APIRequest = {
    message: cleanMessage,
    session_id: sessionId || `sess_${Date.now()}`,
    history: historyPayload,
    scan_context: scanContext ? {
      rawValue: scanContext.rawValue || scanContext.target,
      formatName: scanContext.formatName || scanContext.type,
      riskScore: scanContext.riskScore,
      verdict: scanContext.verdict,
      reasons: scanContext.reasons,
      actionableAdvice: scanContext.actionableAdvice,
    } : undefined,
  };

  try {
    const token = localStorage.getItem('phishguard_access_token');
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    } else if (API_KEY && API_KEY !== 'YOUR_API_KEY') {
      headers['x-api-key'] = API_KEY;
    }

    const endpoint = API_URL.endsWith('/') ? API_URL : `${API_URL}/`;
    const res = await axios.post<APIResponse>(endpoint, payload, {
      headers,
      timeout: 25000,
    });

    if (res.data && res.data.response) {
      return {
        session_id: res.data.session_id || payload.session_id || `sess_${Date.now()}`,
        response: res.data.response,
        detected_threats: res.data.detected_threats || [],
        recommended_action: res.data.recommended_action || 'Follow safe browsing practices.',
        sources: res.data.sources || ['PhishGuard AI Helpline'],
        threat_level: res.data.threat_level || 'INFO',
        is_live_ai: res.data.is_live_ai ?? true,
        ai_provider: res.data.ai_provider || 'groq',
      };
    }

    throw new Error('Empty response received from AI service.');
  } catch (err: any) {
    console.warn('[PhishGuard AI Helpline] API communication error:', err.message);

    // Fallback error normalization without exposing internal stack traces
    return {
      session_id: payload.session_id || `sess_${Date.now()}`,
      response:
        "I'm temporarily unable to reach the cybersecurity AI service. Please check your connection or try again in a moment.\n\n" +
        "**Immediate Safety Advice:** If you are dealing with a suspicious message, OTP request, or unexpected link, **do not click or disclose any secrets.**",
      detected_threats: ['Service Communication Notice'],
      recommended_action: 'Do not share credentials while service reconnects.',
      sources: ['PhishGuard Offline Defense Guardrail'],
      threat_level: 'INFO',
      is_live_ai: false,
    };
  }
}

export const aiService = {
  sendMessage,
  API_URL,
  API_KEY,
};

export default aiService;
