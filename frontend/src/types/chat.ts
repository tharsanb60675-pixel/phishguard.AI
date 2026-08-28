/**
 * PhishGuard AI Helpline — TypeScript Type Definitions
 */

export interface ChatMessage {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
  threatLevel?: 'SAFE' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
  isLiveAi?: boolean;
  sources?: string[];
  detectedThreats?: string[];
  recommendedAction?: string;
}

export interface APIRequest {
  message: string;
  session_id?: string;
  history?: Array<{
    role: 'user' | 'assistant' | 'system';
    content: string;
  }>;
  scan_context?: {
    rawValue?: string;
    formatName?: string;
    riskScore?: number;
    verdict?: string;
    reasons?: string[];
    actionableAdvice?: string;
  };
}

export interface APIResponse {
  session_id: string;
  response: string;
  detected_threats?: string[];
  recommended_action?: string;
  sources?: string[];
  threat_level?: string;
  is_live_ai?: boolean;
  ai_provider?: string;
}

export interface ChatState {
  messages: ChatMessage[];
  loading: boolean;
  error: string | null;
  sessionId: string;
  messageCount: number;
}
