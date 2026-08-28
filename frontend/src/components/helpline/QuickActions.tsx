import React from 'react';
import {
  Link2,
  MessageSquareWarning,
  Building2,
  KeyRound,
  Lock,
  HelpCircle,
} from 'lucide-react';

interface QuickActionsProps {
  onSelectAction: (prompt: string) => void;
  disabled?: boolean;
}

const QUICK_ACTIONS = [
  {
    label: 'Is this URL safe?',
    prompt: 'Is this URL safe? Can you analyze whether a website link is legitimate or a phishing trap?',
    icon: Link2,
    color: 'hover:border-cyan-500/60 hover:text-cyan-300',
  },
  {
    label: 'I received a suspicious message',
    prompt: 'I received a suspicious message claiming I won a contest or need to confirm an order. How do I verify it?',
    icon: MessageSquareWarning,
    color: 'hover:border-amber-500/60 hover:text-amber-300',
  },
  {
    label: 'I received a fake bank message',
    prompt: 'I received an urgent SMS/WhatsApp message claiming my bank account is blocked. How do I know if it is fake?',
    icon: Building2,
    color: 'hover:border-rose-500/60 hover:text-rose-300',
  },
  {
    label: 'Someone asked for my OTP',
    prompt: 'Someone claiming to be customer support asked for my one-time password (OTP). Should I share it?',
    icon: KeyRound,
    color: 'hover:border-rose-500/60 hover:text-rose-300',
  },
  {
    label: 'Someone asked for my password',
    prompt: 'Someone is asking for my password or login credentials for verification. What should I do?',
    icon: Lock,
    color: 'hover:border-amber-500/60 hover:text-amber-300',
  },
  {
    label: 'What should I do?',
    prompt: 'I accidentally clicked a suspicious link or entered some details. What immediate steps should I take?',
    icon: HelpCircle,
    color: 'hover:border-cyan-500/60 hover:text-cyan-300',
  },
];

export const QuickActions: React.FC<QuickActionsProps> = ({ onSelectAction, disabled = false }) => {
  return (
    <div className="w-full space-y-2 pt-1">
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span>QUICK CYBERSECURITY ACTIONS</span>
        <span className="text-[10px] text-slate-500">Tap to Ask Instantly</span>
      </div>

      <div className="flex flex-wrap gap-2 overflow-x-auto pb-1 no-scrollbar">
        {QUICK_ACTIONS.map((action, index) => {
          const Icon = action.icon;
          return (
            <button
              key={index}
              onClick={() => onSelectAction(action.prompt)}
              disabled={disabled}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 text-slate-300 text-xs font-medium transition-all shadow-sm ${action.color} hover:bg-slate-800/80 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed shrink-0`}
            >
              <Icon className="w-3.5 h-3.5 text-cyan-400" />
              <span>{action.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default QuickActions;
