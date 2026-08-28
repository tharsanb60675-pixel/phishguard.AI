import React from 'react';
import { Trash2, AlertTriangle } from 'lucide-react';

interface ClearChatModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
}

export const ClearChatModal: React.FC<ClearChatModalProps> = ({ isOpen, onClose, onConfirm }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="max-w-md w-full glass-panel rounded-2xl border border-slate-700 p-6 space-y-4 shadow-2xl text-center">
        <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center mx-auto text-rose-400">
          <Trash2 className="w-6 h-6" />
        </div>

        <div>
          <h3 className="text-lg font-bold text-white">Clear Conversation History?</h3>
          <p className="text-xs text-slate-400 mt-1">
            This will permanently delete all messages and session context in this conversation. This action cannot be undone.
          </p>
        </div>

        <div className="flex gap-3 pt-2">
          <button
            onClick={onConfirm}
            className="flex-1 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs transition-all shadow-lg shadow-rose-600/30"
          >
            Yes, Clear Chat
          </button>
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold text-xs transition-all"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

export default ClearChatModal;
