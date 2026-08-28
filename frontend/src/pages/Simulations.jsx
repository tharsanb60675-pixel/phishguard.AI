import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import {
  Mail,
  ShieldCheck,
  AlertTriangle,
  Send,
  Flag,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  Award,
  ChevronRight,
  TrendingDown,
} from 'lucide-react';

const Simulations = () => {
  const { user, refreshUserData } = useAuth();
  const { addToast } = useThreat();

  const [scenarios, setScenarios] = useState([]);
  const [selectedScenario, setSelectedScenario] = useState(null);
  const [startTime, setStartTime] = useState(Date.now());
  const [feedback, setFeedback] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    fetchScenarios();
  }, []);

  const fetchScenarios = async () => {
    try {
      const res = await api.get('/simulations/scenarios');
      setScenarios(res.data);
      if (res.data.length > 0) {
        setSelectedScenario(res.data[0]);
        setStartTime(Date.now());
      }
    } catch (err) {
      console.warn('Failed to load simulation scenarios:', err);
    }
  };

  const handleSelectScenario = (sc) => {
    setSelectedScenario(sc);
    setFeedback(null);
    setStartTime(Date.now());
  };

  const handleAction = async (actionType) => {
    if (!selectedScenario || submitting) return;

    setSubmitting(true);
    const elapsedSeconds = Math.max(1, (Date.now() - startTime) / 1000);

    try {
      const res = await api.post('/simulations/action', {
        simulation_id: selectedScenario.id,
        user_action: actionType,
        response_time_seconds: elapsedSeconds,
      });

      setFeedback(res.data);
      await refreshUserData();

      if (res.data.correct_action) {
        addToast(`Bravo! ${res.data.feedback_title}`, 'success');
      } else {
        addToast(res.data.feedback_title, 'error');
      }
    } catch (err) {
      addToast('Simulation action failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-amber-400 uppercase tracking-wider mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            AI Scam Simulator & Reflex Trainer
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            Interactive Phishing Reflex Inbox
          </h1>
        </div>

        <div className="flex items-center gap-4 p-3 bg-slate-900 border border-slate-800 rounded-xl">
          <div className="text-right">
            <span className="text-[10px] uppercase font-mono text-slate-400 block">
              Current Vulnerability Index
            </span>
            <span className="text-base font-bold text-cyan-400 font-mono">
              {(user?.vulnerability_index || 0.5).toFixed(2)} (
              {user?.risk_profile_tier || 'Novice'})
            </span>
          </div>
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
            <Award className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Main Simulation Workspace: Inbox on Left, Email Viewer on Right */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Inbox Scenario List */}
        <div className="lg:col-span-4 glass-panel rounded-2xl p-4 space-y-3">
          <div className="flex items-center justify-between px-2 pb-2 border-b border-slate-800">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Simulated Scenarios ({scenarios.length})
            </span>
            <span className="text-[10px] text-cyan-400 font-mono">Adaptive AI</span>
          </div>

          <div className="space-y-2">
            {scenarios.map((sc) => {
              const isSelected = selectedScenario?.id === sc.id;
              return (
                <div
                  key={sc.id}
                  onClick={() => handleSelectScenario(sc)}
                  className={`p-3 rounded-xl cursor-pointer border transition-all ${
                    isSelected
                      ? 'bg-slate-800/90 border-cyan-500/50 shadow-md shadow-cyan-950/40'
                      : 'bg-slate-900/50 border-slate-800/80 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-800 text-cyan-300 border border-slate-700">
                      {sc.difficulty}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">Inbox</span>
                  </div>
                  <h4 className="text-xs font-bold text-slate-100 line-clamp-1">{sc.theme}</h4>
                  <p className="text-[11px] text-slate-400 line-clamp-1">{sc.subject}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Email Simulation Viewer */}
        <div className="lg:col-span-8 glass-panel rounded-2xl p-6 space-y-6 flex flex-col justify-between">
          {selectedScenario ? (
            <>
              <div className="space-y-4">
                {/* Email Header Metadata */}
                <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-full bg-indigo-600 flex items-center justify-center font-bold text-xs text-white uppercase">
                        {selectedScenario.sender_name.charAt(0)}
                      </div>
                      <div>
                        <h3 className="text-xs font-bold text-white">
                          {selectedScenario.sender_name}
                        </h3>
                        <p className="text-[11px] font-mono text-slate-400">
                          &lt;{selectedScenario.sender_email}&gt;
                        </p>
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500">Just Now</span>
                  </div>

                  <div className="pt-2 border-t border-slate-800/60">
                    <h2 className="text-sm font-bold text-slate-200">
                      Subject: {selectedScenario.subject}
                    </h2>
                  </div>
                </div>

                {/* Email Body Simulation Sandbox */}
                <div
                  className="p-6 bg-white rounded-xl text-slate-900 border border-slate-200 min-h-[180px]"
                  dangerouslySetInnerHTML={{ __html: selectedScenario.body_html }}
                ></div>
              </div>

              {/* Action Buttons for User Response */}
              {!feedback && (
                <div className="p-4 bg-slate-900/90 rounded-xl border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">
                      How would you handle this communication?
                    </span>
                    <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      Timer Running
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <button
                      onClick={() => handleAction('REPORTED')}
                      disabled={submitting}
                      className="flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-xs shadow-lg shadow-emerald-950/40 transition-all disabled:opacity-50"
                    >
                      <Flag className="w-4 h-4" />
                      Report as Phishing (Safe)
                    </button>

                    <button
                      onClick={() => handleAction('CLICKED_LINK')}
                      disabled={submitting}
                      className="flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-slate-800 hover:bg-amber-950/40 text-slate-300 hover:text-amber-300 border border-slate-700 hover:border-amber-500/40 text-xs font-semibold transition-colors disabled:opacity-50"
                    >
                      <AlertTriangle className="w-4 h-4" />
                      Click Email Link
                    </button>

                    <button
                      onClick={() => handleAction('ENTERED_CREDENTIALS')}
                      disabled={submitting}
                      className="flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-slate-800 hover:bg-rose-950/40 text-slate-300 hover:text-rose-300 border border-slate-700 hover:border-rose-500/40 text-xs font-semibold transition-colors disabled:opacity-50"
                    >
                      <XCircle className="w-4 h-4" />
                      Submit Credentials
                    </button>
                  </div>
                </div>
              )}

              {/* Simulation Result & Red Flag Feedback Modal */}
              {feedback && (
                <div
                  className={`p-6 rounded-xl border animate-fadeIn space-y-4 ${
                    feedback.correct_action
                      ? 'bg-emerald-950/20 border-emerald-500/50'
                      : 'bg-rose-950/20 border-rose-500/50'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      {feedback.correct_action ? (
                        <CheckCircle2 className="w-7 h-7 text-emerald-400" />
                      ) : (
                        <XCircle className="w-7 h-7 text-rose-400" />
                      )}
                      <div>
                        <h3 className="text-base font-bold text-white">{feedback.feedback_title}</h3>
                        <p className="text-xs text-slate-300">{feedback.feedback_message}</p>
                      </div>
                    </div>

                    <div className="text-right font-mono text-xs">
                      <span className="text-slate-400 block text-[10px]">Vulnerability Delta:</span>
                      <span
                        className={`font-bold ${
                          feedback.new_vulnerability_index < feedback.previous_vulnerability_index
                            ? 'text-emerald-400'
                            : 'text-rose-400'
                        }`}
                      >
                        {feedback.previous_vulnerability_index.toFixed(2)} &rarr;{' '}
                        {feedback.new_vulnerability_index.toFixed(2)}
                      </span>
                    </div>
                  </div>

                  {/* Red Flags Uncovered */}
                  <div className="space-y-2 pt-2 border-t border-slate-800/80">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                      Red Flags to Memorize:
                    </h4>
                    <ul className="space-y-1.5">
                      {feedback.uncovered_red_flags.map((flag, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-xs text-slate-200">
                          <ChevronRight className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                          <span>{flag}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={() => {
                        setFeedback(null);
                        setStartTime(Date.now());
                      }}
                      className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
                    >
                      Try Again / Next Scenario
                    </button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-16 text-slate-500">Loading simulations...</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Simulations;
