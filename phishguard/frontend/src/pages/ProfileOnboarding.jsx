import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import { ShieldAlert, User, ArrowRight, CheckCircle2 } from 'lucide-react';

const ProfileOnboarding = () => {
  const { user, completeProfile } = useAuth();
  const { addToast } = useThreat();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState('');
  const [tier, setTier] = useState('Novice');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await completeProfile(fullName.trim(), tier);
      addToast('Profile completed successfully!', 'success');
      navigate('/');
    } catch (err) {
      addToast(err.response?.data?.detail || 'Failed to complete profile.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[85vh] flex items-center justify-center px-4 py-12 animate-fadeIn">
      <div className="max-w-md w-full glass-panel rounded-2xl p-8 border border-slate-800 space-y-6 shadow-2xl">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-500 to-indigo-600 shadow-lg shadow-cyan-500/20 mb-2">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Create Defender Profile
          </h1>
          <p className="text-xs text-slate-400">
            Set your initial risk tier to calibrate explainable AI models
          </p>
        </div>

        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 flex items-center justify-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span className="text-xs text-slate-300 font-mono">Email Verified: {user?.email}</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">Full Name</label>
            <div className="relative">
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Alex Rivera"
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-950/80 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
              <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">
              Initial Cybersecurity Knowledge Tier
            </label>
            <select
              value={tier}
              onChange={(e) => setTier(e.target.value)}
              className="w-full px-3.5 py-3 rounded-xl bg-slate-950/80 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="Novice">Novice (Clear plain-language guidance)</option>
              <option value="Intermediate">Intermediate (Balanced tactical indicators)</option>
              <option value="Advanced">Advanced (Deep mathematical SHAP attribution)</option>
              <option value="High-Risk">High-Risk (Strict zero-day protection)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50"
          >
            {loading ? 'Saving...' : 'Complete Profile Onboarding'}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};

export default ProfileOnboarding;
