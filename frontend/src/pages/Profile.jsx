import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import RiskGauge from '../components/RiskGauge';
import { User, Shield, Award, Sparkles, Check, Save } from 'lucide-react';

const Profile = () => {
  const { user, updateUserTier } = useAuth();
  const { addToast } = useThreat();

  const [selectedTier, setSelectedTier] = useState(user?.risk_profile_tier || 'Novice');
  const [updating, setUpdating] = useState(false);

  const tiers = [
    {
      name: 'Novice',
      desc: 'High-assistance mode: Plain-language security explanations and extra cautious threat weightings.',
      color: 'border-amber-500/40 text-amber-300',
    },
    {
      name: 'Intermediate',
      desc: 'Standard defense: Balanced threat modeling and tactical red flag indicators.',
      color: 'border-cyan-500/40 text-cyan-300',
    },
    {
      name: 'Advanced',
      desc: 'SecOps mode: Deep technical SHAP attribution, raw feature vectors, and network indicators.',
      color: 'border-emerald-500/40 text-emerald-300',
    },
    {
      name: 'High-Risk',
      desc: 'Elevated protection: Aggressive zero-day filtering for high-target accounts.',
      color: 'border-rose-500/40 text-rose-300',
    },
  ];

  const handleSaveTier = async () => {
    setUpdating(true);
    try {
      await updateUserTier(selectedTier);
      addToast(`Security profile updated to ${selectedTier} tier.`, 'success');
    } catch (err) {
      addToast('Failed to update tier: ' + err.message, 'error');
    } finally {
      setUpdating(false);
    }
  };

  const vulnerabilityScore = Math.round((user?.vulnerability_index || 0.5) * 100);

  return (
    <div className="max-w-4xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      <div>
        <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
          Personalized Cybersecurity Profile
        </h1>
        <p className="text-sm text-slate-400">
          Manage your demonstrated understanding tier and view real-time behavioral diagnostics.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* User Identity Info */}
        <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-4">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-cyan-500 flex items-center justify-center text-2xl font-black text-white uppercase shadow-lg shadow-indigo-950/50">
            {user?.full_name?.charAt(0) || 'U'}
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">{user?.full_name}</h2>
            <p className="text-xs font-mono text-cyan-400">{user?.email}</p>
          </div>
          <div className="pt-2 border-t border-slate-800 text-xs text-slate-400 font-mono space-y-1">
            <div>Member Since: {new Date(user?.created_at || Date.now()).toLocaleDateString()}</div>
            <div>Account Status: Active</div>
          </div>
        </div>

        {/* Vulnerability Gauge */}
        <div className="md:col-span-2 glass-panel rounded-2xl p-6 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-6">
          <RiskGauge
            score={vulnerabilityScore}
            size={160}
            strokeWidth={13}
            verdict={vulnerabilityScore <= 35 ? 'HARDENED' : vulnerabilityScore <= 65 ? 'MODERATE' : 'ELEVATED'}
          />
          <div className="space-y-2 text-center sm:text-left">
            <span className="text-xs font-mono uppercase text-cyan-400 font-bold block">
              Behavioral Risk Diagnostics
            </span>
            <h3 className="text-base font-bold text-white">
              Vulnerability Index: {(user?.vulnerability_index || 0.5).toFixed(2)}
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed max-w-sm">
              Your susceptibility score updates automatically as you scan URLs, report phishing simulations, and interact with the defense platform.
            </p>
          </div>
        </div>
      </div>

      {/* Tier Selection Section */}
      <div className="glass-panel rounded-2xl p-6 border border-slate-800 space-y-6">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Award className="w-5 h-5 text-amber-400" />
            Adaptive Understanding Level
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Choose how detailed and technical you want your SHAP AI explanations and simulation difficulty to be:
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {tiers.map((t) => (
            <div
              key={t.name}
              onClick={() => setSelectedTier(t.name)}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                selectedTier === t.name
                  ? `bg-slate-800/90 ${t.color} shadow-lg`
                  : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <span className="font-bold text-sm text-white">{t.name}</span>
                {selectedTier === t.name && <Check className="w-4 h-4 text-cyan-400" />}
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{t.desc}</p>
            </div>
          ))}
        </div>

        <button
          onClick={handleSaveTier}
          disabled={updating || selectedTier === user?.risk_profile_tier}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-md shadow-cyan-500/25 transition-all disabled:opacity-50"
        >
          <Save className="w-4 h-4" />
          {updating ? 'Saving...' : 'Save Profile Tier'}
        </button>
      </div>
    </div>
  );
};

export default Profile;
