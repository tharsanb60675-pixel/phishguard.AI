import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import { ShieldAlert, Send, Plus, MapPin, Tag, FileText, CheckCircle2 } from 'lucide-react';

const ScamReporter = () => {
  const { user } = useAuth();
  const { addToast } = useThreat();

  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('phishing');
  const [target, setTarget] = useState('');
  const [locationName, setLocationName] = useState('Global / Online');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [recentReports, setRecentReports] = useState([]);

  useEffect(() => {
    fetchRecentReports();
  }, []);

  const fetchRecentReports = async () => {
    try {
      const res = await api.get('/community/reports');
      setRecentReports(res.data);
    } catch (err) {
      console.warn('Failed to load recent scam reports:', err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim() || !target.trim() || !description.trim()) {
      addToast('Please fill all required report fields.', 'warning');
      return;
    }

    setSubmitting(true);
    try {
      await api.post('/community/report', {
        title: title.trim(),
        scam_category: category,
        reported_target: target.trim(),
        description: description.trim(),
        location_name: locationName.trim() || 'Global / Online',
      });

      addToast('Thank you! Community scam report published.', 'success');
      setTitle('');
      setTarget('');
      setDescription('');
      fetchRecentReports();
    } catch (err) {
      addToast('Submission failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      <div>
        <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
          Crowdsourced Scam Reporting Hub
        </h1>
        <p className="text-sm text-slate-400">
          Submit malicious URLs, phone numbers, fake e-commerce sites, or impersonation campaigns to alert the global defense network.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Form */}
        <div className="lg:col-span-6 glass-panel rounded-2xl p-6 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            Submit New Incident
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-mono text-slate-300 block mb-1">Threat Title *</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Fake Netflix Subscription Renewal SMS"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-mono text-slate-300 block mb-1">Category *</label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                >
                  <option value="phishing">Phishing Link</option>
                  <option value="fake_store">Fake Online Store</option>
                  <option value="crypto_scam">Crypto / Investment Drainer</option>
                  <option value="impersonation">Brand / CEO Impersonation</option>
                  <option value="tech_support">Tech Support Pop-up</option>
                  <option value="job_offer">Job Offer Scam</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-mono text-slate-300 block mb-1">Location / Region</label>
                <input
                  type="text"
                  value={locationName}
                  onChange={(e) => setLocationName(e.target.value)}
                  placeholder="e.g. California, USA or Online"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-mono text-slate-300 block mb-1">
                Target (URL, Phone, Handle) *
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. https://netflix-update-billing.top or +1-800-XXX"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <div>
              <label className="text-xs font-mono text-slate-300 block mb-1">
                Incident Description *
              </label>
              <textarea
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Explain what the scam requested and any red flags observed..."
                className="w-full p-3 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
            </div>

            <button
              type="submit"
              disabled={submitting}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 text-white font-semibold text-xs shadow-lg shadow-rose-900/30 hover:from-rose-500 hover:to-amber-500 transition-all disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
              {submitting ? 'Broadcasting Threat...' : 'Submit to Community Feed'}
            </button>
          </form>
        </div>

        {/* Community Feed Stream */}
        <div className="lg:col-span-6 glass-panel rounded-2xl p-6 border border-slate-800 space-y-4">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            Recently Reported Community Threats
          </h2>

          <div className="space-y-3 max-h-[440px] overflow-y-auto pr-1">
            {recentReports.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-xs font-mono">
                No user reports logged yet. Be the first to submit.
              </div>
            ) : (
              recentReports.map((report) => (
                <div
                  key={report.id}
                  className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300">
                      {report.scam_category.replace('_', ' ')}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {new Date(report.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-slate-100">{report.title}</h4>
                  <p className="text-[11px] font-mono text-cyan-400 break-all">
                    {report.reported_target}
                  </p>
                  <p className="text-xs text-slate-400 line-clamp-2">{report.description}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScamReporter;
