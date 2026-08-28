import React, { useState, useEffect } from 'react';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import ShapWaterfallChart from '../components/ShapWaterfallChart';
import {
  History,
  Search,
  Filter,
  Eye,
  X,
  Clock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';

const ScanHistory = () => {
  const { addToast } = useThreat();
  const [scans, setScans] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [selectedScanDetail, setSelectedScanDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await api.get('/history/scans', { params: { limit: 50 } });
      setScans(res.data);
    } catch (err) {
      console.warn('History fetch failed:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleInspectScan = async (scanId) => {
    try {
      const res = await api.get(`/history/scans/${scanId}`);
      setSelectedScanDetail(res.data);
    } catch (err) {
      addToast('Could not load deep scan details.', 'error');
    }
  };

  const filteredScans = scans.filter((s) => {
    const matchesSearch = s.target.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesVerdict = verdictFilter === 'ALL' || s.verdict === verdictFilter;
    return matchesSearch && matchesVerdict;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 uppercase tracking-wider mb-1">
            <History className="w-3.5 h-3.5" />
            Audit Ledger
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            Threat Scan History & Explainability Logs
          </h1>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="glass-panel rounded-2xl p-4 border border-slate-800 flex flex-col sm:flex-row gap-4 items-center justify-between">
        <div className="relative w-full sm:w-80">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search scanned targets or domains..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-500"
          />
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-2.5" />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto pb-1 sm:pb-0">
          <span className="text-xs text-slate-400 font-mono flex items-center gap-1 shrink-0">
            <Filter className="w-3.5 h-3.5" />
            Verdict:
          </span>
          {['ALL', 'SAFE', 'SUSPICIOUS', 'MALICIOUS', 'ZERO_DAY'].map((v) => (
            <button
              key={v}
              onClick={() => setVerdictFilter(v)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold shrink-0 transition-all ${
                verdictFilter === v
                  ? 'bg-cyan-500 text-white shadow-md shadow-cyan-500/20'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
              }`}
            >
              {v}
            </button>
          ))}
        </div>
      </div>

      {/* Scans Table */}
      <div className="glass-panel rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono text-[10px]">
              <tr>
                <th className="py-3 px-4">Target Destination</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    No scans match the current query.
                  </td>
                </tr>
              ) : (
                filteredScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3.5 px-4 font-mono text-cyan-300 max-w-sm truncate">
                      {scan.target}
                    </td>
                    <td className="py-3.5 px-4 uppercase text-[10px] font-mono text-slate-400">
                      {scan.scan_type}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                          scan.verdict === 'SAFE'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : scan.verdict === 'SUSPICIOUS'
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-rose-500/20 text-rose-300'
                        }`}
                      >
                        {scan.verdict}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold">
                      {scan.risk_score.toFixed(1)}/100
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                      {new Date(scan.scanned_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleInspectScan(scan.id)}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-medium border border-slate-700 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Inspect SHAP
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep Inspection Modal */}
      {selectedScanDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="p-6 border-b border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase text-cyan-400 block">
                  Scan Audit ID #{selectedScanDetail.id}
                </span>
                <h3 className="text-base font-bold text-white font-mono break-all">
                  {selectedScanDetail.target}
                </h3>
              </div>
              <button
                onClick={() => setSelectedScanDetail(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Scroll Content */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Score Breakdown Pills */}
              {selectedScanDetail.breakdown && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Phishing Prob:</span>
                    <span className="font-bold text-white">
                      {(selectedScanDetail.breakdown.phishing_probability * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Zero-Day Score:</span>
                    <span className="font-bold text-white">
                      {(selectedScanDetail.breakdown.zero_day_anomaly_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Social Eng:</span>
                    <span className="font-bold text-white">
                      {(selectedScanDetail.breakdown.social_engineering_score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-xl border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">Final Weighted:</span>
                    <span className="font-bold text-cyan-400">
                      {selectedScanDetail.breakdown.final_weighted_score.toFixed(1)}/100
                    </span>
                  </div>
                </div>
              )}

              {/* SHAP Chart & Explanation */}
              {selectedScanDetail.shap_explanation ? (
                <div className="space-y-4">
                  <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800 space-y-2">
                    <span className="text-[10px] font-mono uppercase text-cyan-400 block">
                      Persisted Plain-Language Explanation:
                    </span>
                    <p className="text-sm text-slate-200">
                      {selectedScanDetail.shap_explanation.personalized_explanation}
                    </p>
                  </div>

                  <ShapWaterfallChart
                    featureImportances={
                      selectedScanDetail.shap_explanation.feature_importances || []
                    }
                    baseValue={selectedScanDetail.shap_explanation.base_value}
                    predictionScore={selectedScanDetail.shap_explanation.prediction_score}
                  />
                </div>
              ) : (
                <div className="p-6 text-center text-slate-500 text-xs font-mono">
                  Full SHAP breakdown cached in MongoDB.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;
