import React, { useState, useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, CircleMarker } from 'react-leaflet';
import { useThreat } from '../context/ThreatContext';
import api from '../services/api';
import { Globe, ShieldAlert, Filter, AlertTriangle, Radio, Plus } from 'lucide-react';
import { Link } from 'react-router-dom';
import L from 'leaflet';

// Fix Leaflet Default Icon path issues
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});

const ThreatMap = () => {
  const { addToast } = useThreat();
  const [threatPoints, setThreatPoints] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchThreatMap();
  }, []);

  const fetchThreatMap = async () => {
    try {
      const res = await api.get('/community/threat-map');
      setThreatPoints(res.data);
    } catch (err) {
      console.warn('Threat map load error:', err);
    } finally {
      setLoading(false);
    }
  };

  const categories = ['ALL', 'phishing', 'fake_store', 'crypto_scam', 'impersonation', 'tech_support', 'job_offer'];

  const filteredPoints =
    selectedCategory === 'ALL'
      ? threatPoints
      : threatPoints.filter((pt) => pt.category.toLowerCase() === selectedCategory.toLowerCase());

  const getMarkerColor = (category, severity) => {
    if (severity >= 5) return '#f43f5e'; // Rose
    if (category === 'crypto_scam') return '#a855f7'; // Purple
    if (category === 'phishing') return '#ef4444'; // Red
    if (category === 'impersonation') return '#f59e0b'; // Amber
    return '#06b6d4'; // Cyan
  };

  return (
    <div className="max-w-7xl mx-auto px-4 lg:px-8 py-8 space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-rose-400 uppercase tracking-wider mb-1">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            Live Crowd-Sourced Threat Density
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold text-white tracking-tight">
            Community Threat Intelligence Map
          </h1>
        </div>

        <Link
          to="/report-scam"
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white font-semibold text-xs shadow-lg shadow-rose-900/30 transition-all self-start md:self-auto"
        >
          <Plus className="w-4 h-4" />
          Report Emerging Scam
        </Link>
      </div>

      {/* Category Filter Pills */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        <span className="text-xs text-slate-400 font-mono flex items-center gap-1 shrink-0">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          Threat Vector:
        </span>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium uppercase tracking-wider shrink-0 transition-all ${
              selectedCategory === cat
                ? 'bg-cyan-500 text-white shadow-md shadow-cyan-500/20'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            {cat.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Map Container */}
      <div className="glass-panel rounded-2xl border border-slate-800 p-2 overflow-hidden shadow-2xl">
        <div className="h-[550px] w-full rounded-xl overflow-hidden relative">
          {loading ? (
            <div className="h-full w-full flex items-center justify-center bg-slate-950 text-slate-400 font-mono text-sm">
              Loading Leaflet Threat Mesh...
            </div>
          ) : (
            <MapContainer
              center={[20, 0]}
              zoom={2}
              minZoom={2}
              scrollWheelZoom={true}
              style={{ height: '100%', width: '100%' }}
            >
              {/* OpenStreetMap Dark/CartoDB Dark Matter tiles */}
              <TileLayer
                attribution='&copy; <a href="https://carto.com/">CARTO</a>'
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              />

              {filteredPoints.map((pt) => {
                const color = getMarkerColor(pt.category, pt.severity);
                return (
                  <CircleMarker
                    key={pt.id}
                    center={[pt.latitude, pt.longitude]}
                    radius={Math.min(18, Math.max(8, Math.sqrt(pt.report_count) * 2.5))}
                    pathOptions={{
                      color: color,
                      fillColor: color,
                      fillOpacity: 0.6,
                      weight: 2,
                    }}
                  >
                    <Popup>
                      <div className="space-y-2 p-1 min-w-[200px]">
                        <div className="flex items-center justify-between border-b border-slate-700 pb-1">
                          <span className="text-[10px] uppercase font-bold text-rose-400">
                            {pt.category.replace('_', ' ')}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400">
                            Sev: {pt.severity}/5
                          </span>
                        </div>
                        <h4 className="text-xs font-bold text-white">{pt.title}</h4>
                        <p className="text-[11px] font-mono text-cyan-300 break-all">
                          Target: {pt.target}
                        </p>
                        <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1">
                          <span>{pt.location}</span>
                          <span className="font-bold text-amber-400">
                            {pt.report_count} Reports
                          </span>
                        </div>
                      </div>
                    </Popup>
                  </CircleMarker>
                );
              })}
            </MapContainer>
          )}

          {/* Map Overlay Stats Card */}
          <div className="absolute bottom-4 left-4 z-[1000] p-3 rounded-xl bg-slate-950/90 border border-slate-800 backdrop-blur-md space-y-1.5 pointer-events-auto">
            <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
              Visualizing Active Outbreaks
            </div>
            <div className="flex items-center gap-4 text-xs">
              <span className="font-bold text-white font-mono">
                {filteredPoints.length} Geocoded Hotspots
              </span>
              <span className="flex items-center gap-1 text-emerald-400 font-mono">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                Live Feed
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatMap;
