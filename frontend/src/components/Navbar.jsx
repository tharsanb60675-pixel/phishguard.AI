import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  ShieldAlert,
  ShieldCheck,
  Radio,
  Crosshair,
  Bot,
  MessageSquareCode,
  History,
  User,
  LogOut,
  Sparkles,
  QrCode,
} from 'lucide-react';

const Navbar = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();

  const navItems = [
    { name: 'Dashboard', path: '/', icon: Crosshair },
    { name: 'Threat Scanner', path: '/scanner', icon: ShieldAlert },
    { name: 'Universal Scanner', path: '/qr-scanner', icon: QrCode },
    { name: 'AI Helpline', path: '/helpline', icon: Bot },
    { name: 'Safety Chatbot', path: '/chatbot', icon: MessageSquareCode },
    { name: 'Background Protection', path: '/background-protection', icon: ShieldCheck },

    { name: 'Audit Ledger', path: '/history', icon: History },
  ];

  const getTierBadge = (tier) => {
    switch (tier) {
      case 'Advanced':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      case 'Intermediate':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'High-Risk':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      default:
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    }
  };

  return (
    <nav className="sticky top-0 z-50 glass-panel border-b border-slate-800/80 px-4 lg:px-8 py-3">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Brand Logo */}
        <Link to="/" className="flex items-center gap-3 group">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
            <ShieldAlert className="w-6 h-6 text-white" />
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xl font-extrabold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-200 to-cyan-400">
                PhishGuard<span className="text-cyan-400">.AI</span>
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono tracking-wider uppercase">
              Adaptive Threat Defense
            </p>
          </div>
        </Link>

        {/* Navigation Links */}
        {isAuthenticated && (
          <div className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  {item.name}
                </Link>
              );
            })}
          </div>
        )}

        {/* User Profile & Actions */}
        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <div className="flex items-center gap-3">
              {/* Risk Tier Badge */}
              <div
                className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border ${getTierBadge(
                  user?.risk_profile_tier
                )}`}
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Tier: {user?.risk_profile_tier || 'Novice'}</span>
              </div>

              {/* Profile Link */}
              <Link
                to="/profile"
                className="flex items-center gap-2 p-1.5 rounded-lg bg-slate-800/80 border border-slate-700 hover:border-slate-600 transition-colors"
                title="Profile & Settings"
              >
                <div className="w-7 h-7 rounded-md bg-gradient-to-br from-indigo-500 to-cyan-500 flex items-center justify-center text-xs font-bold text-white uppercase">
                  {user?.full_name?.charAt(0) || 'U'}
                </div>
                <span className="hidden lg:inline text-xs font-medium text-slate-200 pr-1">
                  {user?.full_name?.split(' ')[0]}
                </span>
              </Link>

              {/* Logout Button */}
              <button
                onClick={logout}
                className="p-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                title="Logout"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Link
                to="/login"
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
              >
                Sign In
              </Link>
              <Link
                to="/register"
                className="px-4 py-2 text-sm font-medium text-white bg-gradient-to-r from-cyan-500 to-blue-600 rounded-lg shadow-md shadow-cyan-500/20 hover:from-cyan-400 hover:to-blue-500 transition-all"
              >
                Get Started
              </Link>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
