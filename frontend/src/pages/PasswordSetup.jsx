import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import { ShieldAlert, Lock, ArrowRight, Eye, EyeOff } from 'lucide-react';

const PasswordSetup = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { setupPassword } = useAuth();
  const { addToast } = useThreat();
  
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!location.state?.email) {
      navigate('/login');
    }
  }, [location.state, navigate]);

  const validatePassword = (pass) => {
    const minLength = pass.length >= 8;
    const hasUpper = /[A-Z]/.test(pass);
    const hasLower = /[a-z]/.test(pass);
    const hasNumber = /[0-9]/.test(pass);
    const hasSpecial = /[^A-Za-z0-9]/.test(pass);
    return minLength && hasUpper && hasLower && hasNumber && hasSpecial;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!password) {
      addToast('Password cannot be empty.', 'warning');
      return;
    }
    if (!confirmPassword) {
      addToast('Confirm password cannot be empty.', 'warning');
      return;
    }
    if (password !== confirmPassword) {
      addToast('Passwords do not match.', 'error');
      return;
    }
    if (!validatePassword(password)) {
      addToast('Password must be at least 8 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character.', 'warning');
      return;
    }

    setLoading(true);
    try {
      const user = await setupPassword(password);
      addToast('Password setup successful! Connecting to session...', 'success');
      
      if (!user.profile_completed) {
        navigate('/onboarding');
      } else {
        navigate('/');
      }
    } catch (err) {
      let errorMsg = 'Failed to setup password. Please try again.';
      if (err.response?.data?.detail) {
        if (Array.isArray(err.response.data.detail)) {
          errorMsg = err.response.data.detail[0].msg;
        } else {
          errorMsg = err.response.data.detail;
        }
      }
      
      if (typeof errorMsg === 'string' && errorMsg.startsWith('Value error, ')) {
        errorMsg = errorMsg.replace('Value error, ', '');
      }
      addToast(errorMsg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12 animate-fadeIn">
      <div className="max-w-md w-full glass-panel rounded-2xl p-8 border border-slate-800 space-y-6 shadow-2xl relative">
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-tr from-cyan-500 to-indigo-600 shadow-lg shadow-cyan-500/20 mb-2">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Create Your Password
          </h1>
          <p className="text-xs text-slate-400">
            Create a password for your account
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">Email Address</label>
            <div className="relative">
              <input
                type="text"
                value={location.state?.email || ''}
                readOnly
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700 text-slate-400 text-xs focus:outline-none cursor-not-allowed"
              />
              <ShieldAlert className="w-4 h-4 text-slate-600 absolute left-3.5 top-3.5" />
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">Password</label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="w-full pl-10 pr-10 py-3 rounded-xl bg-slate-950/80 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
              <button
                type="button"
                className="absolute right-3.5 top-3.5 text-slate-500 hover:text-slate-300"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-300 block mb-1">Confirm Password</label>
            <div className="relative">
              <input
                type={showConfirmPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm password"
                className="w-full pl-10 pr-10 py-3 rounded-xl bg-slate-950/80 border border-slate-700 text-slate-100 text-xs focus:outline-none focus:border-cyan-500"
                required
              />
              <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5" />
              <button
                type="button"
                className="absolute right-3.5 top-3.5 text-slate-500 hover:text-slate-300"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
              >
                {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800">
            <p className="text-xs text-slate-300 font-semibold mb-2">Password Requirements:</p>
            <ul className="text-[10px] text-slate-400 space-y-1 list-disc list-inside">
              <li className={password.length >= 8 ? "text-cyan-400" : ""}>Minimum 8 characters</li>
              <li className={/[A-Z]/.test(password) ? "text-cyan-400" : ""}>At least one uppercase letter</li>
              <li className={/[a-z]/.test(password) ? "text-cyan-400" : ""}>At least one lowercase letter</li>
              <li className={/[0-9]/.test(password) ? "text-cyan-400" : ""}>At least one number</li>
              <li className={/[^A-Za-z0-9]/.test(password) ? "text-cyan-400" : ""}>At least one special character</li>
            </ul>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50"
          >
            {loading ? 'Creating Account...' : 'Create Account'}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
};

export default PasswordSetup;
