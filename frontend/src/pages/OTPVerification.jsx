import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useThreat } from '../context/ThreatContext';
import { ShieldAlert, Key, ArrowRight, RefreshCw } from 'lucide-react';

const OTPVerification = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { verifyOTP, resendOTP } = useAuth();
  const { addToast } = useThreat();
  
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [timer, setTimer] = useState(59);

  useEffect(() => {
    if (location.state?.email) {
      setEmail(location.state.email);
    } else {
      navigate('/login');
    }
  }, [location.state, navigate]);

  useEffect(() => {
    let interval;
    if (timer > 0) {
      interval = setInterval(() => {
        setTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [timer]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (otp.length !== 6) {
      addToast('OTP must be exactly 6 digits.', 'warning');
      return;
    }
    setLoading(true);
    try {
      const res = await verifyOTP(email, otp);
      
      if (res.success && res.verified) {
        addToast('Email verified! Please create your password.', 'success');
        navigate('/setup-password', { state: { email } });
      } else {
        addToast(res.message || 'Verification failed.', 'error');
      }
    } catch (err) {
      addToast(err.response?.data?.message || err.response?.data?.detail || 'Invalid verification code. Please try again.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (timer > 0) return;
    setResending(true);
    try {
      await resendOTP(email);
      addToast('A new verification code has been sent.', 'success');
      setTimer(59);
    } catch (err) {
      addToast(err.response?.data?.detail || 'Unable to send verification code. Please try again.', 'error');
    } finally {
      setResending(false);
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
            Email Verification
          </h1>
          <p className="text-xs text-slate-400">
            Enter the verification code sent to your email
          </p>
          <p className="text-sm font-semibold text-cyan-400">
            {email}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <div className="relative">
              <input
                type="text"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                placeholder="_ _ _ _ _ _"
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-950/80 border border-slate-700 text-slate-100 text-center tracking-[1em] text-xl font-mono focus:outline-none focus:border-cyan-500"
                required
                maxLength={6}
              />
              <Key className="w-4 h-4 text-slate-500 absolute left-3.5 top-[18px]" />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || otp.length !== 6}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-xs shadow-lg shadow-cyan-500/25 transition-all disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify Email'}
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>

        <div className="pt-4 text-center border-t border-slate-800 flex flex-col items-center justify-center gap-2">
          <p className="text-xs text-slate-400">Didn't receive the code?</p>
          <button
            onClick={handleResend}
            disabled={timer > 0 || resending}
            className="text-xs text-cyan-400 hover:text-cyan-300 disabled:text-slate-500 flex items-center justify-center gap-2 w-full transition-colors font-semibold"
          >
            <RefreshCw className={`w-3 h-3 ${resending ? 'animate-spin' : ''}`} />
            {timer > 0 ? `Resend OTP in 00:${timer.toString().padStart(2, '0')}` : 'Resend OTP'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default OTPVerification;
