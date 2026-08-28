import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize Auth state from stored token/user
  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem('phishguard_access_token');
      if (token) {
        try {
          const res = await api.get('/auth/me');
          setUser(res.data);
          localStorage.setItem('phishguard_user', JSON.stringify(res.data));
        } catch (err) {
          console.warn('Session restoration failed:', err);
          logout();
        }
      }
      setLoading(false);
    };

    initializeAuth();

    const handleLogoutEvent = () => {
      setUser(null);
    };
    window.addEventListener('auth:logout', handleLogoutEvent);
    return () => window.removeEventListener('auth:logout', handleLogoutEvent);
  }, []);

  const requestEmail = async (email) => {
    const res = await api.post('/auth/send-otp', { email });
    return res.data;
  };

  const login = async (email, password) => {
    const res = await api.post('/auth/login', { email, password });
    const { user: userData, tokens } = res.data;
    
    localStorage.setItem('phishguard_access_token', tokens.access_token);
    localStorage.setItem('phishguard_refresh_token', tokens.refresh_token);
    localStorage.setItem('phishguard_user', JSON.stringify(userData));
    
    setUser(userData);
    return res.data;
  };

  const register = async (registerData) => {
    const res = await api.post('/auth/register', registerData);
    const { user: userData, tokens } = res.data;
    
    localStorage.setItem('phishguard_access_token', tokens.access_token);
    localStorage.setItem('phishguard_refresh_token', tokens.refresh_token);
    localStorage.setItem('phishguard_user', JSON.stringify(userData));
    
    setUser(userData);
    return res.data;
  };

  const verifyOTP = async (email, otp) => {
    const res = await api.post('/auth/verify-otp', { email, otp });
    
    if (res.data.success && res.data.verified) {
      if (res.data.setup_token) {
        localStorage.setItem('phishguard_setup_token', res.data.setup_token);
      }
      return res.data;
    }
    
    throw new Error("OTP verification failed");
  };

  const setupPassword = async (password) => {
    const setupToken = localStorage.getItem('phishguard_setup_token');
    if (!setupToken) throw new Error("No setup token found");

    // Temporarily set auth header for setup
    const prevAuth = api.defaults.headers.common.Authorization;
    api.defaults.headers.common.Authorization = `Bearer ${setupToken}`;
    
    try {
      const res = await api.post('/auth/setup-password', { password });
      
      const { user: userData, tokens } = res.data;
      
      localStorage.removeItem('phishguard_setup_token');
      localStorage.setItem('phishguard_access_token', tokens.access_token);
      localStorage.setItem('phishguard_refresh_token', tokens.refresh_token);
      localStorage.setItem('phishguard_user', JSON.stringify(userData));
      
      setUser(userData);
      return userData;
    } finally {
      if (prevAuth) {
         api.defaults.headers.common.Authorization = prevAuth;
      } else {
         delete api.defaults.headers.common.Authorization;
      }
    }
  };

  const resendOTP = async (email) => {
    const res = await api.post('/auth/resend-otp', { email });
    return res.data;
  };

  const completeProfile = async (full_name, risk_profile_tier) => {
    const res = await api.post('/auth/profile', { full_name, risk_profile_tier });
    setUser(res.data);
    localStorage.setItem('phishguard_user', JSON.stringify(res.data));
    return res.data;
  };

  const logout = async () => {
    try {
      if (user) {
        await api.post('/auth/logout');
      }
    } catch (e) {
      // Ignore network errors on logout
    } finally {
      localStorage.removeItem('phishguard_access_token');
      localStorage.removeItem('phishguard_refresh_token');
      localStorage.removeItem('phishguard_user');
      setUser(null);
    }
  };

  const updateUserTier = async (newTier, vulnerabilityIndex = null) => {
    try {
      const res = await api.put('/auth/tier', {
        risk_profile_tier: newTier,
        vulnerability_index: vulnerabilityIndex,
      });
      setUser(res.data);
      localStorage.setItem('phishguard_user', JSON.stringify(res.data));
      return res.data;
    } catch (err) {
      console.error('Failed to update user tier:', err);
      throw err;
    }
  };

  const refreshUserData = async () => {
    try {
      const res = await api.get('/auth/me');
      setUser(res.data);
      localStorage.setItem('phishguard_user', JSON.stringify(res.data));
      return res.data;
    } catch (err) {
      console.warn('Failed to refresh user data:', err);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: !!user,
        requestEmail,
        login,
        register,
        verifyOTP,
        setupPassword,
        resendOTP,
        completeProfile,
        logout,
        updateUserTier,
        refreshUserData,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
