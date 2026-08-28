import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThreatProvider } from './context/ThreatContext';

import Navbar from './components/Navbar';
import PreClickModal from './components/PreClickModal';
import Notification from './components/Notification';

import FloatingKeyOverlay from './pages/FloatingKeyOverlay';
import RegionSelectorOverlay from './pages/RegionSelectorOverlay';

import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import QRScanner from './pages/QRScanner';
import AIHelpline from './pages/AIHelpline';
import Chatbot from './pages/Chatbot';
import BackgroundProtection from './pages/BackgroundProtection';

import AndroidCompanion from './pages/AndroidCompanion';
import ScamReporter from './pages/ScamReporter';
import ScanHistory from './pages/ScanHistory';
import Profile from './pages/Profile';
import Login from './pages/Login';
import LoginPassword from './pages/LoginPassword';
import Register from './pages/Register';
import OTPVerification from './pages/OTPVerification';
import PasswordSetup from './pages/PasswordSetup';
import ProfileOnboarding from './pages/ProfileOnboarding';

// Protected Route Guard
const ProtectedRoute = ({ children, requireProfile = true }) => {
  const { isAuthenticated, loading, user } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 text-cyan-400 font-mono text-sm">
        <div className="flex items-center gap-3">
          <span className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin"></span>
          Initializing Shield Session...
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requireProfile && !user?.profile_completed) {
    return <Navigate to="/onboarding" replace />;
  }

  if (!requireProfile && user?.profile_completed) {
    return <Navigate to="/" replace />;
  }

  return children;
};

function AppContent() {
  const location = import.meta.env.VITE_DEV_SERVER_URL ? window.location.pathname : window.location.hash;
  const isOverlay = location.includes('/floating-key') || location.includes('/region-selector');
  const navigate = useNavigate();

  React.useEffect(() => {
    if (window.electronAPI) {
      window.electronAPI.onOpenScanDetails(() => {
        // Navigate to background protection to see details
        navigate('/background-protection');
      });
    }
  }, [navigate]);

  if (isOverlay) {
    return (
      <Routes>
        <Route path="/floating-key" element={<FloatingKeyOverlay />} />
        <Route path="/region-selector" element={<RegionSelectorOverlay />} />
      </Routes>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#080c14] text-slate-100 selection:bg-cyan-500 selection:text-black">
      <Navbar />
      <main className="flex-1">
              <Routes>
                {/* Public Auth Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/login-password" element={<LoginPassword />} />
                <Route path="/register" element={<Register />} />
                <Route path="/verify-otp" element={<OTPVerification />} />
                <Route path="/setup-password" element={<PasswordSetup />} />

                {/* Protected Core Platform Routes */}
                <Route
                  path="/onboarding"
                  element={
                    <ProtectedRoute requireProfile={false}>
                      <ProfileOnboarding />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <Dashboard />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/scanner"
                  element={
                    <ProtectedRoute>
                      <Scanner />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/qr-scanner"
                  element={
                    <ProtectedRoute>
                      <QRScanner />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/helpline"
                  element={
                    <ProtectedRoute>
                      <AIHelpline />
                    </ProtectedRoute>
                  }
                />
                {/* Legacy redirect for simulations */}
                <Route path="/simulations" element={<Navigate to="/helpline" replace />} />
                <Route
                  path="/chatbot"
                  element={
                    <ProtectedRoute>
                      <Chatbot />
                    </ProtectedRoute>
                  }
                />

                <Route
                  path="/background-protection"
                  element={
                    <ProtectedRoute>
                      <BackgroundProtection />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/android-companion"
                  element={
                    <ProtectedRoute>
                      <AndroidCompanion />
                    </ProtectedRoute>
                  }
                />
                {/* Legacy redirect for threat map */}
                <Route path="/threat-map" element={<Navigate to="/background-protection" replace />} />
                <Route
                  path="/report-scam"
                  element={
                    <ProtectedRoute>
                      <ScamReporter />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/history"
                  element={
                    <ProtectedRoute>
                      <ScanHistory />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/profile"
                  element={
                    <ProtectedRoute>
                      <Profile />
                    </ProtectedRoute>
                  }
                />

                {/* Fallback */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
      </main>

      {/* Global Modals & Notifications */}
      <PreClickModal />
      <Notification />
    </div>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <ThreatProvider>
          <AppContent />
        </ThreatProvider>
      </AuthProvider>
    </Router>
  );
}

export default App;
