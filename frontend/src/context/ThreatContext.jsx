import React, { createContext, useContext, useState } from 'react';
import api from '../services/api';

const ThreatContext = createContext(null);

export const ThreatProvider = ({ children }) => {
  const [activeScan, setActiveScan] = useState(null);
  const [scanContext, setScanContext] = useState(null);
  const [preClickModalState, setPreClickModalState] = useState({
    isOpen: false,
    url: '',
    data: null,
    onProceed: null,
  });
  const [toasts, setToasts] = useState([]);

  const addToast = (message, type = 'info', duration = 4000) => {
    const id = Math.random().toString(36).substring(2, 9);
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      removeToast(id);
    }, duration);
  };

  const removeToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const updateScanContext = (newContext) => {
    setScanContext(newContext);
  };

  const clearScanContext = () => {
    setScanContext(null);
  };

  const triggerPreClickCheck = async (url, onProceedCallback = null) => {
    try {
      const res = await api.get('/scan/pre-click', { params: { url } });
      const checkData = res.data;

      if (checkData.should_block) {
        setPreClickModalState({
          isOpen: true,
          url,
          data: checkData,
          onProceed: onProceedCallback,
        });
        return false; // Intercepted
      } else {
        if (onProceedCallback) onProceedCallback();
        return true;
      }
    } catch (err) {
      console.warn('Pre-click check error:', err);
      if (onProceedCallback) onProceedCallback();
      return true;
    }
  };

  const closePreClickModal = () => {
    setPreClickModalState((prev) => ({ ...prev, isOpen: false }));
  };

  return (
    <ThreatContext.Provider
      value={{
        activeScan,
        setActiveScan,
        scanContext,
        updateScanContext,
        clearScanContext,
        triggerPreClickCheck,
        preClickModalState,
        closePreClickModal,
        toasts,
        addToast,
        removeToast,
      }}
    >
      {children}
    </ThreatContext.Provider>
  );
};

export const useThreat = () => {
  const context = useContext(ThreatContext);
  if (!context) {
    throw new Error('useThreat must be used within a ThreatProvider');
  }
  return context;
};
