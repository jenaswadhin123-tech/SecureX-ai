import React, { useEffect, useState } from 'react';
import { Globe2, ShieldCheck, Activity, RefreshCw, CheckCircle2, AlertCircle } from 'lucide-react';
import { checkHealth } from '../services/api';

export default function Header({ onRefresh }) {
  const [healthy, setHealthy] = useState(true);

  const verifyBackend = async () => {
    const isUp = await checkHealth();
    setHealthy(isUp);
  };

  useEffect(() => {
    verifyBackend();
    const interval = setInterval(verifyBackend, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="bg-cardBg border-b border-cardBorder px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
      <div className="flex items-center space-x-3">
        <div className="relative p-2.5 bg-blue-500/10 border border-blue-500/20 rounded-xl text-accentBlue">
          <Globe2 className="w-8 h-8" strokeWidth={1.7} />
          <ShieldCheck className="absolute -right-1 -bottom-1 w-4 h-4 rounded-full bg-accentBlue text-white" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            CYBERGUARD <span className="text-xs font-mono px-2 py-0.5 rounded bg-accentBlue/10 text-accentBlue border border-accentBlue/20">v1.0</span>
          </h1>
          <p className="text-xs text-secondaryText">Real-Time Autonomous Threat Detection Engine</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-xs font-mono px-3 py-1.5 rounded-lg bg-darkBg border border-cardBorder">
          <Activity className="w-4 h-4 text-accentBlue animate-pulse" />
          <span className="text-secondaryText">Backend API:</span>
          {healthy ? (
            <span className="text-emerald-400 font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> ONLINE
            </span>
          ) : (
            <span className="text-rose-400 font-semibold flex items-center gap-1">
              <AlertCircle className="w-3.5 h-3.5" /> OFFLINE
            </span>
          )}
        </div>

        <button
          onClick={onRefresh}
          className="flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-darkBg border border-cardBorder hover:border-accentBlue hover:text-accentBlue rounded-lg transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
}
