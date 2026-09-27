import React, { useState } from 'react';
import { UserCheck, Search, ShieldCheck, Loader2 } from 'lucide-react';
import { analyzeAccount } from '../services/api';

export default function AccountAnalyzer({ onEventGenerated }) {
  const [log, setLog] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    if (!log.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await analyzeAccount(log.trim());
      setResult(res);
      if (onEventGenerated) onEventGenerated();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to analyze log. Please check backend API.');
    } finally {
      setLoading(false);
    }
  };

  const getVerdictStyle = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'border-rose-500/40 bg-rose-500/10 text-rose-400';
      case 'HIGH': return 'border-orange-500/40 bg-orange-500/10 text-orange-400';
      case 'MEDIUM': return 'border-amber-500/40 bg-amber-500/10 text-amber-400';
      case 'LOW': return 'border-blue-500/40 bg-blue-500/10 text-blue-400';
      default: return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-cardBg border border-cardBorder p-6 rounded-xl">
        <div className="flex items-center space-x-3 mb-2">
          <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
            <UserCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Account Authentication Log Analyzer</h3>
            <p className="text-xs text-secondaryText">Inspects login attempt patterns for brute-force attacks or anomalous activity.</p>
          </div>
        </div>

        <form onSubmit={handleScan} className="mt-5 space-y-4">
          <textarea
            rows={5}
            value={log}
            onChange={(e) => setLog(e.target.value)}
            placeholder={"2026-01-01T00:00:00 alice 10.0.0.1 success device=laptop-1\n2026-01-02T00:00:00 alice 10.0.0.2 success device=phone-2"}
            className="w-full bg-darkBg border border-cardBorder focus:border-accentBlue rounded-xl p-4 text-sm text-white focus:outline-none transition-colors font-mono"
          />

          <button
            type="submit"
            disabled={loading || !log.trim()}
            className="w-full sm:w-auto px-6 py-2.5 bg-accentBlue hover:bg-violet-700 disabled:opacity-50 text-white font-medium text-sm rounded-lg transition-colors flex items-center justify-center space-x-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'Analyzing Log Entries...' : 'Analyze Authentication Log'}</span>
          </button>
        </form>

        {error && (
          <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">
            {error}
          </div>
        )}
      </div>

      {result && (
        <div className="bg-cardBg border border-cardBorder p-6 rounded-xl space-y-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-cardBorder">
            <div>
              <span className="text-xs font-mono text-secondaryText uppercase tracking-wider">Account Risk Verdict</span>
              <h4 className="text-xl font-bold text-white mt-1 flex items-center gap-2">
                Verdict: <span className={`px-3 py-1 rounded-full border text-xs font-extrabold ${getVerdictStyle(result.risk_level)}`}>
                  {result.risk_level || 'SAFE'} ({result.risk_score || 0}/100)
                </span>
              </h4>
            </div>

          </div>

          {/* Evidence Items */}
          {result.evidence && result.evidence.length > 0 ? (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Suspicious Log Evidence</h5>
              <div className="divide-y divide-cardBorder border border-cardBorder rounded-lg overflow-hidden bg-darkBg">
                {result.evidence.map((item, i) => (
                  <div key={i} className="px-4 py-2.5 flex items-center justify-between text-xs font-mono">
                    <span className="text-rose-400 font-semibold">{item.name}</span>
                    <span className="text-secondaryText">Weight: +{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              <span>Authentication pattern appears normal. No brute-force or malicious log indicators detected.</span>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations && result.recommendations.length > 0 && (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Security Guidelines</h5>
              <ul className="space-y-1.5 text-xs text-primaryText">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-center space-x-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-accentBlue"></span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* AI Explanation Box */}
        </div>
      )}
    </div>
  );
}
