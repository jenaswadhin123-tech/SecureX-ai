import React, { useState } from 'react';
import { Link as LinkIcon, Search, ShieldCheck, ShieldAlert, Loader2, Info } from 'lucide-react';
import { analyzeUrl } from '../services/api';

export default function UrlScanner({ onEventGenerated }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await analyzeUrl(url.trim());
      setResult(res);
      if (onEventGenerated) onEventGenerated();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to scan URL. Please verify backend is running.');
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
          <div className="p-2 bg-blue-500/10 text-accentBlue rounded-lg border border-blue-500/20">
            <LinkIcon className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Live URL Reputation Scanner</h3>
            <p className="text-xs text-secondaryText">Inspects target domains against Google Safe Browsing and local blocklists.</p>
          </div>
        </div>

        <form onSubmit={handleScan} className="mt-5 space-y-4">
          <div className="relative">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="e.g. http://phishingsite.com or https://example.com"
              className="w-full bg-darkBg border border-cardBorder focus:border-accentBlue rounded-xl px-4 py-3 pl-11 text-sm text-white focus:outline-none transition-colors"
            />
            <Search className="w-4 h-4 text-secondaryText absolute left-4 top-3.5" />
          </div>

          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="w-full sm:w-auto px-6 py-2.5 bg-accentBlue hover:bg-violet-700 disabled:opacity-50 text-white font-medium text-sm rounded-lg transition-colors flex items-center justify-center space-x-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'Scanning Reputation...' : 'Scan URL Reputation'}</span>
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
              <span className="text-xs font-mono text-secondaryText uppercase tracking-wider">Analysis Result</span>
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
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Detected Threat Evidence</h5>
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
              <span>No malicious domain hits or Google Safe Browsing flags detected.</span>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations && result.recommendations.length > 0 && (
            <div>
              <h5 className="text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Recommended Actions</h5>
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

          {/* AI Explanation Modal / Box */}
        </div>
      )}
    </div>
  );
}
