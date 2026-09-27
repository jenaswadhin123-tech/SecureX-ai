import React, { useState } from 'react';
import { Activity, Loader2, Search, ShieldAlert } from 'lucide-react';
import { analyzeCyberThreat } from '../services/api';
import RiskGauge from './RiskGauge';

const EXAMPLE_EVENTS = JSON.stringify([
  {
    event_type: 'network',
    user: 'service-account',
    direction: 'egress',
    destination_port: 4444,
    bytes_out: 115343360,
  },
  {
    event_type: 'api_request',
    user: 'service-account',
    status_code: 429,
    request_count: 25,
  },
  {
    event_type: 'endpoint_alert',
    user: 'workstation-17',
    threat_indicator: 'Example.Malware.Indicator',
  },
], null, 2);

export default function CyberThreatAnalyzer({ onEventGenerated }) {
  const [eventsText, setEventsText] = useState(EXAMPLE_EVENTS);
  const [windowMinutes, setWindowMinutes] = useState(15);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleAnalyze = async (event) => {
    event.preventDefault();
    setError('');
    setResult(null);

    let events;
    try {
      events = JSON.parse(eventsText);
      if (!Array.isArray(events) || events.length === 0) {
        throw new Error('Enter a non-empty JSON array of events.');
      }
    } catch (parseError) {
      setError(parseError.message || 'Enter valid JSON.');
      return;
    }

    setLoading(true);
    try {
      const analysis = await analyzeCyberThreat(events, Number(windowMinutes));
      setResult(analysis);
      onEventGenerated?.();
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Cyber threat analysis failed. Check the backend service.');
    } finally {
      setLoading(false);
    }
  };

  const evidenceValue = (value) =>
    typeof value === 'object' ? JSON.stringify(value) : String(value);

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <section className="bg-cardBg border border-cardBorder p-6 rounded-xl">
        <div className="flex items-center gap-3 mb-5">
          <div className="p-2 bg-rose-500/10 text-rose-400 rounded-lg border border-rose-500/20">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Cyber Threat Event Analyzer</h3>
            <p className="text-xs text-secondaryText">Correlates endpoint, API, network, user, and system-log indicators.</p>
          </div>
        </div>

        <form onSubmit={handleAnalyze} className="space-y-4">
          <label className="block text-xs font-medium text-secondaryText" htmlFor="cyber-event-window">
            Analysis window (minutes)
          </label>
          <input
            id="cyber-event-window"
            type="number"
            min="1"
            max="1440"
            value={windowMinutes}
            onChange={(event) => setWindowMinutes(event.target.value)}
            className="w-32 bg-darkBg border border-cardBorder rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accentBlue"
          />
          <label className="block text-xs font-medium text-secondaryText" htmlFor="cyber-event-json">
            Security events (JSON array)
          </label>
          <textarea
            id="cyber-event-json"
            rows={12}
            value={eventsText}
            onChange={(event) => setEventsText(event.target.value)}
            spellCheck="false"
            className="w-full bg-darkBg border border-cardBorder focus:border-accentBlue rounded-xl p-4 text-xs text-white font-mono focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading || !eventsText.trim()}
            className="px-6 py-2.5 bg-accentBlue hover:bg-violet-700 disabled:opacity-50 text-white font-medium text-sm rounded-lg transition-colors flex items-center gap-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'Analyzing Events...' : 'Analyze Security Events'}</span>
          </button>
        </form>

        {error && <p role="alert" className="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg">{error}</p>}
      </section>

      {result && (
        <section className="bg-cardBg border border-cardBorder p-6 rounded-xl space-y-5">
          <div className="rounded-xl border border-cardBorder bg-darkBg/60 p-4">
            <RiskGauge score={result.risk_score || 0} level={result.risk_level || 'SAFE'} label="THREAT SCORE" />
          </div>
          {result.evidence?.length ? (
            <div className="divide-y divide-cardBorder border border-cardBorder rounded-lg overflow-hidden bg-darkBg">
              {result.evidence.map((item, index) => (
                <div key={`${item.name}-${index}`} className="px-4 py-3 grid gap-1 sm:grid-cols-[minmax(12rem,0.7fr)_minmax(0,1.3fr)] text-xs font-mono">
                  <span className="text-rose-400 font-semibold">{item.name}</span>
                  <span className="text-secondaryText break-all">{evidenceValue(item.value)}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg">No configured threat indicators found in this batch.</p>
          )}
          <ul className="space-y-2 text-xs text-primaryText">
            {result.recommendations?.map((recommendation) => <li key={recommendation}>{recommendation}</li>)}
          </ul>
          <p className="text-xs text-secondaryText">{result.explanation}</p>
        </section>
      )}
    </div>
  );
}