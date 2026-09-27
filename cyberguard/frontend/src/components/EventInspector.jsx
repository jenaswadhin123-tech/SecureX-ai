import React, { useState } from 'react';
import { Database, Loader2, Terminal, Download } from 'lucide-react';
import { exportEventsCSV } from '../services/api';

export default function EventInspector({ events }) {
  const [selectedId, setSelectedId] = useState(events.length > 0 ? events[0].id : '');
  const [exporting, setExporting] = useState(false);

  const selectedEvent = events.find(e => e.id === selectedId) || events[0];

  const handleExportCSV = async () => {
    setExporting(true);
    try {
      await exportEventsCSV();
    } catch (e) {
      alert('Failed to export events. Make sure the backend is running.');
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-cardBg border border-cardBorder p-6 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-500/10 text-accentBlue rounded-lg border border-blue-500/20">
              <Database className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Threat Event Deep Inspector</h3>
              <p className="text-xs text-secondaryText">Inspect detailed ThreatEvent document schemas and generate AI root-cause analysis.</p>
            </div>
          </div>

          {/* Export CSV button */}
          <button
            onClick={handleExportCSV}
            disabled={exporting || events.length === 0}
            className="px-4 py-2 bg-darkBg border border-emerald-500/40 hover:border-emerald-400 hover:text-emerald-400 text-xs font-medium text-emerald-500 rounded-lg transition-all flex items-center space-x-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {exporting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            <span>{exporting ? 'Exporting...' : 'Export CSV'}</span>
          </button>
        </div>

        {events.length > 0 ? (
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">Select Event ID</label>
              <select
                value={selectedId}
                onChange={(e) => {
                  setSelectedId(e.target.value);
                }}
                className="w-full bg-darkBg border border-cardBorder focus:border-accentBlue rounded-xl px-4 py-2.5 text-xs font-mono text-white focus:outline-none"
              >
                {events.map((evt) => (
                  <option key={evt.id} value={evt.id}>
                    {evt.id} — {evt.threat_category || 'EVENT'} [{evt.risk_level || 'UNKNOWN'}] ({evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A'})
                  </option>
                ))}
              </select>
            </div>

            {selectedEvent && (
              <div className="space-y-4 pt-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-secondaryText flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-accentBlue" /> RAW ThreatEvent Payload
                  </span>

                </div>

                <pre className="p-4 bg-darkBg border border-cardBorder rounded-xl text-xs font-mono text-emerald-400 overflow-x-auto max-h-96">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>

              </div>
            )}
          </div>
        ) : (
          <div className="p-8 text-center text-secondaryText text-sm font-sans">
            No logged threat events available in the system yet. Run scans using the other tabs first!
          </div>
        )}
      </div>
    </div>
  );
}
