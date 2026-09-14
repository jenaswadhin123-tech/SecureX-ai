import React from 'react';
import { ShieldAlert, ShieldCheck, Zap, Layers, AlertTriangle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, CartesianGrid } from 'recharts';

export default function Overview({ events, totalCount }) {
  const highCritical = events.filter(e => ['HIGH', 'CRITICAL'].includes(e.risk_level?.toUpperCase())).length;
  const latestCategory = events.length > 0 ? events[0].threat_category || 'N/A' : 'N/A';
  const activeSources = new Set(events.map(e => e.source)).size;

  // Prepare Bar Chart Data
  const riskLevels = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const riskCounts = riskLevels.map(level => ({
    level,
    count: events.filter(e => (e.risk_level || '').toUpperCase() === level).length
  }));

  // Prepare Time Series Data
  const getHourlyData = () => {
    const hoursMap = {};
    for (let i = 23; i >= 0; i--) {
      const d = new Date();
      d.setHours(d.getHours() - i);
      const label = `${d.getHours().toString().padStart(2, '0')}:00`;
      hoursMap[label] = 0;
    }

    events.forEach(e => {
      if (e.timestamp) {
        const date = new Date(e.timestamp);
        const label = `${date.getHours().toString().padStart(2, '0')}:00`;
        if (hoursMap[label] !== undefined) {
          hoursMap[label] += 1;
        }
      }
    });

    return Object.keys(hoursMap).map(hour => ({ time: hour, count: hoursMap[hour] }));
  };

  const timeData = getHourlyData();

  const getRiskBadge = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      case 'HIGH': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM': return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
      case 'LOW': return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      default: return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-cardBg border border-cardBorder p-5 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-xs text-secondaryText font-medium uppercase tracking-wider">Total Events Logged</p>
            <h3 className="text-2xl font-bold font-mono text-white mt-1">{totalCount}</h3>
          </div>
          <div className="p-3 bg-blue-500/10 text-accentBlue rounded-lg border border-blue-500/20">
            <Layers className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-cardBg border border-cardBorder p-5 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-xs text-secondaryText font-medium uppercase tracking-wider">High / Critical Threats</p>
            <h3 className="text-2xl font-bold font-mono text-rose-400 mt-1">{highCritical}</h3>
          </div>
          <div className="p-3 bg-rose-500/10 text-rose-400 rounded-lg border border-rose-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-cardBg border border-cardBorder p-5 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-xs text-secondaryText font-medium uppercase tracking-wider">Latest Threat Type</p>
            <h3 className="text-sm font-semibold font-mono text-white mt-1 truncate max-w-[140px]" title={latestCategory}>
              {latestCategory}
            </h3>
          </div>
          <div className="p-3 bg-amber-500/10 text-amber-400 rounded-lg border border-amber-500/20">
            <Zap className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-cardBg border border-cardBorder p-5 rounded-xl flex items-center justify-between">
          <div>
            <p className="text-xs text-secondaryText font-medium uppercase tracking-wider">Active Services</p>
            <h3 className="text-2xl font-bold font-mono text-white mt-1">{activeSources || 1}</h3>
          </div>
          <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Visual Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Bar Chart */}
        <div className="bg-cardBg border border-cardBorder p-5 rounded-xl">
          <h4 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-accentBlue" /> Risk Level Distribution
          </h4>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskCounts}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30343B" vertical={false} />
                <XAxis dataKey="level" stroke="#A1A1AA" tick={{ fontSize: 12 }} />
                <YAxis stroke="#A1A1AA" tick={{ fontSize: 12 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#141820', borderColor: '#30343B', borderRadius: '8px', color: '#F5F5F5' }}
                />
                <Bar dataKey="count" fill="#3B9EFF" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Time-series Line Chart */}
        <div className="bg-cardBg border border-cardBorder p-5 rounded-xl">
          <h4 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Zap className="w-4 h-4 text-accentBlue" /> Threat Frequency (24h Window)
          </h4>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#30343B" vertical={false} />
                <XAxis dataKey="time" stroke="#A1A1AA" tick={{ fontSize: 10 }} />
                <YAxis stroke="#A1A1AA" tick={{ fontSize: 12 }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#141820', borderColor: '#30343B', borderRadius: '8px', color: '#F5F5F5' }}
                />
                <Line type="monotone" dataKey="count" stroke="#10B981" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="bg-cardBg border border-cardBorder rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-cardBorder flex items-center justify-between">
          <h4 className="text-sm font-semibold text-white">Recent Threat Stream (Latest 10)</h4>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-darkBg text-xs uppercase font-mono text-secondaryText border-b border-cardBorder">
              <tr>
                <th className="px-5 py-3">Event ID</th>
                <th className="px-5 py-3">Timestamp</th>
                <th className="px-5 py-3">Category</th>
                <th className="px-5 py-3">Risk Level</th>
                <th className="px-5 py-3">Score</th>
                <th className="px-5 py-3">Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cardBorder font-mono text-xs text-primaryText">
              {events.slice(0, 10).map((evt, idx) => (
                <tr key={evt.id || idx} className="hover:bg-darkBg/50 transition-colors">
                  <td className="px-5 py-3 text-accentBlue">{evt.id ? evt.id.substring(0, 12) : 'N/A'}</td>
                  <td className="px-5 py-3 text-secondaryText">
                    {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A'}
                  </td>
                  <td className="px-5 py-3 font-semibold">{evt.threat_category || 'N/A'}</td>
                  <td className="px-5 py-3">
                    <span className={`px-2.5 py-1 rounded-full border text-[10px] font-bold ${getRiskBadge(evt.risk_level)}`}>
                      {evt.risk_level || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className="px-5 py-3">{evt.risk_score ?? 0}</td>
                  <td className="px-5 py-3 text-secondaryText">{evt.source || 'system'}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-5 py-8 text-center text-secondaryText font-sans">
                    No threat events logged yet. Use the scanner tabs above to test!
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
