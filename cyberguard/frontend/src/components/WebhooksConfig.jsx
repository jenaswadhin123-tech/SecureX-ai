import React, { useState } from 'react';
import { Bell, Send, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';
import { testWebhookAlert } from '../services/api';

export default function WebhooksConfig() {
  const [webhookUrl, setWebhookUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);

  const handleTestAlert = async (e) => {
    e.preventDefault();
    if (!webhookUrl.trim()) return;
    setLoading(true);
    setStatusMsg(null);

    try {
      const res = await testWebhookAlert(webhookUrl.trim());
      if (res.status === 'success') {
        setStatusMsg({ success: true, text: res.message });
      } else {
        setStatusMsg({ success: false, text: res.message });
      }
    } catch (err) {
      setStatusMsg({ success: false, text: 'Failed to test webhook alert. Check backend connection.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-cardBg border border-cardBorder p-6 rounded-xl space-y-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-rose-500/10 text-rose-400 rounded-lg border border-rose-500/20">
            <Bell className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Real-Time Threat Alerting & Webhooks</h3>
            <p className="text-xs text-secondaryText">Configure Slack, Discord, or custom HTTP POST webhooks for HIGH/CRITICAL incident alerts.</p>
          </div>
        </div>

        <form onSubmit={handleTestAlert} className="space-y-4 pt-2">
          <div>
            <label className="block text-xs font-semibold text-secondaryText uppercase tracking-wider mb-2">
              Webhook Endpoint URL
            </label>
            <input
              type="text"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="e.g. https://hooks.slack.com/services/... or https://discord.com/api/webhooks/..."
              className="w-full bg-darkBg border border-cardBorder focus:border-accentBlue rounded-xl px-4 py-3 text-xs font-mono text-white focus:outline-none transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading || !webhookUrl.trim()}
            className="px-6 py-2.5 bg-accentBlue hover:bg-blue-600 disabled:opacity-50 text-white font-medium text-xs rounded-lg transition-colors flex items-center space-x-2"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            <span>{loading ? 'Sending Test Alert...' : 'Dispatch Test Alert'}</span>
          </button>
        </form>

        {statusMsg && (
          <div
            className={`p-4 rounded-xl border text-xs flex items-center space-x-2 ${
              statusMsg.success
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                : 'bg-rose-500/10 border-rose-500/20 text-rose-400'
            }`}
          >
            {statusMsg.success ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
            <span>{statusMsg.text}</span>
          </div>
        )}
      </div>
    </div>
  );
}
