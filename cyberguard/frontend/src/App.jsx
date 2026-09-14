import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Overview from './components/Overview';
import UrlScanner from './components/UrlScanner';
import PhishingAnalyzer from './components/PhishingAnalyzer';
import AccountAnalyzer from './components/AccountAnalyzer';
import VoiceAnalyzer from './components/VoiceAnalyzer';
import EventInspector from './components/EventInspector';
import WebhooksConfig from './components/WebhooksConfig';
import { fetchEvents, fetchTotalCount } from './services/api';
import { LayoutDashboard, Link as LinkIcon, Mail, UserCheck, Database, Bell, Mic } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);

  const REFRESH_INTERVAL_MS = 30_000; // 30 seconds

  const loadData = async () => {
    setLoading(true);
    try {
      // Fetch events and total count in parallel
      const [data, count] = await Promise.all([
        fetchEvents(0, 100),
        fetchTotalCount(),
      ]);
      setEvents(data);
      setTotalCount(count);
    } catch (e) {
      console.error('Failed to load dashboard data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // Auto-refresh every 30 seconds so the dashboard stays live
    const timer = setInterval(loadData, REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, []);

  const tabs = [
    { id: 'overview', label: 'Overview & Analytics', icon: LayoutDashboard },
    { id: 'url', label: 'URL Scanner', icon: LinkIcon },
    { id: 'phishing', label: 'Phishing Analyzer', icon: Mail },
    { id: 'account', label: 'Account Log Analyzer', icon: UserCheck },
    { id: 'voice', label: 'Voice Analyzer', icon: Mic },
    { id: 'inspector', label: 'Event Inspector', icon: Database },
    { id: 'webhooks', label: 'Alert Webhooks', icon: Bell },
  ];

  return (
    <div className="min-h-screen bg-darkBg text-primaryText flex flex-col font-sans">
      <Header onRefresh={loadData} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Navigation Tabs */}
        <div className="border-b border-cardBorder flex space-x-1 sm:space-x-4 overflow-x-auto pb-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-3 text-xs sm:text-sm font-medium border-b-2 whitespace-nowrap transition-all ${
                  isActive
                    ? 'border-accentBlue text-accentBlue font-semibold bg-accentBlue/5'
                    : 'border-transparent text-secondaryText hover:text-white hover:border-cardBorder'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-accentBlue' : 'text-secondaryText'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Content Panels */}
        <div className="pt-2">
          {activeTab === 'overview' && <Overview events={events} totalCount={totalCount} />}
          {activeTab === 'url' && <UrlScanner onEventGenerated={loadData} />}
          {activeTab === 'phishing' && <PhishingAnalyzer onEventGenerated={loadData} />}
          {activeTab === 'account' && <AccountAnalyzer onEventGenerated={loadData} />}
          {activeTab === 'voice' && <VoiceAnalyzer onEventGenerated={loadData} />}
          {activeTab === 'inspector' && <EventInspector events={events} />}
          {activeTab === 'webhooks' && <WebhooksConfig />}
        </div>
      </main>

      <footer className="border-t border-cardBorder py-4 px-6 text-center text-xs text-secondaryText">
        CYBERGUARD Enterprise Security System — Real-time Autonomous Threat Monitoring Engine
      </footer>
    </div>
  );
}
