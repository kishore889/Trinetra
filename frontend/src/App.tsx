import React from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { DashboardPage } from './pages/DashboardPage';
import { LiveEmailsPage } from './pages/LiveEmailsPage';
import { InvestigationPage } from './pages/InvestigationPage';
import { ThreatGraphPage } from './pages/ThreatGraphPage';
import { CopilotPage } from './pages/CopilotPage';
import { DemoCenterPage } from './pages/DemoCenterPage';
import { GmailConnectionPage } from './pages/GmailConnectionPage';
import { GenericPage } from './pages/GenericPages';

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();

  const getPageTitle = (path: string) => {
    switch (path) {
      case '/': return 'SOC Overview Dashboard';
      case '/analytics': return 'Telemetry & Detection Analytics';
      case '/threats': return 'Active Threat Intelligence Feeds';
      case '/graph': return 'Threat Intelligence Graph Engine';
      case '/live-emails': return 'Live Ingestion Monitoring';
      case '/investigations': return 'Deep Threat Investigation Workspace';
      case '/quarantine': return 'Quarantined Email Records';
      case '/incidents': return 'Security Incident Response';
      case '/copilot': return 'TRINETRA SOC Co-Pilot';
      case '/demo': return 'Interactive Threat Simulation Center';
      case '/gmail': return 'Gmail OAuth & Pub/Sub Connection';
      case '/health': return 'Platform Service Diagnostics';
      case '/settings': return 'SOC System Settings';
      default: return 'SOC Console';
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-bg-darkest text-text-primary">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Topbar currentRouteName={getPageTitle(location.pathname)} />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/analytics" element={<GenericPage title="Analytics & Trends" subtitle="Long-term telemetry and intelligence distribution statistics" />} />
          <Route path="/threats" element={<GenericPage title="Threat Registry" subtitle="Global and local IOC registries integrated across CERT-In, Safe Browsing, and VT" />} />
          <Route path="/graph" element={<ThreatGraphPage />} />
          <Route path="/live-emails" element={<LiveEmailsPage />} />
          <Route path="/investigations" element={<InvestigationPage />} />
          <Route path="/quarantine" element={<GenericPage title="Quarantine Vault" subtitle="Isolated high-risk email messages held for compliance and inspection" />} />
          <Route path="/incidents" element={<GenericPage title="Incident Management" subtitle="Formal incident tracking, escalation protocols, and analyst assignments" />} />
          <Route path="/copilot" element={<CopilotPage />} />
          <Route path="/demo" element={<DemoCenterPage />} />
          <Route path="/gmail" element={<GmailConnectionPage />} />
          <Route path="/health" element={<GenericPage title="System Health" subtitle="Real-time status of backend services, PostgreSQL connection, and detection layers" />} />
          <Route path="/settings" element={<GenericPage title="Platform Settings" subtitle="Risk engine weights, sensitivity thresholds, and notifications" />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
};

export default App;
