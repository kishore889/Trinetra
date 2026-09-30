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
import { IdentityAnalysisPage } from './pages/IdentityAnalysisPage';

import { ResponseActionsPage } from './pages/ResponseActionsPage';
import { ThreatRegistryPage } from './pages/ThreatRegistryPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { SystemHealthPage } from './pages/SystemHealthPage';
import { SettingsPage } from './pages/SettingsPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { SourcesPage } from './pages/SourcesPage';
import { IndicatorsPage } from './pages/IndicatorsPage';
import { AlertsPage } from './pages/AlertsPage';
import { ReviewQueuePage } from './pages/ReviewQueuePage';

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();

  const getPageTitle = (path: string) => {
    switch (path) {
      case '/': return 'SOC Overview Dashboard';
      case '/analytics': return 'Telemetry & Detection Analytics';
      case '/threats': return 'Active Threat Intelligence Feeds';
      case '/sources': return 'Threat Intelligence Sources & Providers';
      case '/indicators': return 'IOC Threat Indicator Registry';
      case '/graph': return 'Threat Intelligence Graph Engine';
      case '/live-emails': return 'Live Ingestion Monitoring';
      case '/investigations': return 'Deep Threat Investigation Workspace';
      case '/quarantine': return 'Gmail Response & Action Engine';
      case '/alerts': return 'Security Alerts & Notifications';
      case '/review': return 'Human-in-the-Loop Analyst Review Queue';
      case '/incidents': return 'Security Incident Response';
      case '/copilot': return 'TRINETRA SOC Co-Pilot';
      case '/demo': return 'Interactive Threat Simulation Center';
      case '/analyze/identity': return 'Identity & Spoofing Intelligence';
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
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/threats" element={<ThreatRegistryPage />} />
          <Route path="/sources" element={<SourcesPage />} />
          <Route path="/indicators" element={<IndicatorsPage />} />
          <Route path="/graph" element={<ThreatGraphPage />} />
          <Route path="/live-emails" element={<LiveEmailsPage />} />
          <Route path="/investigations" element={<InvestigationPage />} />
          <Route path="/analyze/identity" element={<IdentityAnalysisPage />} />
          <Route path="/quarantine" element={<ResponseActionsPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/review" element={<ReviewQueuePage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/copilot" element={<CopilotPage />} />
          <Route path="/demo" element={<DemoCenterPage />} />
          <Route path="/gmail" element={<GmailConnectionPage />} />
          <Route path="/health" element={<SystemHealthPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
};


export default App;
