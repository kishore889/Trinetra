import React, { useState, useEffect } from 'react';
import { 
  Mail, 
  ShieldAlert, 
  AlertTriangle, 
  Lock, 
  Radar, 
  Fingerprint, 
  Layers, 
  Flame, 
  ChevronRight,
  Radio,
  Clock,
  RefreshCw,
  AlertCircle
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell 
} from 'recharts';
import { MetricCard, ThreatBadge, DecisionBadge } from '../components/UIElements';
import { mockDetections } from '../data/mockData';
import { useNavigate } from 'react-router-dom';

const trendData = [
  { time: '00:00', critical: 2, high: 5, medium: 12, low: 25 },
  { time: '04:00', critical: 1, high: 3, medium: 8, low: 18 },
  { time: '08:00', critical: 8, high: 14, medium: 28, low: 62 },
  { time: '12:00', critical: 14, high: 22, medium: 35, low: 88 },
  { time: '16:00', critical: 9, high: 18, medium: 31, low: 74 },
  { time: '20:00', critical: 4, high: 9, medium: 19, low: 45 },
];

const riskDistData = [
  { name: 'Critical', value: 18, color: '#FF5C67' },
  { name: 'High', value: 34, color: '#FF9F43' },
  { name: 'Medium', value: 85, color: '#F6D365' },
  { name: 'Low', value: 240, color: '#38D39F' },
];

interface MonitoringStatus {
  monitoring_active: boolean;
  mode: string;
  last_sync: string | null;
  last_event: string | null;
  messages_processed: number;
  processing_errors: number;
  watch_status: string;
  watch_expiry: string | null;
  pubsub_configured: boolean;
}

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [monitor, setMonitor] = useState<MonitoringStatus>({
    monitoring_active: false,
    mode: 'INACTIVE',
    last_sync: null,
    last_event: null,
    messages_processed: 0,
    processing_errors: 0,
    watch_status: 'UNREGISTERED',
    watch_expiry: null,
    pubsub_configured: false,
  });

  const fetchMonitoringTelemetry = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/monitor/status');
      if (res.ok) {
        const data = await res.json();
        setMonitor(data);
      }
    } catch {
      // offline/mock
    }
  };

  useEffect(() => {
    fetchMonitoringTelemetry();
    const interval = setInterval(fetchMonitoringTelemetry, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Real Monitoring Telemetry Banner */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${monitor.monitoring_active ? 'bg-status-low shadow-[0_0_10px_#38D39F]' : 'bg-status-critical'}`} />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-text-primary font-mono uppercase tracking-wider">
                  Gmail Event Telemetry: {monitor.monitoring_active ? 'Active' : 'Standby'}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-surface-card border border-surface-border text-teal-accent">
                  Mode: {monitor.mode === 'PUBSUB_PUSH' ? 'Google Cloud Pub/Sub (Production)' : monitor.mode === 'DEV_POLLING' ? 'Development Polling Fallback' : 'Inactive'}
                </span>
              </div>
              <p className="text-[11px] text-text-muted mt-0.5">
                {monitor.mode === 'PUBSUB_PUSH'
                  ? 'Push notifications ingested via Gmail Watch & Google Cloud Pub/Sub Webhook.'
                  : 'Development polling active. Configure Google Cloud Pub/Sub in .env for production push triggers.'}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-text-secondary border-t md:border-t-0 md:border-l border-surface-border pt-2 md:pt-0 md:pl-4">
            <div>
              <span className="text-[10px] text-text-muted block">WATCH EXPIRY</span>
              <span className={monitor.watch_status === 'ACTIVE' ? 'text-status-low font-bold' : 'text-text-muted'}>
                {monitor.watch_expiry ? new Date(monitor.watch_expiry).toLocaleDateString() : 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-text-muted block">LAST SYNC</span>
              <span className="text-text-primary">
                {monitor.last_sync ? new Date(monitor.last_sync).toLocaleTimeString() : 'Never'}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-text-muted block">ERRORS</span>
              <span className={monitor.processing_errors > 0 ? 'text-status-critical font-bold' : 'text-status-low'}>
                {monitor.processing_errors}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Top 8 SOC Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard title="Emails Analyzed" value={monitor.messages_processed > 0 ? monitor.messages_processed.toLocaleString() : "12,482"} change="+8.4%" isPositive icon={<Mail className="w-5 h-5" />} />
        <MetricCard title="Phishing Detected" value="48" change="+12%" isPositive={false} icon={<ShieldAlert className="w-5 h-5" />} />
        <MetricCard title="Warnings Issued" value="92" change="-3.1%" isPositive icon={<AlertTriangle className="w-5 h-5" />} />
        <MetricCard title="Quarantined" value="38" change="+15%" isPositive={false} icon={<Lock className="w-5 h-5" />} />
        <MetricCard title="Active Threats" value="14" change="+2 new" isPositive={false} icon={<Radar className="w-5 h-5" />} />
        <MetricCard title="Threat Indicators" value="1,840" change="+42" isPositive={false} icon={<Fingerprint className="w-5 h-5" />} />
        <MetricCard title="Active Campaigns" value="3" change="Correlated" isPositive icon={<Layers className="w-5 h-5" />} />
        <MetricCard title="Current Risk Level" value="ELEVATED" change="Score: 72" isPositive={false} icon={<Flame className="w-5 h-5" />} />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-surface-default border border-surface-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-text-primary tracking-wide">Threat Activity by Severity</h2>
              <p className="text-[11px] text-text-muted">Live telemetry ingested across Gmail & simulation feeds</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-status-critical" /> Critical</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-status-high" /> High</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-status-medium" /> Medium</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-status-low" /> Low</span>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF5C67" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#FF5C67" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF9F43" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#FF9F43" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#668582" fontSize={11} tickLine={false} />
                <YAxis stroke="#668582" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#071E1D', borderColor: '#16D9D0', borderRadius: '8px', fontSize: '12px' }}
                  itemStyle={{ color: '#E8FFFD' }}
                />
                <Area type="monotone" dataKey="critical" stroke="#FF5C67" fillOpacity={1} fill="url(#colorCrit)" strokeWidth={2} />
                <Area type="monotone" dataKey="high" stroke="#FF9F43" fillOpacity={1} fill="url(#colorHigh)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-surface-default border border-surface-border rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-primary tracking-wide">Risk Distribution</h2>
            <p className="text-[11px] text-text-muted">Multi-Signal Engine breakdown</p>
          </div>
          <div className="h-44 relative flex items-center justify-center my-auto">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={riskDistData} dataKey="value" innerRadius={50} outerRadius={70} paddingAngle={4}>
                  {riskDistData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#071E1D', borderColor: '#16D9D0', borderRadius: '8px', fontSize: '11px' }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute text-center pointer-events-none">
              <span className="text-xl font-bold font-mono text-text-primary block leading-none">377</span>
              <span className="text-[10px] text-text-muted font-mono uppercase">Total Threats</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono pt-2 border-t border-surface-border">
            {riskDistData.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-text-secondary">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
                  {item.name}
                </span>
                <span className="font-bold text-text-primary">{item.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Detections Table */}
      <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-surface-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-primary tracking-wide">Recent Threat Detections</h2>
            <p className="text-[11px] text-text-muted">Analyzed by 7-layer intelligence pipeline</p>
          </div>
          <button 
            onClick={() => navigate('/investigations')}
            className="flex items-center gap-1 text-xs font-medium text-teal-accent hover:text-teal-vibrant transition-colors"
          >
            <span>View All Investigations</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-text-secondary">
            <thead className="bg-bg-darkest/60 text-text-muted font-mono uppercase tracking-wider text-[10px] border-b border-surface-border">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Email / Subject</th>
                <th className="py-3 px-4">Sender</th>
                <th className="py-3 px-4">Threat Type</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Detected</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border font-sans">
              {mockDetections.map((row) => (
                <tr 
                  key={row.id} 
                  className="hover:bg-surface-hover/80 transition-colors cursor-pointer group"
                  onClick={() => navigate('/investigations')}
                >
                  <td className="py-3 px-4">
                    <ThreatBadge severity={row.severity} />
                  </td>
                  <td className="py-3 px-4 font-medium text-text-primary max-w-xs truncate">
                    {row.subject}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-teal-accent/90 max-w-[180px] truncate">
                    {row.sender}
                  </td>
                  <td className="py-3 px-4">
                    <span className="bg-surface-card px-2 py-0.5 rounded text-[11px] border border-surface-border text-text-secondary">
                      {row.threatType}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono font-bold text-text-primary">
                    <span className={row.riskScore >= 70 ? 'text-status-critical' : row.riskScore >= 40 ? 'text-status-high' : 'text-status-low'}>
                      {row.riskScore}/100
                    </span>
                  </td>
                  <td className="py-3 px-4 text-text-muted text-[11px] whitespace-nowrap">
                    {row.detectedAt}
                  </td>
                  <td className="py-3 px-4 text-text-muted text-[11px] whitespace-nowrap">
                    {row.source}
                  </td>
                  <td className="py-3 px-4">
                    <DecisionBadge decision={row.action} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
