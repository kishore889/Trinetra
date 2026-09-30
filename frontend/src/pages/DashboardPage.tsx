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
  AlertCircle,
  Loader2,
  CheckCircle2,
  Unlock,
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
  Cell,
} from 'recharts';
import { MetricCard, ThreatBadge, DecisionBadge } from '../components/UIElements';
import { useNavigate } from 'react-router-dom';

interface DashboardStats {
  emails_analyzed: number;
  phishing_detected: number;
  warnings: number;
  quarantined: number;
  released: number;
  action_pending: number;
  risk_distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  threat_trend: Array<{ timestamp: string; analyzed: number; phishing: number; warnings: number }>;
  recent_detections: Array<{
    id: string;
    message_id: string;
    subject: string;
    sender: string;
    sender_domain: string;
    recipient: string;
    received_at: string;
    state: string;
    final_risk_score: number;
    severity: string;
    decision: string;
    confidence: number;
    explanation_summary?: string;
    recommended_action?: string;
  }>;
  active_monitoring: Record<string, any>;
  system_health: Record<string, any>;
}

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  const fetchDashboardStats = async () => {
    try {
      setError(null);
      const res = await fetch('/api/v1/dashboard/stats');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch dashboard telemetry.`);
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message || 'Failed to connect to TRINETRA SOC backend');
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchDashboardStats();

    // Setup real-time SSE listener
    let sse: EventSource | null = null;
    try {
      sse = new EventSource('/api/v1/realtime/stream');
      sse.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.event === 'NEW_EMAIL' || payload.event === 'ACTION_TAKEN' || payload.event === 'RISK_UPDATE') {
            fetchDashboardStats();
          }
        } catch {}
      };
    } catch {}

    const interval = setInterval(fetchDashboardStats, 10000);

    return () => {
      if (sse) sse.close();
      clearInterval(interval);
    };
  }, []);

  const handleRefresh = () => {
    setIsRefreshing(true);
    fetchDashboardStats();
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="bg-surface-default border border-surface-border rounded-xl p-8 flex items-center justify-center">
          <div className="flex items-center gap-3 text-teal-accent font-mono">
            <Loader2 className="w-6 h-6 animate-spin" />
            <span>Connecting to TRINETRA SOC Real-Time Telemetry...</span>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-3 text-status-critical font-bold text-sm font-mono">
          <AlertTriangle className="w-6 h-6" />
          <span>SOC Telemetry Connection Error</span>
        </div>
        <p className="text-xs text-text-secondary font-mono">{error}</p>
        <button
          onClick={handleRefresh}
          className="flex items-center gap-2 bg-status-critical hover:bg-status-critical/90 text-bg-darkest font-mono text-xs font-bold px-4 py-2 rounded"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Retry Connection</span>
        </button>
      </div>
    );
  }

  const stats = data!;
  const riskDistData = [
    { name: 'Critical', value: stats.risk_distribution.CRITICAL, color: '#FF5C67' },
    { name: 'High', value: stats.risk_distribution.HIGH, color: '#FF9F43' },
    { name: 'Medium', value: stats.risk_distribution.MEDIUM, color: '#F6D365' },
    { name: 'Low', value: stats.risk_distribution.LOW, color: '#38D39F' },
  ];
  const totalThreats = stats.risk_distribution.CRITICAL + stats.risk_distribution.HIGH + stats.risk_distribution.MEDIUM + stats.risk_distribution.LOW;

  return (
    <div className="space-y-6">
      {/* Real Monitoring Telemetry Banner */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-status-low shadow-[0_0_10px_#38D39F]" />
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-text-primary font-mono uppercase tracking-wider">
                  Gmail Telemetry Engine: {stats.active_monitoring.status || 'Active'}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-surface-card border border-surface-border text-teal-accent">
                  Mode: {stats.active_monitoring.mode || 'Google Cloud Pub/Sub & Polling'}
                </span>
              </div>
              <p className="text-[11px] text-text-muted mt-0.5 font-mono">
                Real-time telemetry stream connected to PostgreSQL database & risk fusion engine.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRefresh}
              className="flex items-center gap-1.5 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3 py-1.5 rounded transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>Sync Metrics</span>
            </button>
          </div>
        </div>
      </div>

      {/* Top 8 Real SOC Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard title="Emails Analyzed" value={stats.emails_analyzed.toLocaleString()} change="Real Database" isPositive icon={<Mail className="w-5 h-5" />} />
        <MetricCard title="Phishing Detected" value={stats.phishing_detected.toString()} change="QUARANTINE" isPositive={false} icon={<ShieldAlert className="w-5 h-5" />} />
        <MetricCard title="Warnings Issued" value={stats.warnings.toString()} change="WARN Policy" isPositive={false} icon={<AlertTriangle className="w-5 h-5" />} />
        <MetricCard title="Quarantined" value={stats.quarantined.toString()} change="Isolated" isPositive={false} icon={<Lock className="w-5 h-5" />} />
        <MetricCard title="Released" value={stats.released.toString()} change="Analyst Release" isPositive icon={<Unlock className="w-5 h-5" />} />
        <MetricCard title="Action Pending" value={stats.action_pending.toString()} change="In Queue" isPositive icon={<Clock className="w-5 h-5" />} />
        <MetricCard title="Threat Providers" value={stats.system_health.threat_intel_providers?.toString() || '4'} change="CERT-In, GSBS, VT" isPositive icon={<Fingerprint className="w-5 h-5" />} />
        <MetricCard title="System Health" value={stats.system_health.status || 'HEALTHY'} change="100% Operational" isPositive icon={<Flame className="w-5 h-5" />} />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-surface-default border border-surface-border rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-text-primary tracking-wide font-mono uppercase">Threat Telemetry Trend</h2>
              <p className="text-[11px] text-text-muted">Live telemetry analyzed over time</p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-status-critical" /> Phishing</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-status-medium" /> Warnings</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-teal-accent" /> Analyzed</span>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.threat_trend}>
                <defs>
                  <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF5C67" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#FF5C67" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorWarn" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF9F43" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#FF9F43" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="timestamp" stroke="#668582" fontSize={11} tickLine={false} />
                <YAxis stroke="#668582" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#071E1D', borderColor: '#16D9D0', borderRadius: '8px', fontSize: '12px' }}
                  itemStyle={{ color: '#E8FFFD' }}
                />
                <Area type="monotone" dataKey="phishing" stroke="#FF5C67" fillOpacity={1} fill="url(#colorCrit)" strokeWidth={2} />
                <Area type="monotone" dataKey="warnings" stroke="#FF9F43" fillOpacity={1} fill="url(#colorWarn)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Chart */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-primary tracking-wide font-mono uppercase">Risk Distribution</h2>
            <p className="text-[11px] text-text-muted">Multi-Signal Engine severity breakdown</p>
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
              <span className="text-xl font-bold font-mono text-text-primary block leading-none">{totalThreats}</span>
              <span className="text-[10px] text-text-muted font-mono uppercase">Evaluated</span>
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

      {/* Recent Detections Table (Real DB Data) */}
      <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-surface-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-primary tracking-wide font-mono uppercase">
              Recent Ingested Threat Detections
            </h2>
            <p className="text-[11px] text-text-muted">Real-time detections evaluated by 7-layer intelligence pipeline</p>
          </div>
          <button
            onClick={() => navigate('/investigations')}
            className="flex items-center gap-1 text-xs font-medium text-teal-accent hover:text-teal-vibrant transition-colors font-mono"
          >
            <span>View Investigations</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-text-secondary">
            <thead className="bg-bg-darkest/60 text-text-muted font-mono uppercase tracking-wider text-[10px] border-b border-surface-border">
              <tr>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Email Subject</th>
                <th className="py-3 px-4">Sender</th>
                <th className="py-3 px-4">Recipient</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">State</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border font-sans">
              {stats.recent_detections.map((row) => (
                <tr
                  key={row.id}
                  className="hover:bg-surface-hover/80 transition-colors cursor-pointer group font-mono"
                  onClick={() => navigate('/investigations')}
                >
                  <td className="py-3 px-4">
                    <ThreatBadge severity={row.severity} />
                  </td>
                  <td className="py-3 px-4 font-medium text-text-primary max-w-xs truncate">
                    {row.subject}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-teal-accent max-w-[180px] truncate">
                    {row.sender}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-text-muted max-w-[180px] truncate">
                    {row.recipient}
                  </td>
                  <td className="py-3 px-4 font-mono font-bold text-text-primary">
                    <span className={row.final_risk_score >= 0.75 ? 'text-status-critical' : row.final_risk_score >= 0.40 ? 'text-status-high' : 'text-status-low'}>
                      {Math.round(row.final_risk_score * 100)}/100
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className="bg-surface-card px-2 py-0.5 rounded text-[10px] border border-surface-border text-text-secondary font-bold">
                      {row.state}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <DecisionBadge decision={row.decision} />
                  </td>
                </tr>
              ))}

              {stats.recent_detections.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-text-muted font-mono">
                    No detections recorded in database yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
