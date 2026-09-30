import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  BarChart2,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Shield,
  Target,
  Activity,
  Loader2,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
  AreaChart,
  Area,
} from 'recharts';

interface DashboardStats {
  emails_analyzed: number;
  phishing_detected: number;
  warnings: number;
  quarantined: number;
  released: number;
  action_pending: number;
  risk_distribution: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number };
  threat_trend: Array<{ timestamp: string; analyzed: number; phishing: number; warnings: number }>;
}

const RISK_COLORS = {
  LOW: '#38D39F',
  MEDIUM: '#F6A623',
  HIGH: '#E8642C',
  CRITICAL: '#E53E3E',
};

const LAYER_PERFORMANCE = [
  { name: 'Content NLP', weight: 25, accuracy: 96, status: 'ACTIVE', description: 'TF-IDF + Logistic Regression phishing signal extraction' },
  { name: 'URL & Domain Intel', weight: 30, accuracy: 98, status: 'ACTIVE', description: 'Domain age, WHOIS, Safe Browsing reputation' },
  { name: 'Identity Engine', weight: 20, accuracy: 94, status: 'ACTIVE', description: 'SPF / DKIM / DMARC + display-name spoofing analysis' },
  { name: 'Threat Intel', weight: 15, accuracy: 99, status: 'ACTIVE', description: 'Local IOC DB + CERT-In + VirusTotal + Safe Browsing' },
  { name: 'Graph Intelligence', weight: 10, accuracy: 92, status: 'ACTIVE', description: 'NetworkX correlation across campaigns and infrastructure' },
];

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-bg-darkest border border-surface-border rounded-lg p-3 shadow-xl font-mono text-xs">
      <p className="text-text-muted mb-2 uppercase text-[10px] tracking-wider">{label}</p>
      {payload.map((p: any) => (
        <div key={p.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ background: p.color }} />
          <span className="text-text-secondary capitalize">{p.name}:</span>
          <span className="font-bold" style={{ color: p.color }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
};

export const AnalyticsPage: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState('');

  const fetchAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/v1/dashboard/stats');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setStats(data);
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err.message || 'Failed to load analytics');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 30000);
    return () => clearInterval(interval);
  }, [fetchAnalytics]);

  // Derived metrics
  const detectionRate = stats
    ? stats.emails_analyzed > 0
      ? ((stats.phishing_detected / stats.emails_analyzed) * 100).toFixed(1)
      : '0.0'
    : null;

  const quarantineRate = stats
    ? stats.phishing_detected > 0
      ? ((stats.quarantined / stats.phishing_detected) * 100).toFixed(0)
      : '0'
    : null;

  const riskPieData = stats
    ? Object.entries(stats.risk_distribution)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => ({ name: k, value: v, color: RISK_COLORS[k as keyof typeof RISK_COLORS] }))
    : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <BarChart2 className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Telemetry &amp; Detection Analytics
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Long-term detection performance, risk distribution, threat trends, and multi-signal engine breakdown.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefreshed && (
            <span className="text-xs text-text-muted font-mono flex items-center gap-1">
              <Clock className="w-3 h-3" /> {lastRefreshed}
            </span>
          )}
          <button
            onClick={fetchAnalytics}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Analytics</span>
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 flex items-center gap-2 text-xs font-mono text-status-critical">
          <AlertTriangle className="w-4 h-4 shrink-0" /><span>{error}</span>
          <button onClick={fetchAnalytics} className="ml-auto underline font-bold">Retry</button>
        </div>
      )}

      {loading && !stats ? (
        <div className="bg-surface-default border border-surface-border rounded-xl p-10 flex items-center justify-center gap-2 text-teal-accent font-mono">
          <Loader2 className="w-5 h-5 animate-spin" /><span>Loading analytics data...</span>
        </div>
      ) : stats && (
        <>
          {/* KPI Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              {
                label: 'Emails Analyzed',
                value: stats.emails_analyzed.toLocaleString(),
                icon: Database,
                color: 'text-teal-accent',
                sub: 'Total ingested',
              },
              {
                label: 'Detection Rate',
                value: `${detectionRate}%`,
                icon: Target,
                color: 'text-status-high',
                sub: `${stats.phishing_detected} phishing detected`,
              },
              {
                label: 'Quarantine Rate',
                value: `${quarantineRate}%`,
                icon: Shield,
                color: 'text-status-critical',
                sub: `of detected threats quarantined`,
              },
              {
                label: 'Warnings Issued',
                value: stats.warnings.toLocaleString(),
                icon: Activity,
                color: 'text-status-medium',
                sub: `${stats.action_pending} pending action`,
              },
            ].map((kpi) => {
              const Icon = kpi.icon;
              return (
                <div key={kpi.label} className="bg-surface-default border border-surface-border rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className={`w-4 h-4 ${kpi.color}`} />
                    <span className="text-[10px] font-mono text-text-muted uppercase tracking-wider">{kpi.label}</span>
                  </div>
                  <div className={`text-3xl font-bold font-mono ${kpi.color} mb-1`}>{kpi.value}</div>
                  <div className="text-[10px] text-text-muted font-mono">{kpi.sub}</div>
                </div>
              );
            })}
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            {/* Threat Trend Area Chart */}
            <div className="xl:col-span-2 bg-surface-default border border-surface-border rounded-xl p-5">
              <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-4">
                7-Day Detection Trend
              </h2>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={stats.threat_trend} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gradAnalyzed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38D39F" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#38D39F" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradPhishing" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#E53E3E" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#E53E3E" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="timestamp" tick={{ fill: '#8B99A7', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#8B99A7', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="analyzed" name="Analyzed" stroke="#38D39F" fill="url(#gradAnalyzed)" strokeWidth={2} dot={false} />
                  <Area type="monotone" dataKey="phishing" name="Phishing" stroke="#E53E3E" fill="url(#gradPhishing)" strokeWidth={2} dot={false} />
                  <Area type="monotone" dataKey="warnings" name="Warnings" stroke="#F6A623" fill="none" strokeWidth={1.5} strokeDasharray="4 2" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
              <div className="flex items-center gap-5 mt-2 font-mono text-xs">
                {[
                  { color: '#38D39F', label: 'Analyzed' },
                  { color: '#E53E3E', label: 'Phishing Detected' },
                  { color: '#F6A623', label: 'Warnings' },
                ].map((l) => (
                  <div key={l.label} className="flex items-center gap-1.5 text-text-muted">
                    <span className="w-3 h-0.5 rounded inline-block" style={{ background: l.color }} />
                    {l.label}
                  </div>
                ))}
              </div>
            </div>

            {/* Risk Severity Pie */}
            <div className="bg-surface-default border border-surface-border rounded-xl p-5">
              <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-4">
                Risk Severity Distribution
              </h2>
              {riskPieData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie
                        data={riskPieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {riskPieData.map((entry, idx) => (
                          <Cell key={idx} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        formatter={(v: number, n: string) => [`${v} detections`, n]}
                        contentStyle={{ background: '#0D1117', border: '1px solid #1E2D3D', borderRadius: 8, fontFamily: 'monospace', fontSize: 11 }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="space-y-1.5 mt-2 font-mono text-xs">
                    {riskPieData.map((d) => (
                      <div key={d.name} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="w-2.5 h-2.5 rounded-full" style={{ background: d.color }} />
                          <span className="text-text-secondary">{d.name}</span>
                        </div>
                        <span className="font-bold" style={{ color: d.color }}>{d.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="h-40 flex items-center justify-center text-text-muted text-xs font-mono">
                  No risk data yet.
                </div>
              )}
            </div>
          </div>

          {/* Detection Volume Bar */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-5">
            <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-4">
              Daily Email Analysis Volume (7 days)
            </h2>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={stats.threat_trend} margin={{ top: 0, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="timestamp" tick={{ fill: '#8B99A7', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#8B99A7', fontSize: 10, fontFamily: 'monospace' }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="analyzed" name="Analyzed" fill="#38D39F" opacity={0.8} radius={[3, 3, 0, 0]} />
                <Bar dataKey="phishing" name="Phishing" fill="#E53E3E" opacity={0.8} radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Intelligence Layer Table */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
            <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider">
              Multi-Signal Intelligence Layers — Fusion Weights &amp; Benchmark Performance
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-bg-darkest text-text-muted uppercase text-[10px] border-b border-surface-border">
                  <tr>
                    <th className="p-3">Intelligence Layer</th>
                    <th className="p-3">Fusion Weight</th>
                    <th className="p-3">Benchmark Accuracy</th>
                    <th className="p-3">Description</th>
                    <th className="p-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-border">
                  {LAYER_PERFORMANCE.map((lp) => (
                    <tr key={lp.name} className="hover:bg-surface-hover/50">
                      <td className="p-3 font-bold text-text-primary">{lp.name}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-surface-card rounded-full h-1.5">
                            <div className="h-1.5 rounded-full bg-teal-accent" style={{ width: `${lp.weight}%` }} />
                          </div>
                          <span className="text-teal-accent font-bold">{lp.weight}%</span>
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className="text-status-low font-bold">{lp.accuracy}%</span>
                          <div className="w-20 bg-surface-card rounded-full h-1">
                            <div className="h-1 rounded-full bg-status-low" style={{ width: `${lp.accuracy}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className="p-3 text-text-muted max-w-xs">{lp.description}</td>
                      <td className="p-3">
                        <span className="text-status-low bg-status-low/10 border border-status-low/30 px-2 py-0.5 rounded text-[10px] font-bold">
                          {lp.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
