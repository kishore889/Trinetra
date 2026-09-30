import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Bell,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  RefreshCw,
  Loader2,
  Clock,
  X,
  Wifi,
  WifiOff,
  Filter,
  Search,
  ChevronRight,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Alert {
  id: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  type: string;
  title: string;
  message: string;
  email_id?: string;
  subject?: string;
  sender?: string;
  risk_score?: number;
  decision?: string;
  acknowledged: boolean;
}

interface DashboardStats {
  emails_analyzed: number;
  phishing_detected: number;
  warnings: number;
  quarantined: number;
  recent_detections: Array<{
    id: string;
    message_id: string;
    subject: string;
    sender: string;
    received_at: string;
    severity: string;
    decision: string;
    final_risk_score: number;
    state: string;
  }>;
}

// ---------------------------------------------------------------------------
// Build alerts from dashboard detection data
// ---------------------------------------------------------------------------

const buildAlertsFromStats = (stats: DashboardStats): Alert[] => {
  const alerts: Alert[] = [];

  stats.recent_detections.forEach((det, idx) => {
    const sev = det.severity as Alert['severity'];
    if (det.decision === 'QUARANTINE' || det.severity === 'CRITICAL' || det.severity === 'HIGH') {
      alerts.push({
        id: `det-${det.id}-${idx}`,
        timestamp: det.received_at,
        severity: sev || 'MEDIUM',
        type: det.decision === 'QUARANTINE' ? 'PHISHING_DETECTED' : 'HIGH_RISK_EMAIL',
        title: det.decision === 'QUARANTINE'
          ? 'Phishing Email Detected & Quarantined'
          : `High-Risk Email — ${det.severity} Severity`,
        message: `Subject: "${det.subject}" from ${det.sender}. Risk Score: ${(det.final_risk_score * 100).toFixed(0)}%. Decision: ${det.decision}.`,
        email_id: det.id,
        subject: det.subject,
        sender: det.sender,
        risk_score: det.final_risk_score,
        decision: det.decision,
        acknowledged: det.state !== 'QUARANTINED' && det.state !== 'RECEIVED',
      });
    } else if (det.decision === 'WARN') {
      alerts.push({
        id: `warn-${det.id}-${idx}`,
        timestamp: det.received_at,
        severity: 'MEDIUM',
        type: 'SUSPICIOUS_EMAIL_WARNING',
        title: 'Suspicious Email Warning',
        message: `Subject: "${det.subject}" from ${det.sender}. Risk Score: ${(det.final_risk_score * 100).toFixed(0)}%. Decision: WARN.`,
        email_id: det.id,
        subject: det.subject,
        sender: det.sender,
        risk_score: det.final_risk_score,
        decision: det.decision,
        acknowledged: det.state !== 'RECEIVED',
      });
    }
  });

  // System-level alerts
  if (stats.quarantined > 0) {
    alerts.push({
      id: 'sys-quarantine',
      timestamp: new Date().toISOString(),
      severity: 'HIGH',
      type: 'SYSTEM_ALERT',
      title: `${stats.quarantined} Email${stats.quarantined > 1 ? 's' : ''} in Quarantine`,
      message: `${stats.quarantined} email(s) are currently quarantined and awaiting analyst review or release.`,
      acknowledged: false,
    });
  }

  return alerts.sort((a, b) => {
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    const aDiff = (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3);
    if (aDiff !== 0) return aDiff;
    return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
  });
};

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

const SEVERITY_CONFIG = {
  CRITICAL: { color: 'text-status-critical', bg: 'bg-status-critical/10', border: 'border-status-critical/40', icon: AlertOctagon },
  HIGH:     { color: 'text-status-high',     bg: 'bg-status-high/10',     border: 'border-status-high/40',     icon: AlertTriangle },
  MEDIUM:   { color: 'text-status-medium',   bg: 'bg-status-medium/10',   border: 'border-status-medium/40',   icon: AlertTriangle },
  LOW:      { color: 'text-status-low',      bg: 'bg-status-low/10',      border: 'border-status-low/40',      icon: ShieldCheck },
};

const AlertCard: React.FC<{
  alert: Alert;
  onAcknowledge: (id: string) => void;
}> = ({ alert, onAcknowledge }) => {
  const cfg = SEVERITY_CONFIG[alert.severity] ?? SEVERITY_CONFIG.LOW;
  const Icon = cfg.icon;

  return (
    <div className={`rounded-xl border p-4 transition-all ${alert.acknowledged ? 'opacity-50 border-surface-border bg-surface-default' : `${cfg.border} ${cfg.bg}`}`}>
      <div className="flex items-start gap-3">
        <div className={`shrink-0 mt-0.5 ${cfg.color}`}>
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2 mb-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${cfg.border} ${cfg.color}`}>
                {alert.severity}
              </span>
              <span className="text-[10px] font-mono text-text-muted uppercase bg-surface-card border border-surface-border px-2 py-0.5 rounded">
                {alert.type.replace(/_/g, ' ')}
              </span>
              {alert.acknowledged && (
                <span className="text-[10px] font-mono text-text-muted flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-status-low" /> ACK
                </span>
              )}
            </div>
            <span className="text-[10px] text-text-muted font-mono whitespace-nowrap shrink-0">
              {new Date(alert.timestamp).toLocaleString()}
            </span>
          </div>
          <h3 className="font-bold text-text-primary font-mono text-sm mb-1">{alert.title}</h3>
          <p className="text-xs text-text-secondary font-mono leading-relaxed">{alert.message}</p>
          {(alert.risk_score !== undefined) && (
            <div className="mt-2 flex items-center gap-2">
              <div className="w-32 bg-surface-card rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full ${cfg.color.replace('text-', 'bg-')}`}
                  style={{ width: `${Math.min(alert.risk_score * 100, 100).toFixed(0)}%` }}
                />
              </div>
              <span className={`text-xs font-mono font-bold ${cfg.color}`}>
                {(alert.risk_score * 100).toFixed(0)}% Risk
              </span>
            </div>
          )}
        </div>
        {!alert.acknowledged && (
          <button
            onClick={() => onAcknowledge(alert.id)}
            className="shrink-0 flex items-center gap-1.5 text-[10px] font-mono text-text-secondary hover:text-teal-accent border border-surface-border hover:border-teal-accent/40 rounded px-2 py-1 transition-all"
            title="Acknowledge alert"
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            ACK
          </button>
        )}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [showAcked, setShowAcked] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState('');
  const [sseConnected, setSseConnected] = useState(false);
  const acknowledgedIds = useRef<Set<string>>(new Set());

  const fetchAlerts = useCallback(async () => {
    try {
      setError(null);
      const resp = await fetch('/api/v1/dashboard/stats');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data: DashboardStats = await resp.json();
      const built = buildAlertsFromStats(data);
      setAlerts((prev) => {
        // Preserve local acknowledgements across re-fetches
        return built.map((a) => ({
          ...a,
          acknowledged: a.acknowledged || acknowledgedIds.current.has(a.id),
        }));
      });
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err.message || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 15000);

    // SSE for real-time alert streaming
    let sse: EventSource | null = null;
    try {
      sse = new EventSource('/api/v1/realtime/stream');
      sse.onopen = () => setSseConnected(true);
      sse.onerror = () => setSseConnected(false);
      sse.onmessage = (e) => {
        try {
          const event = JSON.parse(e.data);
          if (event.event !== 'HEARTBEAT' && event.event !== 'CONNECTED') {
            fetchAlerts();
          }
        } catch {}
      };
    } catch {}

    return () => {
      if (sse) sse.close();
      clearInterval(interval);
    };
  }, [fetchAlerts]);

  const handleAcknowledge = (id: string) => {
    acknowledgedIds.current.add(id);
    setAlerts((prev) => prev.map((a) => a.id === id ? { ...a, acknowledged: true } : a));
  };

  const handleAcknowledgeAll = () => {
    alerts.forEach((a) => acknowledgedIds.current.add(a.id));
    setAlerts((prev) => prev.map((a) => ({ ...a, acknowledged: true })));
  };

  const filtered = alerts.filter((a) => {
    const matchesSev = severityFilter === 'ALL' || a.severity === severityFilter;
    const matchesType = typeFilter === 'ALL' || a.type === typeFilter;
    const matchesSearch =
      a.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (a.sender || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchesAck = showAcked || !a.acknowledged;
    return matchesSev && matchesType && matchesSearch && matchesAck;
  });

  const unackedCount = alerts.filter((a) => !a.acknowledged).length;
  const criticalCount = alerts.filter((a) => a.severity === 'CRITICAL' && !a.acknowledged).length;
  const alertTypes = [...new Set(alerts.map((a) => a.type))];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Bell className={`w-6 h-6 ${unackedCount > 0 ? 'text-status-high animate-pulse' : 'text-teal-accent'}`} />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Security Alerts
            </h1>
            {unackedCount > 0 && (
              <span className="bg-status-high text-bg-darkest text-[10px] font-bold font-mono px-2 py-0.5 rounded-full">
                {unackedCount} ACTIVE
              </span>
            )}
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Real-time detection alerts, quarantine events, and system anomaly notifications.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-1.5 text-xs font-mono ${sseConnected ? 'text-status-low' : 'text-text-muted'}`}>
            {sseConnected ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
            <span>{sseConnected ? 'LIVE' : 'POLLING'}</span>
          </div>
          {lastRefreshed && (
            <span className="text-xs text-text-muted font-mono flex items-center gap-1">
              <Clock className="w-3 h-3" /> {lastRefreshed}
            </span>
          )}
          {unackedCount > 0 && (
            <button
              onClick={handleAcknowledgeAll}
              className="flex items-center gap-2 bg-surface-card border border-teal-accent/30 hover:border-teal-accent text-teal-accent font-mono text-xs px-3 py-2 rounded transition-all"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Acknowledge All</span>
            </button>
          )}
          <button
            onClick={() => { setLoading(true); fetchAlerts(); }}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Alerts', value: alerts.length, color: 'text-teal-accent' },
          { label: 'Active (Unacked)', value: unackedCount, color: 'text-status-high' },
          { label: 'Critical', value: criticalCount, color: 'text-status-critical' },
          { label: 'Acknowledged', value: alerts.length - unackedCount, color: 'text-status-low' },
        ].map((s) => (
          <div key={s.label} className="bg-surface-default border border-surface-border rounded-xl p-4 text-center">
            <div className={`text-3xl font-bold font-mono ${s.color}`}>{s.value}</div>
            <div className="text-[10px] text-text-muted font-mono uppercase mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 flex items-center gap-2 text-xs font-mono text-status-critical">
          <AlertTriangle className="w-4 h-4 shrink-0" /><span>{error}</span>
          <button onClick={fetchAlerts} className="ml-auto underline font-bold">Retry</button>
        </div>
      )}

      {/* Filters */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-3 flex flex-wrap items-center gap-3 font-mono text-xs">
        <div className="relative flex-1 min-w-48">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search alerts by title, sender, details..."
            className="w-full bg-bg-darkest border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-text-primary focus:outline-none focus:border-teal-accent"
          />
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="w-3.5 h-3.5 text-text-muted" />
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent">
            <option value="ALL">All Severities</option>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent">
            <option value="ALL">All Types</option>
            {alertTypes.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
          <label className="flex items-center gap-1.5 cursor-pointer text-text-secondary">
            <input type="checkbox" checked={showAcked} onChange={(e) => setShowAcked(e.target.checked)} className="accent-teal-accent" />
            Show Acknowledged
          </label>
        </div>
        <span className="text-text-muted ml-auto">{filtered.length} alerts</span>
      </div>

      {/* Alert List */}
      {loading ? (
        <div className="bg-surface-default border border-surface-border rounded-xl p-10 flex items-center justify-center gap-2 text-teal-accent font-mono">
          <Loader2 className="w-5 h-5 animate-spin" /><span>Loading security alerts...</span>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((alert) => (
            <AlertCard key={alert.id} alert={alert} onAcknowledge={handleAcknowledge} />
          ))}
          {filtered.length === 0 && (
            <div className="bg-surface-default border border-surface-border rounded-xl p-10 text-center font-mono">
              <ShieldCheck className="w-10 h-10 text-status-low mx-auto mb-3" />
              <div className="text-text-primary font-bold mb-1">No Active Alerts</div>
              <div className="text-text-muted text-xs">
                {showAcked ? 'No alerts match the current filters.' : 'All alerts have been acknowledged. Enable "Show Acknowledged" to view history.'}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
