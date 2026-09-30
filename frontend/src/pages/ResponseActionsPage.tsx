import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Eye,
  Clock,
  CheckCircle2,
  AlertTriangle,
  History,
  RotateCcw,
  Search,
  Filter,
  RefreshCw,
  FileText,
} from 'lucide-react';
import { GmailActionPanel, AuditRecord } from '../components/GmailActionPanel';

interface ActionSummaryStats {
  total_emails: number;
  action_taken: number;
  action_pending: number;
  analyst_review: number;
  quarantined: number;
  released: number;
}

const DEMO_AUDIT_LOGS: AuditRecord[] = [
  {
    id: 'audit-101',
    message_id: 'msg-9821-phish',
    action: 'ANALYST_QUARANTINE',
    actor: 'analyst@trinetra.soc',
    reason: 'Analyst manual threat containment after credential harvest verification',
    previous_state: 'ACTION_PENDING',
    new_state: 'QUARANTINED',
    target_email: 'cfo@enterprise-finance.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    details: { labels_added: ['TRINETRA/QUARANTINE'], confirmed: true },
  },
  {
    id: 'audit-102',
    message_id: 'msg-7721-clean',
    action: 'AUTO_ALLOW',
    actor: 'SYSTEM',
    reason: 'Automated risk engine score 0.05 passed safety threshold',
    previous_state: 'ANALYZED',
    new_state: 'SAFE',
    target_email: 'ceo@enterprise.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
    details: { labels_added: ['TRINETRA/SAFE'] },
  },
  {
    id: 'audit-103',
    message_id: 'msg-3341-warn',
    action: 'AUTO_WARN',
    actor: 'SYSTEM',
    reason: 'Automated risk engine score 0.58 flagged lookalike domain signals',
    previous_state: 'ANALYZED',
    new_state: 'ACTIONED',
    target_email: 'hr@enterprise.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    details: { labels_added: ['TRINETRA/WARN'] },
  },
  {
    id: 'audit-104',
    message_id: 'msg-1198-quar',
    action: 'ANALYST_RELEASE',
    actor: 'soc_lead@trinetra.soc',
    reason: 'Analyst verified as legitimate partner vendor email',
    previous_state: 'QUARANTINED',
    new_state: 'RELEASED',
    target_email: 'procurement@enterprise.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 300).toISOString(),
    details: { labels_added: ['INBOX', 'TRINETRA/SAFE'], confirmed: true },
  },
];

export const ResponseActionsPage: React.FC = () => {
  const [stats, setStats] = useState<ActionSummaryStats>({
    total_emails: 48,
    action_taken: 36,
    action_pending: 4,
    analyst_review: 3,
    quarantined: 5,
    released: 2,
  });
  const [auditTrail, setAuditTrail] = useState<AuditRecord[]>(DEMO_AUDIT_LOGS);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEmail, setSelectedEmail] = useState<{ id: string; msgId: string; state: string } | null>({
    id: 'CASE-2026-9821',
    msgId: 'msg-9821-phish',
    state: 'QUARANTINED',
  });

  useEffect(() => {
    fetchStats();
    fetchSystemAuditLogs();
  }, []);

  const fetchStats = async () => {
    try {
      const resp = await fetch('/api/v1/actions/summary');
      if (resp.ok) {
        const data = await resp.json();
        setStats(data);
      }
    } catch {
      // Keep demo stats
    }
  };

  const fetchSystemAuditLogs = async () => {
    setLoading(true);
    try {
      const resp = await fetch('/api/v1/actions/audit?limit=50');
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.length > 0) {
          setAuditTrail(data);
        }
      }
    } catch {
      // Keep demo audit logs
    } finally {
      setLoading(false);
    }
  };

  const filteredLogs = auditTrail.filter(
    (item) =>
      item.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.actor.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.target_email && item.target_email.toLowerCase().includes(searchTerm.toLowerCase())) ||
      item.reason.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              TRINETRA Response & Action Vault
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1">
            Safe Gmail response actions, analyst-controlled quarantine, and traceable audit trail logging.
          </p>
        </div>
        <button
          onClick={() => {
            fetchStats();
            fetchSystemAuditLogs();
          }}
          className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3 py-1.5 rounded transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Actions</span>
        </button>
      </div>

      {/* Metric Cards (Required Phase 13 UI Metrics) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Action Taken */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-text-muted font-mono text-xs">
            <span>Action Taken</span>
            <CheckCircle2 className="w-4 h-4 text-teal-accent" />
          </div>
          <div className="text-2xl font-bold font-mono text-teal-accent">{stats.action_taken}</div>
          <div className="text-[10px] text-text-muted">Applied labels or automated actions</div>
        </div>

        {/* Action Pending */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-text-muted font-mono text-xs">
            <span>Action Pending</span>
            <Clock className="w-4 h-4 text-status-high" />
          </div>
          <div className="text-2xl font-bold font-mono text-status-high">{stats.action_pending}</div>
          <div className="text-[10px] text-text-muted">Awaiting evaluation or response</div>
        </div>

        {/* Analyst Review */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-text-muted font-mono text-xs">
            <span>Analyst Review</span>
            <Eye className="w-4 h-4 text-status-medium" />
          </div>
          <div className="text-2xl font-bold font-mono text-status-medium">{stats.analyst_review}</div>
          <div className="text-[10px] text-text-muted">Flagged for SOC tier-2 inspection</div>
        </div>

        {/* Quarantined */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-text-muted font-mono text-xs">
            <span>Quarantined</span>
            <Lock className="w-4 h-4 text-status-critical" />
          </div>
          <div className="text-2xl font-bold font-mono text-status-critical">{stats.quarantined}</div>
          <div className="text-[10px] text-text-muted">Isolated with TRINETRA/QUARANTINE</div>
        </div>

        {/* Released */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-text-muted font-mono text-xs">
            <span>Released</span>
            <Unlock className="w-4 h-4 text-status-low" />
          </div>
          <div className="text-2xl font-bold font-mono text-status-low">{stats.released}</div>
          <div className="text-[10px] text-text-muted">Restored to recipient INBOX</div>
        </div>
      </div>

      {/* Main Grid: Interactive Action Panel + Full Audit Trail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Selected Email Action Engine Panel */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider">
              Selected Email Context
            </h3>
            <div className="space-y-1.5 text-xs font-mono bg-bg-darkest p-3 rounded-lg border border-surface-border">
              <div className="flex justify-between">
                <span className="text-text-muted">Case ID:</span>
                <span className="text-text-primary font-bold">{selectedEmail?.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Message ID:</span>
                <span className="text-text-primary">{selectedEmail?.msgId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">State:</span>
                <span className="text-status-critical font-bold">{selectedEmail?.state}</span>
              </div>
            </div>
          </div>

          <GmailActionPanel
            emailId={selectedEmail?.id || 'CASE-2026-9821'}
            messageId={selectedEmail?.msgId || 'msg-9821-phish'}
            currentState={selectedEmail?.state || 'QUARANTINED'}
            recipientEmail="cfo@enterprise-finance.com"
            onStateChange={(newState) => {
              setSelectedEmail((prev) => (prev ? { ...prev, state: newState } : null));
              fetchStats();
              fetchSystemAuditLogs();
            }}
          />
        </div>

        {/* Right: Traceable Audit Trail Table */}
        <div className="lg:col-span-2 bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-surface-border">
            <div className="flex items-center gap-2">
              <History className="w-5 h-5 text-teal-accent" />
              <div>
                <h2 className="text-sm font-bold text-text-primary font-mono uppercase tracking-wider">
                  Traceable Audit Trail Log
                </h2>
                <p className="text-[11px] text-text-muted">
                  Every automated and analyst action is permanently recorded and auditable.
                </p>
              </div>
            </div>

            {/* Search Filter */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Filter by action, actor, email..."
                className="bg-bg-darkest border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-xs text-text-primary focus:outline-none focus:border-teal-accent font-mono w-56"
              />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-bg-darkest text-text-muted uppercase text-[10px] border-b border-surface-border">
                <tr>
                  <th className="p-2.5">Timestamp</th>
                  <th className="p-2.5">Action</th>
                  <th className="p-2.5">Actor</th>
                  <th className="p-2.5">Target Email</th>
                  <th className="p-2.5">State Transition</th>
                  <th className="p-2.5">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border/50">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-surface-hover/50 transition-colors">
                    <td className="p-2.5 text-text-muted whitespace-nowrap text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="p-2.5 font-bold text-teal-accent">{log.action}</td>
                    <td className="p-2.5 text-text-primary">{log.actor}</td>
                    <td className="p-2.5 text-text-secondary">{log.target_email || 'n/a'}</td>
                    <td className="p-2.5 whitespace-nowrap">
                      <span className="text-status-medium">{log.previous_state}</span> →{' '}
                      <span className="text-teal-vibrant">{log.new_state}</span>
                    </td>
                    <td className="p-2.5 text-text-muted text-[11px] max-w-xs truncate">{log.reason}</td>
                  </tr>
                ))}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-4 text-center text-text-muted">
                      No audit records found matching search query.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
