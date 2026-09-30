import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  RotateCcw,
  Eye,
  AlertTriangle,
  History,
  CheckCircle2,
  XCircle,
  Clock,
  UserCheck,
  Lock,
  Unlock,
  AlertCircle,
  HelpCircle,
} from 'lucide-react';

export interface AuditRecord {
  id: string;
  email_id?: string;
  message_id: string;
  action: string;
  actor: string;
  reason: string;
  previous_state: string;
  new_state: string;
  target_email?: string;
  timestamp: string;
  details?: Record<string, any>;
}

export interface GmailActionPanelProps {
  emailId: string;
  messageId: string;
  currentState: string;
  currentDecision?: string;
  recipientEmail?: string;
  onStateChange?: (newState: string) => void;
}

export const GmailActionPanel: React.FC<GmailActionPanelProps> = ({
  emailId,
  messageId,
  currentState: initialValState,
  currentDecision = 'QUARANTINE',
  recipientEmail = 'target@enterprise.com',
  onStateChange,
}) => {
  const [currentState, setCurrentState] = useState<string>(initialValState || 'ACTION_PENDING');
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionReason, setActionReason] = useState<string>('');
  const [activeModalAction, setActiveModalAction] = useState<'QUARANTINE' | 'RELEASE' | null>(null);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error' | 'warning'; text: string } | null>(null);

  // Initial audit log fetching & mock sync
  useEffect(() => {
    fetchAuditTrail();
  }, [emailId, messageId]);

  const fetchAuditTrail = async () => {
    try {
      const resp = await fetch(`/api/v1/actions/audit?email_id=${emailId || messageId}`);
      if (resp.ok) {
        const data = await resp.json();
        setAuditLogs(data);
      } else {
        // Fallback default mock audit records for demo state
        setAuditLogs([
          {
            id: 'audit-001',
            message_id: messageId || 'msg-demo-99',
            action: `AUTO_${currentDecision}`,
            actor: 'SYSTEM',
            reason: `Risk fusion score 0.94 triggered automated decision ${currentDecision}`,
            previous_state: 'ANALYZED',
            new_state: currentDecision === 'QUARANTINE' ? 'QUARANTINED' : 'SAFE',
            target_email: recipientEmail,
            timestamp: new Date().toISOString(),
            details: { label_applied: `TRINETRA/${currentDecision}` },
          },
        ]);
      }
    } catch {
      // Fallback
      setAuditLogs([
        {
          id: 'audit-001',
          message_id: messageId || 'msg-demo-99',
          action: `AUTO_${currentDecision}`,
          actor: 'SYSTEM',
          reason: `Risk engine fusion verdict ${currentDecision}`,
          previous_state: 'ANALYZED',
          new_state: currentDecision === 'QUARANTINE' ? 'QUARANTINED' : 'SAFE',
          target_email: recipientEmail,
          timestamp: new Date().toISOString(),
          details: { label_applied: `TRINETRA/${currentDecision}` },
        },
      ]);
    }
  };

  const handleAction = async (
    actionType: 'quarantine' | 'release' | 'mark-safe' | 'review' | 'reprocess',
    confirmed = false
  ) => {
    // Check high-impact action confirmation requirements
    if ((actionType === 'quarantine' || actionType === 'release') && !confirmed) {
      setActiveModalAction(actionType === 'quarantine' ? 'QUARANTINE' : 'RELEASE');
      return;
    }

    setLoading(true);
    setStatusMessage(null);
    const endpoint = `/api/v1/actions/${actionType}`;
    const payload = {
      email_id: emailId || messageId,
      actor: 'analyst@trinetra.soc',
      reason: actionReason || `Analyst manual action: ${actionType.toUpperCase()}`,
      confirmed: confirmed,
    };

    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const result = await resp.json();

      if (resp.ok && result.success) {
        setCurrentState(result.new_state);
        if (onStateChange) onStateChange(result.new_state);
        setStatusMessage({
          type: 'success',
          text: `Action ${result.action_taken} recorded! State updated to ${result.new_state}.`,
        });
        setActionReason('');
        setActiveModalAction(null);
        fetchAuditTrail();
      } else if (result.confirmation_required) {
        setActiveModalAction(actionType === 'quarantine' ? 'QUARANTINE' : 'RELEASE');
      } else {
        setStatusMessage({ type: 'error', text: result.detail || result.message || 'Action failed.' });
      }
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: `Failed to execute action: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const getStateBadge = (stateStr: string) => {
    switch (stateStr) {
      case 'QUARANTINED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-status-critical/20 text-status-critical border border-status-critical/40 flex items-center gap-1"><Lock className="w-3 h-3" /> Quarantined</span>;
      case 'RELEASED':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-status-low/20 text-status-low border border-status-low/40 flex items-center gap-1"><Unlock className="w-3 h-3" /> Released</span>;
      case 'SAFE':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-teal-accent/20 text-teal-accent border border-teal-accent/40 flex items-center gap-1"><ShieldCheck className="w-3 h-3" /> Safe</span>;
      case 'REVIEW':
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-status-medium/20 text-status-medium border border-status-medium/40 flex items-center gap-1"><Eye className="w-3 h-3" /> Analyst Review</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-status-high/20 text-status-high border border-status-high/40 flex items-center gap-1"><Clock className="w-3 h-3" /> Action Pending</span>;
    }
  };

  return (
    <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-4">
      {/* Panel Header */}
      <div className="flex items-center justify-between pb-3 border-b border-surface-border">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-teal-accent" />
          <h3 className="text-sm font-semibold text-text-primary uppercase tracking-wider font-mono">
            Gmail Response & Action Engine
          </h3>
        </div>
        <div>{getStateBadge(currentState)}</div>
      </div>

      {/* Safety Notice */}
      <div className="bg-bg-darkest/60 border border-teal-accent/20 rounded-lg p-2.5 text-[11px] font-mono text-text-secondary flex items-start gap-2">
        <AlertCircle className="w-4 h-4 text-teal-accent shrink-0 mt-0.5" />
        <div>
          <span className="text-teal-accent font-bold">Safety Rule Enforced:</span> Automatic permanent email deletion is strictly disabled. Actions utilize controlled Gmail labels (<code className="text-teal-vibrant">TRINETRA/SAFE</code>, <code className="text-status-medium">TRINETRA/WARN</code>, <code className="text-status-critical">TRINETRA/QUARANTINE</code>, <code className="text-status-high">TRINETRA/REVIEW</code>). High-impact actions require analyst confirmation.
        </div>
      </div>

      {/* Feedback Banner */}
      {statusMessage && (
        <div
          className={`p-3 rounded-lg text-xs font-mono flex items-center justify-between border ${
            statusMessage.type === 'success'
              ? 'bg-teal-accent/10 border-teal-accent text-teal-accent'
              : 'bg-status-critical/10 border-status-critical text-status-critical'
          }`}
        >
          <span>{statusMessage.text}</span>
          <button onClick={() => setStatusMessage(null)} className="text-text-muted hover:text-text-primary">✕</button>
        </div>
      )}

      {/* Action Reason Input */}
      <div>
        <label className="text-[10px] font-mono text-text-muted uppercase block mb-1">Analyst Rationale / Reason</label>
        <input
          type="text"
          value={actionReason}
          onChange={(e) => setActionReason(e.target.value)}
          placeholder="Enter investigation notes or justification for this action..."
          className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-xs text-text-primary focus:outline-none focus:border-teal-accent font-mono"
        />
      </div>

      {/* Analyst Action Controls */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 pt-1">
        <button
          id="btn-action-quarantine"
          onClick={() => handleAction('quarantine', false)}
          disabled={loading}
          className="px-3 py-2 rounded text-xs font-semibold bg-status-critical/20 border border-status-critical/50 hover:bg-status-critical/30 text-status-critical transition-all flex items-center justify-center gap-1.5 shadow-sm"
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Quarantine</span>
        </button>

        <button
          id="btn-action-release"
          onClick={() => handleAction('release', false)}
          disabled={loading}
          className="px-3 py-2 rounded text-xs font-semibold bg-status-low/20 border border-status-low/50 hover:bg-status-low/30 text-status-low transition-all flex items-center justify-center gap-1.5 shadow-sm"
        >
          <Unlock className="w-3.5 h-3.5" />
          <span>Release</span>
        </button>

        <button
          id="btn-action-mark-safe"
          onClick={() => handleAction('mark-safe', true)}
          disabled={loading}
          className="px-3 py-2 rounded text-xs font-semibold bg-teal-accent/20 border border-teal-accent/50 hover:bg-teal-accent/30 text-teal-accent transition-all flex items-center justify-center gap-1.5 shadow-sm"
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Mark Safe</span>
        </button>

        <button
          id="btn-action-review"
          onClick={() => handleAction('review', true)}
          disabled={loading}
          className="px-3 py-2 rounded text-xs font-semibold bg-status-medium/20 border border-status-medium/50 hover:bg-status-medium/30 text-status-medium transition-all flex items-center justify-center gap-1.5 shadow-sm"
        >
          <Eye className="w-3.5 h-3.5" />
          <span>Flag Review</span>
        </button>

        <button
          id="btn-action-reprocess"
          onClick={() => handleAction('reprocess', true)}
          disabled={loading}
          className="px-3 py-2 rounded text-xs font-semibold bg-surface-card border border-surface-border hover:border-teal-accent/50 text-text-secondary hover:text-text-primary transition-all flex items-center justify-center gap-1.5 shadow-sm col-span-2 md:col-span-1"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reprocess</span>
        </button>
      </div>

      {/* Confirmation Modal */}
      {activeModalAction && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-bg-dark border border-teal-accent/40 rounded-xl p-5 max-w-md w-full space-y-4 shadow-2xl">
            <div className="flex items-center gap-2 text-status-critical font-bold text-sm uppercase tracking-wider font-mono">
              <AlertTriangle className="w-5 h-5 text-status-critical" />
              <span>Confirm High-Impact Action ({activeModalAction})</span>
            </div>

            <p className="text-xs text-text-secondary leading-relaxed bg-bg-darkest p-3 rounded-lg border border-surface-border">
              {activeModalAction === 'QUARANTINE' ? (
                <span>
                  Quarantining this email will isolate it from the recipient's Inbox, applying label <code className="text-status-critical">TRINETRA/QUARANTINE</code> and removing it from <code className="text-text-primary">INBOX</code>.
                </span>
              ) : (
                <span>
                  Releasing this email will restore it to the recipient's Inbox, removing <code className="text-status-critical">TRINETRA/QUARANTINE</code> and tagging <code className="text-teal-accent">TRINETRA/SAFE</code>.
                </span>
              )}
            </p>

            <div className="text-[11px] font-mono text-text-muted">
              Target Email: <span className="text-text-primary font-bold">{recipientEmail}</span>
              <br />
              Action Actor: <span className="text-teal-accent font-bold">analyst@trinetra.soc</span>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setActiveModalAction(null)}
                className="px-4 py-2 text-xs font-mono text-text-muted hover:text-text-primary border border-surface-border rounded"
              >
                Cancel
              </button>
              <button
                id="btn-confirm-modal-action"
                onClick={() => handleAction(activeModalAction === 'QUARANTINE' ? 'quarantine' : 'release', true)}
                className="px-4 py-2 text-xs font-mono font-bold bg-status-critical hover:bg-status-critical/90 text-bg-darkest rounded shadow-teal-glow"
              >
                Confirm {activeModalAction}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Audit Trail Timeline */}
      <div className="pt-3 border-t border-surface-border space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-1.5 text-teal-accent font-semibold uppercase tracking-wider">
            <History className="w-4 h-4" />
            <span>Traceable Audit Log Trail</span>
          </div>
          <span className="text-[10px] text-text-muted">{auditLogs.length} audit entry(ies)</span>
        </div>

        <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
          {auditLogs.map((log) => (
            <div
              key={log.id}
              className="bg-bg-darkest/70 border border-surface-border rounded-lg p-2.5 text-xs font-mono space-y-1"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-teal-accent">{log.action}</span>
                <span className="text-[10px] text-text-muted">{new Date(log.timestamp).toLocaleString()}</span>
              </div>
              <div className="text-[11px] text-text-secondary">
                Actor: <span className="text-text-primary">{log.actor}</span> | State Transition:{' '}
                <span className="text-status-medium">{log.previous_state}</span> →{' '}
                <span className="text-teal-vibrant">{log.new_state}</span>
              </div>
              <div className="text-[10px] text-text-muted italic">"{log.reason}"</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
