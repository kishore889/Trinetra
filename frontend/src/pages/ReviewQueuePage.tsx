import React, { useState, useEffect, useCallback } from 'react';
import {
  ClipboardCheck,
  RefreshCw,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  User,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  Eye,
  Download,
  History,
  BarChart2,
  Shield,
  AlertOctagon,
  ShieldCheck,
  Send,
  X,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ReviewQueueItem {
  email_id: string;
  detection_id: string;
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
  explanation_summary: string | null;
  recommended_action: string | null;
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  urls_count: number;
  has_feedback: boolean;
  reviewed_at: string | null;
}

interface RiskSignal {
  layer: string;
  signal_type: string;
  score: number;
  description: string;
}

interface ExistingFeedback {
  feedback_id: string;
  classification: string;
  comments: string | null;
  analyst_name: string | null;
  reviewed_at: string;
  review_source: string;
}

interface ReviewDetail {
  email_id: string;
  detection_id: string;
  message_id: string;
  subject: string;
  sender: string;
  sender_domain: string;
  recipient: string;
  received_at: string;
  state: string;
  spf_result: string | null;
  dkim_result: string | null;
  dmarc_result: string | null;
  urls: string[];
  final_risk_score: number;
  severity: string;
  decision: string;
  confidence: number;
  content_risk: number;
  url_risk: number;
  identity_risk: number;
  threat_intel_risk: number;
  graph_risk: number;
  explanation_summary: string | null;
  recommended_action: string | null;
  evidence: Record<string, any> | null;
  risk_signals: RiskSignal[];
  existing_feedback: ExistingFeedback | null;
}

interface ReviewStats {
  pending_reviews: number;
  reviewed_today: number;
  reviewed_total: number;
  feedback_distribution: Record<string, number>;
  false_positive_rate: number;
  analyst_activity: Array<{ analyst_name: string; reviews_submitted: number; last_active: string | null }>;
  review_queue_by_severity: Record<string, number>;
  avg_confidence_in_queue: number;
}

interface FeedbackHistoryItem {
  feedback_id: string;
  detection_id: string;
  email_id: string;
  subject: string;
  sender: string;
  final_risk_score: number;
  severity: string;
  decision: string;
  classification: string;
  comments: string | null;
  analyst_name: string | null;
  reviewed_at: string;
  review_source: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CLASSIFICATION_OPTIONS = [
  {
    value: 'TRUE_POSITIVE',
    label: 'True Positive',
    desc: 'Confirmed phishing / malicious email. Detection was correct.',
    color: 'text-status-critical border-status-critical/50 bg-status-critical/10',
    selected: 'bg-status-critical/20 border-status-critical text-status-critical',
    icon: AlertOctagon,
  },
  {
    value: 'FALSE_POSITIVE',
    label: 'False Positive',
    desc: 'Legitimate email incorrectly flagged. Detection was wrong.',
    color: 'text-status-medium border-status-medium/50 bg-status-medium/10',
    selected: 'bg-status-medium/20 border-status-medium text-status-medium',
    icon: XCircle,
  },
  {
    value: 'TRUE_NEGATIVE',
    label: 'True Negative',
    desc: 'Legitimate email correctly allowed through.',
    color: 'text-status-low border-status-low/50 bg-status-low/10',
    selected: 'bg-status-low/20 border-status-low text-status-low',
    icon: CheckCircle2,
  },
  {
    value: 'FALSE_NEGATIVE',
    label: 'False Negative',
    desc: 'Phishing email missed by detection system.',
    color: 'text-status-high border-status-high/50 bg-status-high/10',
    selected: 'bg-status-high/20 border-status-high text-status-high',
    icon: AlertTriangle,
  },
];

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-status-critical bg-status-critical/15 border-status-critical/40',
  HIGH:     'text-status-high bg-status-high/15 border-status-high/40',
  MEDIUM:   'text-status-medium bg-status-medium/15 border-status-medium/40',
  LOW:      'text-status-low bg-status-low/15 border-status-low/40',
};

const CLASSIFICATION_COLORS: Record<string, string> = {
  TRUE_POSITIVE:  'text-status-critical bg-status-critical/15 border-status-critical/40',
  FALSE_POSITIVE: 'text-status-medium bg-status-medium/15 border-status-medium/40',
  TRUE_NEGATIVE:  'text-status-low bg-status-low/15 border-status-low/40',
  FALSE_NEGATIVE: 'text-status-high bg-status-high/15 border-status-high/40',
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const RiskBar: React.FC<{ label: string; value: number; color?: string }> = ({
  label, value, color = 'bg-teal-accent',
}) => (
  <div>
    <div className="flex justify-between text-[10px] font-mono mb-1">
      <span className="text-text-muted uppercase tracking-wide">{label}</span>
      <span className="font-bold text-text-primary">{(value * 100).toFixed(0)}%</span>
    </div>
    <div className="w-full bg-surface-card rounded-full h-1.5">
      <div
        className={`h-1.5 rounded-full transition-all ${color}`}
        style={{ width: `${Math.min(value * 100, 100)}%` }}
      />
    </div>
  </div>
);

const AuthBadge: React.FC<{ label: string; result: string | null }> = ({ label, result }) => {
  const pass = result === 'pass';
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
      pass ? 'text-status-low bg-status-low/10 border-status-low/30'
           : 'text-status-critical bg-status-critical/10 border-status-critical/30'
    }`}>
      {label}: {result || 'none'}
    </span>
  );
};

// ---------------------------------------------------------------------------
// Review Detail Modal
// ---------------------------------------------------------------------------

const ReviewModal: React.FC<{
  detectionId: string;
  onClose: () => void;
  onSubmitted: () => void;
}> = ({ detectionId, onClose, onSubmitted }) => {
  const [detail, setDetail] = useState<ReviewDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [classification, setClassification] = useState<string>('');
  const [comments, setComments] = useState('');
  const [analystName, setAnalystName] = useState('SOC Analyst');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const [activeTab, setActiveTab] = useState<'evidence' | 'signals' | 'email'>('evidence');

  useEffect(() => {
    fetch(`/api/v1/review/queue/${detectionId}`)
      .then((r) => r.ok ? r.json() : Promise.reject(`HTTP ${r.status}`))
      .then((data) => {
        setDetail(data);
        if (data.existing_feedback) {
          setClassification(data.existing_feedback.classification);
          setComments(data.existing_feedback.comments || '');
          setAnalystName(data.existing_feedback.analyst_name || 'SOC Analyst');
        }
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false));
  }, [detectionId]);

  const handleSubmit = async () => {
    if (!classification) { setSubmitError('Please select a classification.'); return; }
    if (!comments.trim()) { setSubmitError('Please provide a rationale in the comments.'); return; }
    setSubmitting(true);
    setSubmitError(null);
    try {
      const resp = await fetch(`/api/v1/review/${detectionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          classification,
          comments,
          analyst_name: analystName || 'SOC Analyst',
          review_source: 'REVIEW_QUEUE',
        }),
      });
      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || `HTTP ${resp.status}`);
      }
      setSubmitted(true);
      setTimeout(() => { onClose(); onSubmitted(); }, 1500);
    } catch (err: any) {
      setSubmitError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const riskColor = (v: number) =>
    v >= 0.75 ? 'bg-status-critical' : v >= 0.5 ? 'bg-status-high' : v >= 0.25 ? 'bg-status-medium' : 'bg-status-low';

  return (
    <div className="fixed inset-0 bg-bg-darkest/85 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-surface-default border border-surface-border rounded-2xl w-full max-w-4xl my-4 shadow-2xl flex flex-col">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-5 border-b border-surface-border shrink-0">
          <div className="flex items-center gap-3">
            <ClipboardCheck className="w-5 h-5 text-teal-accent" />
            <div>
              <h2 className="font-bold text-text-primary font-mono text-sm uppercase">Analyst Review</h2>
              {detail && (
                <p className="text-xs text-text-muted font-mono mt-0.5 truncate max-w-md">
                  {detail.subject}
                </p>
              )}
            </div>
          </div>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {loading && (
          <div className="flex-1 flex items-center justify-center p-16 text-teal-accent font-mono gap-2">
            <Loader2 className="w-5 h-5 animate-spin" /><span>Loading detection context...</span>
          </div>
        )}

        {error && (
          <div className="p-6 text-status-critical font-mono text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />{error}
          </div>
        )}

        {submitted && (
          <div className="flex-1 flex flex-col items-center justify-center p-16 gap-4">
            <CheckCircle2 className="w-16 h-16 text-status-low" />
            <p className="font-mono font-bold text-text-primary text-lg">Review Submitted</p>
            <p className="font-mono text-text-muted text-sm">Audit trail recorded. Closing...</p>
          </div>
        )}

        {detail && !submitted && (
          <>
            {/* Risk Summary Bar */}
            <div className="flex items-center gap-6 px-5 py-3 border-b border-surface-border bg-bg-darkest/40 font-mono text-xs flex-wrap">
              <div className="flex items-center gap-2">
                <span className="text-text-muted uppercase">Risk Score</span>
                <span className={`font-bold text-lg ${
                  detail.final_risk_score >= 0.75 ? 'text-status-critical' :
                  detail.final_risk_score >= 0.5 ? 'text-status-high' :
                  detail.final_risk_score >= 0.25 ? 'text-status-medium' : 'text-status-low'
                }`}>{(detail.final_risk_score * 100).toFixed(0)}%</span>
              </div>
              <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${SEVERITY_COLORS[detail.severity] || ''}`}>
                {detail.severity}
              </span>
              <span className="text-text-muted">Decision: <span className="text-text-primary font-bold">{detail.decision}</span></span>
              <span className="text-text-muted">Confidence: <span className="text-teal-accent font-bold">{(detail.confidence * 100).toFixed(0)}%</span></span>
              {detail.existing_feedback && (
                <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${CLASSIFICATION_COLORS[detail.existing_feedback.classification] || ''}`}>
                  Previously: {detail.existing_feedback.classification.replace('_', ' ')}
                </span>
              )}
            </div>

            <div className="flex-1 flex flex-col lg:flex-row overflow-hidden">
              {/* Left Panel: Evidence Tabs */}
              <div className="flex-1 border-b lg:border-b-0 lg:border-r border-surface-border overflow-y-auto">
                {/* Tabs */}
                <div className="flex border-b border-surface-border font-mono text-xs">
                  {([
                    { id: 'evidence', label: 'Risk Evidence' },
                    { id: 'signals', label: `Signals (${detail.risk_signals.length})` },
                    { id: 'email', label: 'Email Context' },
                  ] as const).map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setActiveTab(tab.id)}
                      className={`px-4 py-2.5 border-b-2 transition-colors ${
                        activeTab === tab.id
                          ? 'border-teal-accent text-teal-accent'
                          : 'border-transparent text-text-muted hover:text-text-secondary'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                <div className="p-4 space-y-4">
                  {/* EVIDENCE TAB */}
                  {activeTab === 'evidence' && (
                    <>
                      <div className="space-y-3">
                        <RiskBar label="Content NLP Risk" value={detail.content_risk} color={riskColor(detail.content_risk)} />
                        <RiskBar label="URL & Domain Risk" value={detail.url_risk} color={riskColor(detail.url_risk)} />
                        <RiskBar label="Identity / Auth Risk" value={detail.identity_risk} color={riskColor(detail.identity_risk)} />
                        <RiskBar label="Threat Intel Risk" value={detail.threat_intel_risk} color={riskColor(detail.threat_intel_risk)} />
                        <RiskBar label="Graph Intelligence Risk" value={detail.graph_risk} color={riskColor(detail.graph_risk)} />
                      </div>

                      {detail.explanation_summary && (
                        <div className="bg-teal-accent/5 border border-teal-accent/20 rounded-lg p-3">
                          <div className="text-[10px] font-mono text-teal-accent uppercase tracking-wider mb-1">AI Explanation</div>
                          <p className="text-xs font-mono text-text-secondary leading-relaxed">{detail.explanation_summary}</p>
                        </div>
                      )}

                      {detail.recommended_action && (
                        <div className="bg-surface-card border border-surface-border rounded-lg p-3">
                          <div className="text-[10px] font-mono text-text-muted uppercase tracking-wider mb-1">Recommended Action</div>
                          <p className="text-xs font-mono text-text-primary font-bold">{detail.recommended_action}</p>
                        </div>
                      )}

                      {detail.urls.length > 0 && (
                        <div>
                          <div className="text-[10px] font-mono text-text-muted uppercase tracking-wider mb-2">Extracted URLs ({detail.urls.length})</div>
                          <div className="space-y-1 max-h-32 overflow-y-auto">
                            {detail.urls.map((u, i) => (
                              <div key={i} className="text-[11px] font-mono text-status-high bg-status-high/5 border border-status-high/20 px-2 py-1 rounded truncate" title={u}>
                                {u}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}

                  {/* SIGNALS TAB */}
                  {activeTab === 'signals' && (
                    <div className="space-y-2">
                      {detail.risk_signals.length === 0 ? (
                        <p className="text-text-muted text-xs font-mono py-4 text-center">No granular risk signals recorded for this detection.</p>
                      ) : (
                        detail.risk_signals.map((sig, i) => (
                          <div key={i} className="bg-bg-darkest border border-surface-border rounded-lg p-3">
                            <div className="flex items-center justify-between mb-1">
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] font-mono font-bold text-teal-accent bg-teal-accent/10 border border-teal-accent/20 px-1.5 py-0.5 rounded">
                                  {sig.layer}
                                </span>
                                <span className="text-[10px] font-mono text-text-muted">{sig.signal_type}</span>
                              </div>
                              <span className={`text-xs font-bold font-mono ${
                                sig.score >= 0.75 ? 'text-status-critical' : sig.score >= 0.5 ? 'text-status-high' : sig.score >= 0.25 ? 'text-status-medium' : 'text-status-low'
                              }`}>{(sig.score * 100).toFixed(0)}%</span>
                            </div>
                            <p className="text-[11px] text-text-secondary font-mono">{sig.description}</p>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* EMAIL CONTEXT TAB */}
                  {activeTab === 'email' && (
                    <div className="space-y-3 font-mono text-xs">
                      {[
                        { label: 'From', value: detail.sender },
                        { label: 'Domain', value: detail.sender_domain },
                        { label: 'To', value: detail.recipient },
                        { label: 'Subject', value: detail.subject },
                        { label: 'Received', value: new Date(detail.received_at).toLocaleString() },
                        { label: 'Message ID', value: detail.message_id },
                        { label: 'State', value: detail.state },
                      ].map((row) => (
                        <div key={row.label} className="flex gap-4">
                          <span className="text-text-muted w-24 shrink-0 uppercase text-[10px] tracking-wider pt-0.5">{row.label}</span>
                          <span className="text-text-primary break-all">{row.value}</span>
                        </div>
                      ))}
                      <div className="flex gap-2 pt-1">
                        <AuthBadge label="SPF" result={detail.spf_result} />
                        <AuthBadge label="DKIM" result={detail.dkim_result} />
                        <AuthBadge label="DMARC" result={detail.dmarc_result} />
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Right Panel: Classification */}
              <div className="w-full lg:w-80 shrink-0 p-4 space-y-4 overflow-y-auto">
                <div>
                  <div className="text-[10px] font-mono font-bold text-teal-accent uppercase tracking-wider mb-2">
                    Analyst Identity
                  </div>
                  <div className="flex items-center gap-2 bg-bg-darkest border border-surface-border rounded-lg px-3 py-2">
                    <User className="w-3.5 h-3.5 text-text-muted shrink-0" />
                    <input
                      type="text"
                      value={analystName}
                      onChange={(e) => setAnalystName(e.target.value)}
                      placeholder="Your name or analyst ID"
                      className="flex-1 bg-transparent text-xs font-mono text-text-primary focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-mono font-bold text-teal-accent uppercase tracking-wider mb-2">
                    Classification *
                  </div>
                  <div className="space-y-2">
                    {CLASSIFICATION_OPTIONS.map((opt) => {
                      const Icon = opt.icon;
                      const isSelected = classification === opt.value;
                      return (
                        <button
                          key={opt.value}
                          onClick={() => setClassification(opt.value)}
                          className={`w-full text-left p-3 rounded-lg border transition-all ${
                            isSelected ? opt.selected : `border-surface-border hover:border-surface-border/80 ${opt.color} opacity-60 hover:opacity-90`
                          }`}
                        >
                          <div className="flex items-center gap-2 mb-0.5">
                            <Icon className="w-3.5 h-3.5 shrink-0" />
                            <span className="font-mono text-xs font-bold">{opt.label}</span>
                            {isSelected && <CheckCircle2 className="w-3 h-3 ml-auto" />}
                          </div>
                          <p className="font-mono text-[10px] opacity-80">{opt.desc}</p>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-mono font-bold text-teal-accent uppercase tracking-wider mb-2">
                    Analyst Rationale / Comments *
                  </div>
                  <textarea
                    value={comments}
                    onChange={(e) => setComments(e.target.value)}
                    rows={4}
                    placeholder="Explain your classification decision — this is recorded in the audit trail and used for model improvement."
                    className="w-full bg-bg-darkest border border-surface-border rounded-lg px-3 py-2 text-xs font-mono text-text-primary focus:outline-none focus:border-teal-accent resize-none leading-relaxed"
                  />
                  <p className="text-[10px] text-text-muted font-mono mt-1">
                    Required for audit trail. Stored for offline analysis only.
                  </p>
                </div>

                {submitError && (
                  <div className="bg-status-critical/10 border border-status-critical/30 rounded-lg p-3 text-xs font-mono text-status-critical flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />{submitError}
                  </div>
                )}

                <button
                  onClick={handleSubmit}
                  disabled={submitting || !classification}
                  className="w-full flex items-center justify-center gap-2 bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-mono text-xs font-bold px-4 py-2.5 rounded-lg transition-all shadow-teal-glow disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {submitting
                    ? <><Loader2 className="w-4 h-4 animate-spin" /> Submitting...</>
                    : <><Send className="w-4 h-4" /> Submit Classification</>
                  }
                </button>

                <p className="text-[10px] font-mono text-text-muted text-center leading-relaxed">
                  Feedback is stored for analyst review only.
                  No automatic model retraining occurs.
                </p>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

type PageView = 'queue' | 'history' | 'stats';

export const ReviewQueuePage: React.FC = () => {
  const [view, setView] = useState<PageView>('queue');
  const [queueItems, setQueueItems] = useState<ReviewQueueItem[]>([]);
  const [historyItems, setHistoryItems] = useState<FeedbackHistoryItem[]>([]);
  const [stats, setStats] = useState<ReviewStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [selectedDetectionId, setSelectedDetectionId] = useState<string | null>(null);
  const [histClassFilter, setHistClassFilter] = useState('ALL');
  const [exporting, setExporting] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState('');

  const fetchQueue = useCallback(async () => {
    try {
      setError(null);
      const resp = await fetch('/api/v1/review/queue?limit=200');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setQueueItems(data);
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const params = histClassFilter !== 'ALL' ? `?classification=${histClassFilter}` : '';
      const resp = await fetch(`/api/v1/review/history${params}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setHistoryItems(data);
    } catch { /* non-critical */ }
  }, [histClassFilter]);

  const fetchStats = useCallback(async () => {
    try {
      const resp = await fetch('/api/v1/review/stats');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setStats(data);
    } catch { /* non-critical */ }
  }, []);

  useEffect(() => {
    fetchQueue();
    fetchStats();
  }, [fetchQueue, fetchStats]);

  useEffect(() => {
    if (view === 'history') fetchHistory();
  }, [view, fetchHistory]);

  const handleExport = async (format: 'json' | 'csv') => {
    setExporting(true);
    try {
      const resp = await fetch(`/api/v1/review/export?format=${format}`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `trinetra_feedback_export.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { /* show inline error in future */ }
    finally { setExporting(false); }
  };

  const filteredQueue = queueItems.filter((item) => {
    const matchesSearch =
      item.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.sender_domain.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSev = severityFilter === 'ALL' || item.severity === severityFilter;
    return matchesSearch && matchesSev;
  });

  const filteredHistory = historyItems.filter((item) =>
    item.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
    item.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (item.analyst_name || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ClipboardCheck className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Analyst Review Queue
            </h1>
            {queueItems.length > 0 && (
              <span className="bg-status-high/90 text-bg-darkest text-[10px] font-bold font-mono px-2 py-0.5 rounded-full">
                {queueItems.length} PENDING
              </span>
            )}
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Human-in-the-loop review of uncertain and medium-confidence detections.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {lastRefreshed && (
            <span className="text-xs text-text-muted font-mono flex items-center gap-1">
              <Clock className="w-3 h-3" />{lastRefreshed}
            </span>
          )}
          <div className="flex items-center gap-1">
            <button
              onClick={() => handleExport('json')}
              disabled={exporting}
              className="flex items-center gap-1.5 bg-surface-card border border-teal-accent/30 hover:border-teal-accent text-teal-accent font-mono text-xs px-3 py-2 rounded transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={() => handleExport('csv')}
              disabled={exporting}
              className="flex items-center gap-1.5 bg-surface-card border border-teal-accent/30 hover:border-teal-accent text-teal-accent font-mono text-xs px-3 py-2 rounded transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          </div>
          <button
            onClick={() => { setLoading(true); fetchQueue(); fetchStats(); }}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* View Tabs */}
      <div className="flex gap-1 border-b border-surface-border font-mono text-xs">
        {([
          { id: 'queue', label: 'Review Queue', icon: ClipboardCheck },
          { id: 'stats', label: 'Dashboard', icon: BarChart2 },
          { id: 'history', label: 'Audit History', icon: History },
        ] as const).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setView(id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 border-b-2 transition-colors ${
              view === id ? 'border-teal-accent text-teal-accent' : 'border-transparent text-text-muted hover:text-text-secondary'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* ── QUEUE VIEW ── */}
      {view === 'queue' && (
        <>
          {/* Filter Bar */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-3 flex flex-wrap items-center gap-3 font-mono text-xs">
            <div className="relative flex-1 min-w-48">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by sender, subject, domain..."
                className="w-full bg-bg-darkest border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-3.5 h-3.5 text-text-muted" />
              <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent">
                <option value="ALL">All Severities</option>
                {['CRITICAL','HIGH','MEDIUM','LOW'].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <span className="text-text-muted ml-auto">{filteredQueue.length} items</span>
          </div>

          {error && (
            <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 flex items-center gap-2 text-xs font-mono text-status-critical">
              <AlertTriangle className="w-4 h-4 shrink-0" />{error}
              <button onClick={fetchQueue} className="ml-auto underline font-bold">Retry</button>
            </div>
          )}

          {loading ? (
            <div className="bg-surface-default border border-surface-border rounded-xl p-10 flex items-center justify-center gap-2 text-teal-accent font-mono">
              <Loader2 className="w-5 h-5 animate-spin" /><span>Loading review queue...</span>
            </div>
          ) : filteredQueue.length === 0 ? (
            <div className="bg-surface-default border border-surface-border rounded-xl p-12 text-center font-mono">
              <ShieldCheck className="w-12 h-12 text-status-low mx-auto mb-3" />
              <p className="font-bold text-text-primary mb-1">Queue Clear</p>
              <p className="text-xs text-text-muted">No detections pending analyst review.</p>
            </div>
          ) : (
            <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-bg-darkest/70 text-text-muted uppercase text-[10px] border-b border-surface-border">
                    <tr>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Subject</th>
                      <th className="py-3 px-4">Sender</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Confidence</th>
                      <th className="py-3 px-4">Decision</th>
                      <th className="py-3 px-4">Auth</th>
                      <th className="py-3 px-4">Received</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-border">
                    {filteredQueue.map((item) => (
                      <tr key={item.detection_id} className="hover:bg-surface-hover/60 transition-colors">
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${SEVERITY_COLORS[item.severity] || ''}`}>
                            {item.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 max-w-xs">
                          <div className="font-bold text-text-primary truncate" title={item.subject}>{item.subject}</div>
                          <div className="text-text-muted text-[10px] truncate">{item.message_id}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-teal-accent truncate max-w-[160px]" title={item.sender}>{item.sender}</div>
                          <div className="text-text-muted text-[10px]">{item.sender_domain}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className={`font-bold text-sm ${
                            item.final_risk_score >= 0.75 ? 'text-status-critical' :
                            item.final_risk_score >= 0.5 ? 'text-status-high' :
                            item.final_risk_score >= 0.25 ? 'text-status-medium' : 'text-status-low'
                          }`}>{(item.final_risk_score * 100).toFixed(0)}%</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5">
                            <div className="w-14 bg-surface-card rounded-full h-1.5">
                              <div className="h-1.5 rounded-full bg-teal-accent" style={{ width: `${(item.confidence * 100).toFixed(0)}%` }} />
                            </div>
                            <span className="text-text-secondary">{(item.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className="text-text-secondary">{item.decision}</span>
                        </td>
                        <td className="py-3 px-4 space-x-0.5 whitespace-nowrap">
                          <AuthBadge label="SPF" result={item.spf_result} />
                        </td>
                        <td className="py-3 px-4 text-text-muted whitespace-nowrap">
                          {new Date(item.received_at).toLocaleDateString()}
                        </td>
                        <td className="py-3 px-4">
                          {item.has_feedback ? (
                            <span className="flex items-center gap-1 text-status-low text-[10px]">
                              <CheckCircle2 className="w-3.5 h-3.5" />REVIEWED
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-status-medium text-[10px]">
                              <Clock className="w-3.5 h-3.5" />PENDING
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <button
                            onClick={() => setSelectedDetectionId(item.detection_id)}
                            className="flex items-center gap-1.5 text-teal-accent hover:text-teal-vibrant font-mono text-[11px] border border-teal-accent/30 hover:border-teal-accent/60 px-2 py-1 rounded transition-all"
                          >
                            <Eye className="w-3.5 h-3.5" />
                            {item.has_feedback ? 'Re-Review' : 'Review'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── STATS VIEW ── */}
      {view === 'stats' && stats && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Pending Reviews', value: stats.pending_reviews, color: 'text-status-high' },
              { label: 'Reviewed Today', value: stats.reviewed_today, color: 'text-teal-accent' },
              { label: 'Total Reviewed', value: stats.reviewed_total, color: 'text-status-low' },
              { label: 'False Positive Rate', value: `${(stats.false_positive_rate * 100).toFixed(1)}%`, color: 'text-status-medium' },
            ].map((s) => (
              <div key={s.label} className="bg-surface-default border border-surface-border rounded-xl p-4 text-center">
                <div className={`text-3xl font-bold font-mono ${s.color}`}>{s.value}</div>
                <div className="text-[10px] text-text-muted font-mono uppercase mt-1">{s.label}</div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Feedback Distribution */}
            <div className="bg-surface-default border border-surface-border rounded-xl p-5">
              <h3 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-4">Feedback Distribution</h3>
              <div className="space-y-3">
                {Object.entries(stats.feedback_distribution).map(([cls, cnt]) => {
                  const total = Object.values(stats.feedback_distribution).reduce((a, b) => a + b, 0);
                  const pct = total > 0 ? (cnt / total) * 100 : 0;
                  return (
                    <div key={cls}>
                      <div className="flex justify-between text-xs font-mono mb-1">
                        <span className={`font-bold ${CLASSIFICATION_COLORS[cls]?.split(' ')[0] || 'text-text-secondary'}`}>
                          {cls.replace('_', ' ')}
                        </span>
                        <span className="text-text-muted">{cnt} ({pct.toFixed(0)}%)</span>
                      </div>
                      <div className="w-full bg-surface-card rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${
                            cls === 'TRUE_POSITIVE' ? 'bg-status-critical' :
                            cls === 'FALSE_POSITIVE' ? 'bg-status-medium' :
                            cls === 'TRUE_NEGATIVE' ? 'bg-status-low' : 'bg-status-high'
                          }`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Queue by Severity */}
            <div className="bg-surface-default border border-surface-border rounded-xl p-5">
              <h3 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-4">
                Queue Breakdown by Severity
              </h3>
              <div className="space-y-3">
                {Object.entries(stats.review_queue_by_severity).map(([sev, cnt]) => (
                  <div key={sev} className="flex items-center justify-between font-mono text-xs">
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${SEVERITY_COLORS[sev] || ''}`}>{sev}</span>
                    <div className="flex items-center gap-3 flex-1 ml-3">
                      <div className="flex-1 bg-surface-card rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${
                            sev === 'CRITICAL' ? 'bg-status-critical' : sev === 'HIGH' ? 'bg-status-high' :
                            sev === 'MEDIUM' ? 'bg-status-medium' : 'bg-status-low'
                          }`}
                          style={{ width: cnt > 0 ? '100%' : '0%', maxWidth: `${(cnt / (stats.pending_reviews || 1)) * 100}%` }}
                        />
                      </div>
                      <span className="text-text-primary font-bold w-8 text-right">{cnt}</span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 pt-3 border-t border-surface-border font-mono text-xs text-text-muted">
                Avg. confidence in queue: <span className="text-teal-accent font-bold">{(stats.avg_confidence_in_queue * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>

          {/* Analyst Activity */}
          {stats.analyst_activity.length > 0 && (
            <div className="bg-surface-default border border-surface-border rounded-xl p-5">
              <h3 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-4">Analyst Activity</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="text-text-muted uppercase text-[10px] border-b border-surface-border">
                    <tr>
                      <th className="pb-2 px-2">Analyst</th>
                      <th className="pb-2 px-2">Reviews Submitted</th>
                      <th className="pb-2 px-2">Last Active</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-border">
                    {stats.analyst_activity.map((a, i) => (
                      <tr key={i} className="hover:bg-surface-hover/50">
                        <td className="py-2 px-2 font-bold text-text-primary flex items-center gap-2">
                          <User className="w-3.5 h-3.5 text-teal-accent" />{a.analyst_name}
                        </td>
                        <td className="py-2 px-2 text-teal-accent font-bold">{a.reviews_submitted}</td>
                        <td className="py-2 px-2 text-text-muted">
                          {a.last_active ? new Date(a.last_active).toLocaleString() : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── HISTORY VIEW ── */}
      {view === 'history' && (
        <>
          <div className="bg-surface-default border border-surface-border rounded-xl p-3 flex flex-wrap items-center gap-3 font-mono text-xs">
            <div className="relative flex-1 min-w-48">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by subject, sender, analyst..."
                className="w-full bg-bg-darkest border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>
            <select value={histClassFilter} onChange={(e) => setHistClassFilter(e.target.value)}
              className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent">
              <option value="ALL">All Classifications</option>
              {['TRUE_POSITIVE','FALSE_POSITIVE','TRUE_NEGATIVE','FALSE_NEGATIVE'].map((c) => (
                <option key={c} value={c}>{c.replace('_', ' ')}</option>
              ))}
            </select>
            <span className="text-text-muted ml-auto">{filteredHistory.length} records</span>
          </div>

          <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-bg-darkest/70 text-text-muted uppercase text-[10px] border-b border-surface-border">
                  <tr>
                    <th className="py-3 px-4">Classification</th>
                    <th className="py-3 px-4">Subject</th>
                    <th className="py-3 px-4">Sender</th>
                    <th className="py-3 px-4">Risk / Severity</th>
                    <th className="py-3 px-4">Analyst (WHO)</th>
                    <th className="py-3 px-4">Reviewed At (WHEN)</th>
                    <th className="py-3 px-4">Comments (WHY)</th>
                    <th className="py-3 px-4">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-border">
                  {filteredHistory.map((item) => (
                    <tr key={item.feedback_id} className="hover:bg-surface-hover/60 transition-colors">
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${CLASSIFICATION_COLORS[item.classification] || ''}`}>
                          {item.classification.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-xs">
                        <div className="font-bold text-text-primary truncate" title={item.subject}>{item.subject}</div>
                      </td>
                      <td className="py-3 px-4 text-teal-accent truncate max-w-[140px]">{item.sender}</td>
                      <td className="py-3 px-4">
                        <div className={`font-bold ${
                          item.final_risk_score >= 0.75 ? 'text-status-critical' :
                          item.final_risk_score >= 0.5 ? 'text-status-high' :
                          item.final_risk_score >= 0.25 ? 'text-status-medium' : 'text-status-low'
                        }`}>{(item.final_risk_score * 100).toFixed(0)}%</div>
                        <span className={`text-[10px] ${SEVERITY_COLORS[item.severity]?.split(' ')[0] || ''}`}>{item.severity}</span>
                      </td>
                      <td className="py-3 px-4 font-bold text-text-primary">
                        <div className="flex items-center gap-1.5">
                          <User className="w-3.5 h-3.5 text-teal-accent shrink-0" />
                          {item.analyst_name || 'Unknown'}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-text-muted whitespace-nowrap">
                        {new Date(item.reviewed_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 max-w-xs">
                        {item.comments ? (
                          <p className="text-text-secondary text-[11px] truncate" title={item.comments}>{item.comments}</p>
                        ) : (
                          <span className="text-text-muted italic">No comment</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-text-muted text-[10px]">{item.review_source}</td>
                    </tr>
                  ))}
                  {filteredHistory.length === 0 && (
                    <tr>
                      <td colSpan={8} className="py-10 text-center text-text-muted">
                        No feedback history yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* Review Modal */}
      {selectedDetectionId && (
        <ReviewModal
          detectionId={selectedDetectionId}
          onClose={() => setSelectedDetectionId(null)}
          onSubmitted={() => { fetchQueue(); fetchStats(); }}
        />
      )}
    </div>
  );
};
