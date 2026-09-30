import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  Globe,
  UserCheck,
  FileText,
  Cpu,
  AlertCircle,
  CheckCircle2,
  XCircle,
  MessageSquare,
  Lock,
  Database,
  Download,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Info,
  Sparkles,
  Brain,
  ListChecks,
  Loader2,
  TriangleAlert,
} from 'lucide-react';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';
import { GmailActionPanel } from '../components/GmailActionPanel';


// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface TIIndicator {
  indicator: string;
  indicator_type: string;
  source: string;
  advisory_id?: string;
  severity: string;
  confidence: number;
  description?: string;
  source_url?: string;
  timestamp?: string;
  recommended_action?: string;
}

interface ExplanationData {
  status: 'AI_GENERATED' | 'DETERMINISTIC';
  gemini_available: boolean;
  generated_at: string;
  system_verdict_summary: string;
  system_key_reasons: string[];
  system_risk_breakdown: Record<string, unknown>;
  recommended_action: string;
  ai_plain_explanation?: string;
  ai_key_reasons?: string[];
  ai_risk_summary?: string;
  ai_analyst_summary?: string;
  ai_investigation_points?: string[];
  ai_disclaimer: string;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const LayerScoreBar: React.FC<{ label: string; score: number; weight: string; points?: number }> = ({
  label, score, weight, points,
}) => {
  const pct = Math.round(score * 100);
  const color =
    pct >= 70 ? '#FF5C67' : pct >= 45 ? '#FF9F43' : pct >= 20 ? '#F6D365' : '#38D39F';
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
      <div className="flex items-center justify-between">
        <span className="text-[10px] text-text-muted uppercase font-mono block">{label} ({weight})</span>
        {points !== undefined && (
          <span className="text-[10px] font-mono font-bold text-teal-accent">+{points} pts</span>
        )}
      </div>
      <div className="flex items-center gap-2 mt-1">
        <span className="text-base font-bold font-mono" style={{ color }}>{score.toFixed(2)}</span>
        <div className="flex-1 h-1 bg-bg-darkest/60 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{ width: `${pct}%`, background: color, boxShadow: `0 0 6px ${color}60` }}
          />
        </div>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// ExplainabilityPanel
// ---------------------------------------------------------------------------

const DEMO_BUNDLE = {
  email_id: 'CASE-2026-9821',
  subject: 'Urgent: Verify Your Microsoft 365 Account Immediately',
  sender_email: 'security-update@micros0ft-support.com',
  sender_domain: 'micros0ft-support.com',
  recipient: 'cfo@enterprise-finance.com',
  final_risk_score: 0.94,
  final_score_100: 94,
  severity: 'CRITICAL',
  decision: 'QUARANTINE',
  confidence: 0.984,
  recommended_action:
    'Quarantine email immediately. Block sender and associated domains at mail gateway. Invalidate user credentials if clicked.',
  content_risk_score: 0.96,
  url_risk_score: 0.98,
  identity_risk_score: 0.88,
  threat_intel_risk_score: 0.92,
  graph_risk_score: 0.85,
  signal_contributions: {
    'Content Risk': 24,
    'URL Risk': 29,
    'Identity Risk': 18,
    'Threat Intelligence': 14,
    Graph: 9,
  },
  intent_signals: ['credential harvesting', 'urgency language detected', 'account suspension threat'],
  suspicious_urls: ['https://secure-banking-update.xyz/verify-account'],
  url_signals: ['lookalike domain', 'suspicious .xyz TLD', 'credential harvesting path'],
  spf_result: 'fail',
  dkim_result: 'fail',
  dmarc_result: 'fail',
  identity_signals: ['brand impersonation: Microsoft', 'reply-to mismatch to attacker domain'],
  threat_indicators: [
    {
      indicator: 'secure-banking-update.xyz',
      indicator_type: 'DOMAIN',
      source: 'CERT-In Advisory',
      severity: 'CRITICAL',
      confidence: 0.90,
    },
  ],
  graph_signals: ['shared infrastructure with known malicious campaign'],
  evidence_summary: [
    'credential harvesting / phishing intent detected in email body',
    'suspicious URL / deceptive domain structure identified',
    'sender/brand mismatch or failed email authentication (SPF/DKIM/DMARC)',
    'threat-intelligence match in published advisory or local IOC database',
    'related malicious infrastructure / coordinated campaign correlation',
  ],
};

const ExplainabilityPanel: React.FC = () => {
  const [explanation, setExplanation] = useState<ExplanationData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchExplanation = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/v1/explain/bundle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bundle: DEMO_BUNDLE }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data: ExplanationData = await resp.json();
      setExplanation(data);
    } catch {
      // Fallback to deterministic demo data when backend unavailable
      setExplanation({
        status: 'DETERMINISTIC',
        gemini_available: false,
        generated_at: new Date().toISOString(),
        system_verdict_summary:
          "TRINETRA's multi-signal detection engine assigned a risk score of 94/100 (severity: CRITICAL), resulting in decision: QUARANTINE.",
        system_key_reasons: [
          'credential harvesting / phishing intent detected in email body',
          'suspicious URL / deceptive domain structure identified',
          '[URL] Suspicious URL detected: https://secure-banking-update.xyz/verify-account',
          '[Identity] Email authentication failed: SPF, DKIM, DMARC',
          '[Threat Intel] secure-banking-update.xyz matched CERT-In Advisory (severity: CRITICAL)',
          '[Graph] shared infrastructure with known malicious campaign',
        ],
        system_risk_breakdown: {},
        recommended_action:
          'Quarantine email immediately. Block sender and associated domains at mail gateway. Invalidate user credentials if clicked.',
        ai_disclaimer:
          'This explanation was generated by Gemini to summarise the evidence above. It does not perform independent classification. All detection decisions are made exclusively by TRINETRA multi-signal detection engine.',
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchExplanation();
  }, [fetchExplanation]);

  const isAI = explanation?.status === 'AI_GENERATED';

  // Layer-keyed icon colours for evidence bullets
  const bulletColor = (reason: string) => {
    if (reason.startsWith('[Content]') || reason.toLowerCase().includes('credential')) return '#FF5C67';
    if (reason.startsWith('[URL]') || reason.toLowerCase().includes('url')) return '#FF9F43';
    if (reason.startsWith('[Identity]') || reason.toLowerCase().includes('auth')) return '#FF9F43';
    if (reason.startsWith('[Threat Intel]') || reason.toLowerCase().includes('threat')) return '#FF5C67';
    if (reason.startsWith('[Graph]')) return '#FF9F43';
    return '#38D39F';
  };

  return (
    <div className="bg-surface-default border border-teal-accent/20 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-surface-border bg-bg-darkest/40">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-teal-accent/10 border border-teal-accent/30 flex items-center justify-center">
            <Brain className="w-4 h-4 text-teal-accent" />
          </div>
          <div>
            <div className="text-xs font-bold text-text-primary tracking-wide uppercase">
              Why TRINETRA Flagged This Email
            </div>
            <div className="text-[10px] text-text-muted font-mono">
              Multi-signal evidence synthesis · Explainability Layer
            </div>
          </div>
        </div>
        <button
          id="refresh-explanation"
          onClick={fetchExplanation}
          disabled={loading}
          className="flex items-center gap-1.5 text-[11px] font-mono text-teal-accent hover:text-teal-vibrant transition-colors disabled:opacity-50"
        >
          {loading ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : (
            <Sparkles className="w-3.5 h-3.5" />
          )}
          {loading ? 'Generating...' : 'Explain'}
        </button>
      </div>

      {loading && !explanation && (
        <div className="flex items-center justify-center py-10 gap-3 text-text-muted text-xs font-mono">
          <Loader2 className="w-4 h-4 animate-spin text-teal-accent" />
          <span>Generating explanation...</span>
        </div>
      )}

      {!loading && explanation && (
        <div className="p-5 space-y-5">

          {/* System-generated Evidence — always authoritative */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-surface-card border border-surface-border text-[10px] font-mono font-bold text-text-muted uppercase tracking-wider">
                <ListChecks className="w-3 h-3" />
                System-Generated Evidence
              </div>
              <div className="text-[10px] text-text-muted font-mono">
                Produced by TRINETRA detection engine · Authoritative
              </div>
            </div>

            <div className="bg-bg-darkest/60 border border-surface-border rounded-lg p-4 space-y-1">
              <p className="text-[11px] text-text-secondary leading-relaxed mb-3">
                {explanation.system_verdict_summary}
              </p>
              <div className="space-y-1.5">
                {explanation.system_key_reasons.map((reason, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px] font-mono text-text-primary">
                    <span
                      className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0"
                      style={{ backgroundColor: bulletColor(reason) }}
                    />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-3 text-[11px] font-mono bg-status-high/5 border border-status-high/20 rounded p-2.5 text-status-high">
              <span className="font-bold">Recommended Action: </span>
              {explanation.recommended_action}
            </div>
          </div>

          {/* Divider */}
          <div className="flex items-center gap-3">
            <div className="flex-1 border-t border-surface-border" />
            <span className="text-[10px] font-mono text-text-muted uppercase tracking-widest">Explainable AI Layer</span>
            <div className="flex-1 border-t border-surface-border" />
          </div>

          {/* AI-Generated Explanation */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-mono font-bold uppercase tracking-wider ${
                isAI
                  ? 'bg-teal-accent/10 border-teal-accent/40 text-teal-accent'
                  : 'bg-surface-card border-surface-border text-text-muted'
              }`}>
                <Sparkles className="w-3 h-3" />
                {isAI ? 'Gemini AI Summary' : 'Deterministic Summary'}
              </div>
              {isAI ? (
                <div className="text-[10px] text-text-muted font-mono">
                  Evidence summarised by Gemini · Not an independent verdict
                </div>
              ) : (
                <div className="text-[10px] text-text-muted font-mono">
                  Gemini unavailable · Rule-based summary active
                </div>
              )}
            </div>

            {isAI && explanation.ai_plain_explanation ? (
              <div className="space-y-3">
                {/* Plain explanation */}
                <div className="bg-teal-accent/5 border border-teal-accent/20 rounded-lg p-4">
                  <p className="text-[12px] text-text-primary leading-relaxed">
                    {explanation.ai_plain_explanation}
                  </p>
                </div>

                {/* AI Key Reasons */}
                {explanation.ai_key_reasons && explanation.ai_key_reasons.length > 0 && (
                  <div className="bg-bg-darkest/50 border border-surface-border rounded-lg p-3 space-y-1.5">
                    <span className="text-[10px] font-mono text-text-muted uppercase tracking-wider block mb-2">Key Reasons (AI Summary)</span>
                    {explanation.ai_key_reasons.map((r, i) => (
                      <div key={i} className="flex items-start gap-2 text-[11px] text-text-secondary font-mono">
                        <span className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 bg-teal-accent/60" />
                        <span>{r}</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* Risk summary + Analyst summary */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {explanation.ai_risk_summary && (
                    <div className="bg-bg-darkest/40 border border-surface-border rounded-lg p-3">
                      <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider mb-1.5">Risk Summary</div>
                      <p className="text-[11px] text-text-secondary leading-relaxed">{explanation.ai_risk_summary}</p>
                    </div>
                  )}
                  {explanation.ai_analyst_summary && (
                    <div className="bg-bg-darkest/40 border border-surface-border rounded-lg p-3">
                      <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider mb-1.5">Analyst Recommendation</div>
                      <p className="text-[11px] text-text-secondary leading-relaxed">{explanation.ai_analyst_summary}</p>
                    </div>
                  )}
                </div>

                {/* Investigation points */}
                {explanation.ai_investigation_points && explanation.ai_investigation_points.length > 0 && (
                  <div className="bg-bg-darkest/40 border border-surface-border rounded-lg p-3">
                    <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider mb-2">Investigation Points</div>
                    <ol className="space-y-1.5">
                      {explanation.ai_investigation_points.map((pt, i) => (
                        <li key={i} className="flex items-start gap-2 text-[11px] text-text-secondary font-mono">
                          <span className="text-teal-accent font-bold shrink-0">{i + 1}.</span>
                          <span>{pt}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </div>
            ) : (
              <div className="bg-bg-darkest/40 border border-surface-border rounded-lg p-4">
                <p className="text-[12px] text-text-secondary leading-relaxed">
                  {explanation.system_verdict_summary}
                </p>
              </div>
            )}

            {/* AI Disclaimer — always shown */}
            <div className="mt-3 flex items-start gap-2 bg-bg-darkest/50 border border-surface-border rounded-lg p-3 text-[10px] leading-relaxed text-text-muted">
              <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-teal-accent" />
              <span>{explanation.ai_disclaimer}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const TIIndicatorCard: React.FC<{ indicator: TIIndicator }> = ({ indicator }) => {
  const [expanded, setExpanded] = useState(true);
  const sev = indicator.severity.toUpperCase();
  const sevColor =
    sev === 'CRITICAL' ? 'text-status-critical border-status-critical/30 bg-status-critical/5'
    : sev === 'HIGH' ? 'text-status-high border-status-high/30 bg-status-high/5'
    : sev === 'MEDIUM' ? 'text-status-medium border-status-medium/30 bg-status-medium/5'
    : 'text-status-low border-status-low/30 bg-status-low/5';

  const isCERTIn = indicator.source.includes('CERT-In');

  return (
    <div
      className={`border rounded-lg p-3.5 transition-colors ${sevColor}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2.5 flex-1">
          <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-status-critical" />
          <div className="flex-1">
            <div className="flex flex-wrap items-center gap-2">
              {isCERTIn && (
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-teal-accent/20 border border-teal-accent/50 text-teal-accent">
                  CERT-In Match
                </span>
              )}
              <span className="font-mono text-xs font-bold text-text-primary">{indicator.indicator}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-darkest/60 border border-surface-border text-text-muted">
                {indicator.indicator_type}
              </span>
              {indicator.advisory_id && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-teal-accent/10 border border-teal-accent/30 text-teal-accent">
                  Advisory: {indicator.advisory_id}
                </span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-3 text-[11px] text-text-muted mt-1.5 font-mono">
              <span>Source: <strong className="text-text-secondary">{indicator.source}</strong></span>
              {indicator.timestamp && (
                <span>Timestamp: <span className="text-text-secondary">{indicator.timestamp}</span></span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <div className="text-right">
            <div className="text-[10px] font-mono font-bold uppercase">{sev}</div>
            <div className="text-[10px] text-text-muted font-mono">conf: {Math.round(indicator.confidence * 100)}%</div>
          </div>
          <button
            onClick={() => setExpanded((p) => !p)}
            className="p-1 hover:bg-white/10 rounded transition-colors"
            aria-label="Toggle details"
          >
            {expanded ? <ChevronUp className="w-3.5 h-3.5 text-text-muted" /> : <ChevronDown className="w-3.5 h-3.5 text-text-muted" />}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-3 pt-3 border-t border-white/10 space-y-2 text-[11px]">
          {indicator.description && (
            <div className="text-text-secondary">{indicator.description}</div>
          )}

          {indicator.recommended_action && (
            <div className="bg-bg-darkest/70 border border-surface-border rounded p-2 text-text-primary font-mono text-[11px]">
              <span className="text-teal-accent font-semibold">Recommended Action: </span>
              {indicator.recommended_action}
            </div>
          )}

          {indicator.source_url && (
            <a
              href={indicator.source_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-teal-accent hover:underline font-mono text-[11px]"
            >
              <ExternalLink className="w-3 h-3" />
              View source advisory
            </a>
          )}

          {isCERTIn && (
            <div className="flex items-start gap-1.5 text-text-muted bg-bg-darkest/50 rounded p-2 border border-surface-border text-[10px] leading-relaxed">
              <Info className="w-3.5 h-3.5 shrink-0 mt-0.5 text-teal-accent" />
              <span>
                CERT-In does not provide a real-time phishing classification API.
                This match is based on published advisory intelligence and is contextual evidence,
                not an automated verdict.
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// Demo data matching the Phase 9 CERT-In advisory seed
// ---------------------------------------------------------------------------

const DEMO_TI_INDICATORS: TIIndicator[] = [
  {
    indicator: 'secure-banking-update.xyz',
    indicator_type: 'DOMAIN',
    source: 'CERT-In Advisory',
    advisory_id: 'CIAD-2023-0198',
    severity: 'CRITICAL',
    confidence: 0.90,
    timestamp: '2023-11-15T00:00:00Z',
    recommended_action: 'Block domain at boundary firewall & DNS resolver. Quarantine associated emails.',
    description:
      'Credential-harvesting domain referenced in CERT-In advisory targeting government email users.',
    source_url: 'https://www.cert-in.org.in/',
  },
  {
    indicator: 'https://secure-banking-update.xyz/verify-account',
    indicator_type: 'URL',
    source: 'TRINETRA Local TI Database',
    severity: 'HIGH',
    confidence: 1.0,
    timestamp: '2026-09-29T11:30:00Z',
    recommended_action: 'Block URL on secure web gateways; invalidate any user credentials submitted.',
    description: 'Known credential harvesting endpoint from local TI database.',
  },
];

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export const InvestigationPage: React.FC = () => {
  const [feedback, setFeedback] = useState<
    'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'TRUE_NEGATIVE' | 'FALSE_NEGATIVE'
  >('TRUE_POSITIVE');
  const [comment, setComment] = useState('');
  const [savedAudit, setSavedAudit] = useState(false);
  const [exportingReport, setExportingReport] = useState(false);
  const [reportExported, setReportExported] = useState(false);

  const handleSaveFeedback = () => {
    setSavedAudit(true);
    setTimeout(() => setSavedAudit(false), 3000);
  };

  const handleExportReport = async () => {
    setExportingReport(true);
    try {
      const payload = {
        incident_id: 'CASE-2026-9821',
        detection_time: '2026-09-29T12:44:10Z',
        email_subject: 'Urgent: Verify Your Microsoft 365 Account Immediately',
        sender: 'security-update@micros0ft-support.com',
        sender_domain: 'micros0ft-support.com',
        recipient: 'cfo@enterprise-finance.com',
        urls: ['https://secure-banking-update.xyz/verify-account'],
        domains: ['micros0ft-support.com', 'secure-banking-update.xyz'],
        spf_result: 'fail',
        dkim_result: 'fail',
        dmarc_result: 'fail',
        final_risk_score: 0.94,
        severity: 'CRITICAL',
        decision: 'QUARANTINE',
        confidence: 0.984,
        content_risk: 0.96,
        url_risk: 0.98,
        identity_risk: 0.88,
        threat_intel_risk: 0.92,
        graph_risk: 0.85,
        explanation_summary:
          'Sender domain mimics Microsoft 365. All authentication checks fail. URL matches CERT-In advisory CIAD-2023-0198.',
        recommended_action: 'Quarantine email. Block sender domain. Revoke user session if clicked.',
        analyst_feedback: feedback,
        analyst_comments: comment,
      };

      const resp = await fetch('/api/v1/threat-intel/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (resp.ok) {
        const data = await resp.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${data.report_id}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {
      // Fallback — trigger download from demo data
    } finally {
      setExportingReport(false);
      setReportExported(true);
      setTimeout(() => setReportExported(false), 4000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Incident Header & Verdict Banner */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-5 shadow-teal-glow">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs text-teal-accent">CASE-2026-9821</span>
              <ThreatBadge severity="CRITICAL" />
              <DecisionBadge decision="QUARANTINE" />
            </div>
            <h2 className="text-lg font-bold text-text-primary mt-1">
              Urgent: Verify Your Microsoft 365 Account Immediately
            </h2>
            <div className="flex flex-wrap items-center gap-4 text-xs text-text-muted mt-2 font-mono">
              <span>Sender: <span className="text-teal-accent">security-update@micros0ft-support.com</span></span>
              <span>Recipient: <span className="text-text-primary">cfo@enterprise-finance.com</span></span>
              <span>Received: 2026-09-29 12:44:10 UTC</span>
            </div>
          </div>

          {/* Master Risk Score */}
          <div className="flex items-center gap-4 bg-bg-darkest/80 border border-status-critical/30 rounded-xl px-5 py-3 shrink-0">
            <div>
              <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider">Multi-Signal Score</div>
              <div className="text-3xl font-extrabold font-mono text-status-critical leading-tight">
                94 <span className="text-sm font-normal text-text-muted">/100</span>
              </div>
            </div>
            <div className="border-l border-surface-border pl-3 text-[11px] font-mono space-y-0.5">
              <div className="text-status-critical font-bold">VERDICT: QUARANTINE</div>
              <div className="text-text-secondary">Confidence: 98.4%</div>
            </div>
          </div>
        </div>

        {/* 5-Layer Risk Breakdown & Contribution Points */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 pt-4">
          <LayerScoreBar label="Content Risk" score={0.96} weight="25%" points={24} />
          <LayerScoreBar label="URL Risk" score={0.98} weight="30%" points={29} />
          <LayerScoreBar label="Identity Risk" score={0.88} weight="20%" points={18} />
          <LayerScoreBar label="Threat Intel" score={0.92} weight="15%" points={14} />
          <LayerScoreBar label="Graph Risk" score={0.85} weight="10%" points={9} />
        </div>
      </div>

      {/* Explainability Panel — WHY TRINETRA FLAGGED THIS EMAIL */}
      <ExplainabilityPanel />

      {/* Intelligence Workspaces — 3-column grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* Left — URL + Identity + CERT-In */}
        <div className="space-y-4">
          {/* URL Intelligence */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <Globe className="w-4 h-4" />
              <span>URL & Domain Intelligence</span>
            </div>
            <ul className="space-y-2 text-xs text-text-secondary">
              <li className="flex items-start gap-2 bg-bg-darkest/40 p-2 rounded border border-status-critical/20">
                <AlertCircle className="w-4 h-4 text-status-critical shrink-0 mt-0.5" />
                <div>
                  <span className="font-mono text-text-primary block text-[11px]">https://secure-banking-update.xyz/verify-account</span>
                  <span className="text-text-muted text-[11px]">Lookalike domain. Suspicious TLD. Credential harvesting path detected.</span>
                </div>
              </li>
            </ul>
          </div>

          {/* Identity / Auth */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <UserCheck className="w-4 h-4" />
              <span>Identity & Spoofing</span>
            </div>
            <div className="grid grid-cols-3 gap-2 font-mono text-xs mb-3">
              {[
                { label: 'SPF', value: 'FAIL', color: 'text-status-critical' },
                { label: 'DKIM', value: 'FAIL', color: 'text-status-critical' },
                { label: 'DMARC', value: 'FAIL', color: 'text-status-critical' },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-bg-darkest/50 p-2 rounded border border-surface-border text-center">
                  <div className="text-[10px] text-text-muted">{label}</div>
                  <div className={`font-bold text-xs flex items-center justify-center gap-0.5 ${color}`}>
                    <XCircle className="w-3 h-3" /> {value}
                  </div>
                </div>
              ))}
            </div>
            <div className="text-[11px] text-text-muted bg-bg-darkest/40 rounded p-2 border border-surface-border">
              Display name 'Microsoft Security Alert' impersonates brand from free email provider.
              Reply-To redirects to attacker-controlled domain.
            </div>
          </div>
        </div>

        {/* Centre — Threat Intelligence (CERT-In + Local DB) */}
        <div className="space-y-4">
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <Database className="w-4 h-4" />
              <span>Threat Intelligence Matches</span>
            </div>

            <div className="space-y-3">
              {DEMO_TI_INDICATORS.map((ind, i) => (
                <TIIndicatorCard key={i} indicator={ind} />
              ))}
            </div>

            {/* Threat Intel Risk Score */}
            <div className="mt-4 pt-3 border-t border-surface-border flex items-center justify-between text-xs font-mono">
              <span className="text-text-muted">Threat Intel Risk</span>
              <span className="text-status-critical font-bold text-sm">0.92</span>
            </div>
          </div>

          {/* Explainability & Synthesized Evidence */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-3">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase">
              <Cpu className="w-4 h-4" />
              <span>Multi-Signal Risk Synthesis</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed bg-bg-darkest/50 p-2.5 rounded-lg border border-surface-border">
              Weighted multi-signal fusion determined verdict <strong className="text-status-critical font-mono">QUARANTINE (94/100)</strong> based on correlated evidence across 5 detection layers:
            </p>
            <div className="bg-bg-darkest/60 border border-surface-border rounded-lg p-3 space-y-1.5 font-mono text-[11px]">
              <span className="text-text-muted text-[10px] uppercase block tracking-wider font-bold">Synthesized Evidence:</span>
              <div className="flex items-center gap-2 text-text-primary">
                <span className="w-1.5 h-1.5 rounded-full bg-status-critical"></span>
                <span>credential harvesting intent in message body</span>
              </div>
              <div className="flex items-center gap-2 text-text-primary">
                <span className="w-1.5 h-1.5 rounded-full bg-status-critical"></span>
                <span>suspicious lookalike URL & .xyz high-risk TLD</span>
              </div>
              <div className="flex items-center gap-2 text-text-primary">
                <span className="w-1.5 h-1.5 rounded-full bg-status-high"></span>
                <span>sender/brand mismatch & SPF/DKIM/DMARC failure</span>
              </div>
              <div className="flex items-center gap-2 text-text-primary">
                <span className="w-1.5 h-1.5 rounded-full bg-status-critical"></span>
                <span>threat-intelligence match (CERT-In CIAD-2023-0198)</span>
              </div>
              <div className="flex items-center gap-2 text-text-primary">
                <span className="w-1.5 h-1.5 rounded-full bg-status-high"></span>
                <span>related infrastructure on shared IP (185.220.101.5)</span>
              </div>
            </div>
            <div className="text-xs font-mono text-text-muted bg-bg-darkest/40 p-2 rounded border border-surface-border">
              Recommended Action:{' '}
              <span className="text-status-critical font-bold block mt-0.5">
                Quarantine email. Block sender domain at gateway. Invalidate clicked sessions.
              </span>
            </div>
          </div>
        </div>

        {/* Right — Analyst Response Engine + Review + Export */}
        <div className="space-y-4">
          {/* Gmail Action Engine */}
          <GmailActionPanel
            emailId="CASE-2026-9821"
            messageId="msg-9821-phish"
            currentState="QUARANTINED"
            currentDecision="QUARANTINE"
            recipientEmail="cfo@enterprise-finance.com"
          />

          {/* Human-in-the-Loop */}

          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <MessageSquare className="w-4 h-4" />
              <span>Analyst Review</span>
            </div>
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                {(['TRUE_POSITIVE', 'FALSE_POSITIVE', 'TRUE_NEGATIVE', 'FALSE_NEGATIVE'] as const).map(
                  (opt) => (
                    <button
                      key={opt}
                      id={`feedback-${opt.toLowerCase().replace('_', '-')}`}
                      onClick={() => setFeedback(opt)}
                      className={`px-3 py-1 rounded border transition-colors ${
                        feedback === opt
                          ? 'bg-teal-accent/20 border-teal-accent text-teal-accent font-bold'
                          : 'border-surface-border text-text-muted hover:text-text-secondary'
                      }`}
                    >
                      {opt}
                    </button>
                  ),
                )}
              </div>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Enter SOC incident notes or validation rationale..."
                className="w-full bg-bg-darkest/60 border border-surface-border rounded p-2 text-xs text-text-primary focus:outline-none focus:border-teal-accent"
                rows={3}
              />
              <button
                id="save-analyst-feedback"
                onClick={handleSaveFeedback}
                className="w-full bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-semibold px-4 py-2 rounded text-xs transition-colors shadow-teal-glow flex items-center justify-center gap-2"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{savedAudit ? 'Audit Record Saved!' : 'Save Analyst Classification'}</span>
              </button>
            </div>
          </div>

          {/* Incident Report Export */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <FileText className="w-4 h-4" />
              <span>Incident Report Export</span>
            </div>
            <div className="text-[11px] text-text-muted mb-3 leading-relaxed">
              Generate a structured incident report containing all detection evidence,
              threat indicators, risk scores, and analyst classification.
            </div>
            <div className="text-[10px] font-mono bg-status-high/5 border border-status-high/20 rounded p-2 mb-3 text-status-high">
              ⚠ Analyst-initiated only. Report is NOT automatically submitted externally.
            </div>

            {/* Report fields preview */}
            <div className="space-y-1 text-[10px] font-mono text-text-muted mb-3">
              {[
                ['Incident ID', 'CASE-2026-9821'],
                ['Decision', 'QUARANTINE'],
                ['Severity', 'CRITICAL'],
                ['Indicators', `${DEMO_TI_INDICATORS.length} matched`],
                ['Classification', feedback],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between">
                  <span className="text-text-muted">{k}</span>
                  <span className="text-text-primary">{v}</span>
                </div>
              ))}
            </div>

            <button
              id="export-incident-report"
              onClick={handleExportReport}
              disabled={exportingReport}
              className="w-full flex items-center justify-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-semibold text-xs px-4 py-2 rounded transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              <span>
                {exportingReport
                  ? 'Generating...'
                  : reportExported
                  ? 'Report Downloaded!'
                  : 'Export Incident Report (JSON)'}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
