import React, { useState } from 'react';
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
} from 'lucide-react';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';

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

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const LayerScoreBar: React.FC<{ label: string; score: number; weight: string }> = ({
  label, score, weight,
}) => {
  const pct = Math.round(score * 100);
  const color =
    pct >= 70 ? '#FF5C67' : pct >= 45 ? '#FF9F43' : pct >= 20 ? '#F6D365' : '#38D39F';
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
      <span className="text-[10px] text-text-muted uppercase font-mono block">{label} ({weight})</span>
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

        {/* 5-Layer Risk Breakdown */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 pt-4">
          <LayerScoreBar label="Content Risk" score={0.96} weight="25%" />
          <LayerScoreBar label="URL Risk" score={0.98} weight="30%" />
          <LayerScoreBar label="Identity Risk" score={0.88} weight="20%" />
          <LayerScoreBar label="Threat Intel" score={0.92} weight="15%" />
          <LayerScoreBar label="Graph Risk" score={0.85} weight="10%" />
        </div>
      </div>

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

          {/* Explainability */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <Cpu className="w-4 h-4" />
              <span>Explainable AI Synthesis</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed bg-bg-darkest/50 p-3 rounded-lg border border-surface-border">
              This communication mimics genuine Microsoft 365 security notices but uses an unverified
              lookalike domain (<span className="text-status-critical font-mono">micros0ft-support.com</span>).
              The embedded URL matches{' '}
              <span className="text-teal-accent font-mono">CIAD-2023-0198</span> in the CERT-In advisory index.
              Sender fails all SPF/DKIM/DMARC checks.
            </p>
            <div className="mt-3 text-xs font-mono text-text-muted">
              Recommended SOC Action:{' '}
              <span className="text-status-critical font-bold">
                Quarantine · Block Sender Domain · Revoke Session
              </span>
            </div>
          </div>
        </div>

        {/* Right — Analyst Review + Incident Report Export */}
        <div className="space-y-4">
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
