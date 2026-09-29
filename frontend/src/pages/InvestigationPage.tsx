import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Globe, 
  UserCheck, 
  FileText, 
  Share2, 
  Cpu, 
  AlertCircle, 
  CheckCircle2, 
  ExternalLink,
  MessageSquare,
  Lock
} from 'lucide-react';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';

export const InvestigationPage: React.FC = () => {
  const [feedback, setFeedback] = useState<'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'TRUE_NEGATIVE' | 'FALSE_NEGATIVE'>('TRUE_POSITIVE');
  const [comment, setComment] = useState('');
  const [savedAudit, setSavedAudit] = useState(false);

  const handleSaveFeedback = () => {
    setSavedAudit(true);
    setTimeout(() => setSavedAudit(false), 3000);
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

          {/* Master Risk Score Gauge */}
          <div className="flex items-center gap-4 bg-bg-darkest/80 border border-status-critical/30 rounded-xl px-5 py-3 shrink-0">
            <div>
              <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider">Multi-Signal Score</div>
              <div className="text-3xl font-extrabold font-mono text-status-critical leading-tight">94 <span className="text-sm font-normal text-text-muted">/100</span></div>
            </div>
            <div className="border-l border-surface-border pl-3 text-[11px] font-mono space-y-0.5">
              <div className="text-status-critical font-bold">VERDICT: QUARANTINE</div>
              <div className="text-text-secondary">Confidence: 98.4%</div>
            </div>
          </div>
        </div>

        {/* 5-Layer Risk Breakdown */}
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 pt-4">
          <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
            <span className="text-[10px] text-text-muted uppercase font-mono block">Content Risk (25%)</span>
            <span className="text-base font-bold font-mono text-status-critical">0.96</span>
          </div>
          <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
            <span className="text-[10px] text-text-muted uppercase font-mono block">URL Risk (30%)</span>
            <span className="text-base font-bold font-mono text-status-critical">0.98</span>
          </div>
          <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
            <span className="text-[10px] text-text-muted uppercase font-mono block">Identity Risk (20%)</span>
            <span className="text-base font-bold font-mono text-status-high">0.88</span>
          </div>
          <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
            <span className="text-[10px] text-text-muted uppercase font-mono block">Threat Intel (15%)</span>
            <span className="text-base font-bold font-mono text-status-critical">0.92</span>
          </div>
          <div className="bg-surface-card border border-surface-border rounded-lg p-2.5">
            <span className="text-[10px] text-text-muted uppercase font-mono block">Graph Risk (10%)</span>
            <span className="text-base font-bold font-mono text-status-high">0.85</span>
          </div>
        </div>
      </div>

      {/* Intelligence Workspaces */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Layer Intelligence Details */}
        <div className="space-y-4">
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <Globe className="w-4 h-4" />
              <span>URL & Domain Intelligence</span>
            </div>
            <ul className="space-y-2 text-xs text-text-secondary">
              <li className="flex items-start gap-2 bg-bg-darkest/40 p-2 rounded border border-surface-border">
                <AlertCircle className="w-4 h-4 text-status-critical shrink-0 mt-0.5" />
                <div>
                  <span className="font-mono text-text-primary block text-[11px]">https://auth-portal-micros0ft.online/login</span>
                  <span className="text-text-muted text-[11px]">Typosquatting registered 3 days ago. Destination resolves to known credential harvesting endpoint.</span>
                </div>
              </li>
            </ul>
          </div>

          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <UserCheck className="w-4 h-4" />
              <span>Identity & Spoofing Intelligence</span>
            </div>
            <div className="grid grid-cols-3 gap-2 font-mono text-xs">
              <div className="bg-bg-darkest/50 p-2 rounded border border-surface-border">
                <div className="text-[10px] text-text-muted">SPF</div>
                <div className="text-status-critical font-bold">FAIL</div>
              </div>
              <div className="bg-bg-darkest/50 p-2 rounded border border-surface-border">
                <div className="text-[10px] text-text-muted">DKIM</div>
                <div className="text-status-high font-bold">NONE</div>
              </div>
              <div className="bg-bg-darkest/50 p-2 rounded border border-surface-border">
                <div className="text-[10px] text-text-muted">DMARC</div>
                <div className="text-status-critical font-bold">REJECT</div>
              </div>
            </div>
          </div>
        </div>

        {/* Explainability & SOC Co-Pilot Summary */}
        <div className="space-y-4">
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <Cpu className="w-4 h-4" />
              <span>Explainable AI Synthesis</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed bg-bg-darkest/50 p-3 rounded-lg border border-surface-border">
              This communication mimics genuine Microsoft 365 security notices but uses an unverified lookalike domain (<span className="text-status-critical font-mono">micros0ft-support.com</span>). The embedded URL directs users to an external credential-harvesting server configured to capture session tokens. Sender fails SPF alignment and DMARC enforcement.
            </p>
            <div className="mt-3 text-xs font-mono text-text-muted">
              Recommended SOC Action: <span className="text-status-critical font-bold">Enforce Domain Blacklist & Revoke User Session</span>
            </div>
          </div>

          {/* Human-in-the-Loop Analyst Verification */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-teal-accent font-semibold text-xs tracking-wider uppercase mb-3">
              <MessageSquare className="w-4 h-4" />
              <span>Human-in-the-Loop Analyst Review</span>
            </div>
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                {(['TRUE_POSITIVE', 'FALSE_POSITIVE', 'TRUE_NEGATIVE', 'FALSE_NEGATIVE'] as const).map((opt) => (
                  <button
                    key={opt}
                    onClick={() => setFeedback(opt)}
                    className={`px-3 py-1 rounded border transition-colors ${
                      feedback === opt 
                        ? 'bg-teal-accent/20 border-teal-accent text-teal-accent font-bold' 
                        : 'border-surface-border text-text-muted hover:text-text-secondary'
                    }`}
                  >
                    {opt}
                  </button>
                ))}
              </div>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Enter SOC incident notes or validation rationale..."
                className="w-full bg-bg-darkest/60 border border-surface-border rounded p-2 text-xs text-text-primary focus:outline-none focus:border-teal-accent"
                rows={2}
              />
              <button
                onClick={handleSaveFeedback}
                className="bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-semibold px-4 py-1.5 rounded text-xs transition-colors shadow-teal-glow flex items-center gap-2"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>{savedAudit ? 'Audit Record Saved!' : 'Save Analyst Classification'}</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
