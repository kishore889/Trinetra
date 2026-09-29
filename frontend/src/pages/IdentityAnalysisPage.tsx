import React, { useState } from 'react';
import {
  UserCheck,
  ShieldAlert,
  AlertCircle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Mail,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Fingerprint,
  Lock,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Types (mirrors backend IdentityAnalysisResult)
// ---------------------------------------------------------------------------

interface AuthResult {
  spf: string;
  dkim: string;
  dmarc: string;
  spf_present: boolean;
  dkim_present: boolean;
  dmarc_present: boolean;
  all_pass: boolean;
  any_fail: boolean;
}

interface ParsedAddress {
  raw: string;
  display_name?: string;
  email?: string;
  local_part?: string;
  domain?: string;
  tld?: string;
  is_free_provider: boolean;
}

interface IdentitySignal {
  signal_type: string;
  weight: number;
  description: string;
  evidence_value?: unknown;
}

interface IdentityResult {
  identity_risk_score: number;
  authentication: AuthResult;
  from_address?: ParsedAddress;
  reply_to_address?: ParsedAddress;
  envelope_from?: ParsedAddress;
  signals: IdentitySignal[];
  evidence: Record<string, unknown>;
  known_sender: boolean;
  first_contact: boolean;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const AuthChip: React.FC<{ label: string; value: string }> = ({ label, value }) => {
  const isPass = value === 'pass';
  const isFail = ['fail', 'softfail', 'reject'].includes(value);
  const isNone = value === 'none' || value === 'unknown' || value === 'absent';

  return (
    <div className="bg-bg-darkest/60 border border-surface-border rounded-lg px-3 py-2 text-center">
      <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-sm font-bold font-mono uppercase ${isPass ? 'text-status-low' : isFail ? 'text-status-critical' : 'text-status-medium'}`}>
        {isPass && <CheckCircle2 className="w-3.5 h-3.5 inline mr-1" />}
        {isFail && <XCircle className="w-3.5 h-3.5 inline mr-1" />}
        {isNone && <HelpCircle className="w-3.5 h-3.5 inline mr-1" />}
        {value.toUpperCase()}
      </div>
    </div>
  );
};

const SignalRow: React.FC<{ signal: IdentitySignal }> = ({ signal }) => {
  const [expanded, setExpanded] = useState(false);
  const isHigh = signal.weight >= 0.80;
  const isMed = signal.weight >= 0.55 && signal.weight < 0.80;

  return (
    <div
      className={`bg-bg-darkest/40 border rounded p-2.5 cursor-pointer transition-colors ${
        isHigh ? 'border-status-critical/30' : isMed ? 'border-status-medium/30' : 'border-surface-border'
      }`}
      onClick={() => setExpanded((p) => !p)}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-start gap-2 flex-1">
          <AlertCircle className={`w-4 h-4 shrink-0 mt-0.5 ${isHigh ? 'text-status-critical' : isMed ? 'text-status-medium' : 'text-status-low'}`} />
          <div>
            <div className="text-[11px] font-mono font-semibold text-text-primary">{signal.signal_type}</div>
            <div className="text-[11px] text-text-secondary mt-0.5">{signal.description}</div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${isHigh ? 'bg-status-critical/10 text-status-critical' : isMed ? 'bg-status-medium/10 text-status-medium' : 'bg-status-low/10 text-status-low'}`}>
            W:{signal.weight.toFixed(2)}
          </span>
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-text-muted" /> : <ChevronDown className="w-3.5 h-3.5 text-text-muted" />}
        </div>
      </div>
      {expanded && signal.evidence_value !== null && signal.evidence_value !== undefined && (
        <pre className="mt-2 text-[10px] font-mono text-text-muted bg-bg-darkest/60 rounded p-2 overflow-auto max-h-24 border border-surface-border">
          {JSON.stringify(signal.evidence_value, null, 2)}
        </pre>
      )}
    </div>
  );
};

const RiskGauge: React.FC<{ score: number }> = ({ score }) => {
  const pct = Math.round(score * 100);
  const color =
    pct >= 70 ? '#FF5C67' : pct >= 45 ? '#FF9F43' : pct >= 20 ? '#F6D365' : '#38D39F';
  const label =
    pct >= 70 ? 'HIGH RISK' : pct >= 45 ? 'ELEVATED' : pct >= 20 ? 'LOW RISK' : 'SAFE';

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative w-20 h-20">
        <svg viewBox="0 0 80 80" className="w-full h-full -rotate-90">
          <circle cx="40" cy="40" r="32" fill="none" stroke="#0C2927" strokeWidth="10" />
          <circle
            cx="40"
            cy="40"
            r="32"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeDasharray={`${2 * Math.PI * 32}`}
            strokeDashoffset={`${2 * Math.PI * 32 * (1 - score)}`}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${color}80)`, transition: 'stroke-dashoffset 0.6s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-base font-extrabold font-mono" style={{ color }}>
            {pct}
          </span>
          <span className="text-[8px] text-text-muted font-mono">/100</span>
        </div>
      </div>
      <span className="text-[10px] font-mono font-semibold" style={{ color }}>
        {label}
      </span>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

// Demo result shown when no live analysis is performed
const DEMO_RESULT: IdentityResult = {
  identity_risk_score: 0.82,
  authentication: {
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    spf_present: true,
    dkim_present: false,
    dmarc_present: true,
    all_pass: false,
    any_fail: true,
  },
  from_address: {
    raw: '"Microsoft Security Alert" <alert@gmail.com>',
    display_name: 'Microsoft Security Alert',
    email: 'alert@gmail.com',
    local_part: 'alert',
    domain: 'gmail.com',
    tld: 'com',
    is_free_provider: true,
  },
  reply_to_address: {
    raw: 'attacker@malicious-harvest.xyz',
    email: 'attacker@malicious-harvest.xyz',
    domain: 'malicious-harvest.xyz',
    tld: 'xyz',
    is_free_provider: false,
  },
  envelope_from: undefined,
  signals: [
    {
      signal_type: 'FREE_PROVIDER_BRAND_IMPERSONATION',
      weight: 0.88,
      description: "Display name 'Microsoft Security Alert' impersonates 'microsoft' while using a free email provider (gmail.com).",
      evidence_value: { display_name: 'Microsoft Security Alert', brand_keyword: 'microsoft', provider_domain: 'gmail.com' },
    },
    {
      signal_type: 'REPLY_TO_DOMAIN_MISMATCH',
      weight: 0.82,
      description: "Reply-To domain 'malicious-harvest.xyz' differs from From domain 'gmail.com'. Victim replies will be redirected.",
      evidence_value: { from_domain: 'gmail.com', reply_to_domain: 'malicious-harvest.xyz' },
    },
    {
      signal_type: 'SPF_AUTHENTICATION_FAILURE',
      weight: 0.80,
      description: "SPF check returned 'fail'. The sending server is not authorized for this domain.",
      evidence_value: { spf_result: 'fail' },
    },
    {
      signal_type: 'DKIM_SIGNATURE_ABSENT',
      weight: 0.35,
      description: 'No DKIM signature present. Message authenticity cannot be cryptographically verified.',
      evidence_value: { dkim_result: 'absent' },
    },
    {
      signal_type: 'DMARC_POLICY_FAILURE',
      weight: 0.88,
      description: "DMARC policy check failed. Email does not align with the sender domain's published policy.",
      evidence_value: { dmarc_result: 'fail' },
    },
  ],
  evidence: {
    from_email: 'alert@gmail.com',
    from_domain: 'gmail.com',
    from_display_name: 'Microsoft Security Alert',
    reply_to_email: 'attacker@malicious-harvest.xyz',
    is_free_provider: true,
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    auth_all_pass: false,
    auth_any_fail: true,
    signals_count: 5,
    known_sender: false,
    first_contact: true,
  },
  known_sender: false,
  first_contact: true,
};

const BLANK_FORM = {
  from_header: '',
  reply_to_header: '',
  return_path_header: '',
  auth_results: '',
  received_spf: '',
};

export const IdentityAnalysisPage: React.FC = () => {
  const [form, setForm] = useState(BLANK_FORM);
  const [result, setResult] = useState<IdentityResult>(DEMO_RESULT);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDemo, setShowDemo] = useState(true);

  const handleAnalyze = async () => {
    if (!form.from_header.trim()) {
      setError('From header is required.');
      return;
    }
    setLoading(true);
    setError(null);
    setShowDemo(false);
    try {
      const headers: Record<string, string> = {};
      if (form.auth_results) headers['authentication-results'] = form.auth_results;
      if (form.received_spf) headers['received-spf'] = form.received_spf;

      const resp = await fetch('/api/v1/analyze/identity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          from_header: form.from_header,
          headers,
          reply_to_header: form.reply_to_header || null,
          return_path_header: form.return_path_header || null,
        }),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || `HTTP ${resp.status}`);
      }
      const data: IdentityResult = await resp.json();
      setResult(data);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(`Analysis failed: ${msg}. Showing demo result.`);
      setResult(DEMO_RESULT);
      setShowDemo(true);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setForm(BLANK_FORM);
    setResult(DEMO_RESULT);
    setError(null);
    setShowDemo(true);
  };

  const scoreColor =
    result.identity_risk_score >= 0.70
      ? 'text-status-critical'
      : result.identity_risk_score >= 0.45
      ? 'text-status-high'
      : result.identity_risk_score >= 0.20
      ? 'text-status-medium'
      : 'text-status-low';

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex items-center gap-3">
        <UserCheck className="w-6 h-6 text-teal-accent" />
        <div>
          <h1 className="text-xl font-bold text-text-primary">Identity & Spoofing Intelligence</h1>
          <p className="text-xs text-text-muted font-mono">Layer 3 — Sender Authentication & Display Name Deception Analysis</p>
        </div>
        {showDemo && (
          <span className="ml-auto text-[10px] font-mono bg-teal-accent/10 text-teal-accent border border-teal-accent/30 px-2 py-0.5 rounded">
            DEMO MODE
          </span>
        )}
      </div>

      {/* Analysis Input */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-5">
        <div className="flex items-center gap-2 text-xs font-semibold text-teal-accent uppercase tracking-wider mb-4">
          <Fingerprint className="w-4 h-4" />
          <span>Analyze Email Sender Identity</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="md:col-span-2">
            <label className="block text-text-muted font-mono mb-1">From Header <span className="text-status-critical">*</span></label>
            <input
              id="identity-from-header"
              type="text"
              value={form.from_header}
              onChange={(e) => setForm((p) => ({ ...p, from_header: e.target.value }))}
              placeholder='e.g. "Microsoft Security" <security@gmail.com>'
              className="w-full bg-bg-darkest/70 border border-surface-border rounded px-3 py-2 text-text-primary font-mono placeholder-text-muted focus:outline-none focus:border-teal-accent transition-colors"
            />
          </div>
          <div>
            <label className="block text-text-muted font-mono mb-1">Reply-To Header</label>
            <input
              id="identity-reply-to"
              type="text"
              value={form.reply_to_header}
              onChange={(e) => setForm((p) => ({ ...p, reply_to_header: e.target.value }))}
              placeholder="e.g. attacker@evil.xyz"
              className="w-full bg-bg-darkest/70 border border-surface-border rounded px-3 py-2 text-text-primary font-mono placeholder-text-muted focus:outline-none focus:border-teal-accent transition-colors"
            />
          </div>
          <div>
            <label className="block text-text-muted font-mono mb-1">Return-Path / Envelope-From</label>
            <input
              id="identity-return-path"
              type="text"
              value={form.return_path_header}
              onChange={(e) => setForm((p) => ({ ...p, return_path_header: e.target.value }))}
              placeholder="e.g. bounce@different-domain.com"
              className="w-full bg-bg-darkest/70 border border-surface-border rounded px-3 py-2 text-text-primary font-mono placeholder-text-muted focus:outline-none focus:border-teal-accent transition-colors"
            />
          </div>
          <div>
            <label className="block text-text-muted font-mono mb-1">Authentication-Results Header</label>
            <input
              id="identity-auth-results"
              type="text"
              value={form.auth_results}
              onChange={(e) => setForm((p) => ({ ...p, auth_results: e.target.value }))}
              placeholder="spf=fail dkim=fail dmarc=fail"
              className="w-full bg-bg-darkest/70 border border-surface-border rounded px-3 py-2 text-text-primary font-mono placeholder-text-muted focus:outline-none focus:border-teal-accent transition-colors"
            />
          </div>
          <div>
            <label className="block text-text-muted font-mono mb-1">Received-SPF Header</label>
            <input
              id="identity-received-spf"
              type="text"
              value={form.received_spf}
              onChange={(e) => setForm((p) => ({ ...p, received_spf: e.target.value }))}
              placeholder="spf=softfail ..."
              className="w-full bg-bg-darkest/70 border border-surface-border rounded px-3 py-2 text-text-primary font-mono placeholder-text-muted focus:outline-none focus:border-teal-accent transition-colors"
            />
          </div>
        </div>

        {error && (
          <div className="mt-3 text-xs text-status-critical font-mono bg-status-critical/5 border border-status-critical/20 rounded p-2">
            {error}
          </div>
        )}

        <div className="flex gap-3 mt-4">
          <button
            id="identity-analyze-btn"
            onClick={handleAnalyze}
            disabled={loading}
            className="flex items-center gap-2 bg-teal-accent hover:bg-teal-vibrant disabled:opacity-50 text-bg-darkest font-semibold text-xs px-5 py-2 rounded shadow-teal-glow transition-colors"
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
            {loading ? 'Analyzing...' : 'Analyze Identity'}
          </button>
          <button
            onClick={handleReset}
            className="text-xs text-text-muted hover:text-text-secondary border border-surface-border rounded px-4 py-2 transition-colors"
          >
            Reset / Load Demo
          </button>
        </div>
      </div>

      {/* Results */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* Risk Score + Address Breakdown */}
        <div className="space-y-4">
          {/* Score Gauge */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4 flex flex-col items-center gap-3">
            <div className="text-[10px] text-text-muted font-mono uppercase tracking-wider">Identity Risk Score</div>
            <RiskGauge score={result.identity_risk_score} />
            <div className="w-full border-t border-surface-border pt-3 grid grid-cols-2 gap-2 text-xs font-mono">
              <div>
                <div className="text-text-muted text-[10px]">Known Sender</div>
                <div className={result.known_sender ? 'text-status-low' : 'text-status-medium'}>
                  {result.known_sender ? '✓ Yes' : '✗ No'}
                </div>
              </div>
              <div>
                <div className="text-text-muted text-[10px]">First Contact</div>
                <div className={result.first_contact ? 'text-status-high' : 'text-status-low'}>
                  {result.first_contact ? '⚠ Yes' : '✓ No'}
                </div>
              </div>
              <div>
                <div className="text-text-muted text-[10px]">Signals Detected</div>
                <div className={scoreColor}>{result.signals.length}</div>
              </div>
              <div>
                <div className="text-text-muted text-[10px]">Auth Any Fail</div>
                <div className={result.authentication.any_fail ? 'text-status-critical' : 'text-status-low'}>
                  {result.authentication.any_fail ? '✗ YES' : '✓ No'}
                </div>
              </div>
            </div>
          </div>

          {/* Email Address Parsing */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-teal-accent uppercase tracking-wider mb-3">
              <Mail className="w-4 h-4" />
              <span>Address Parsing</span>
            </div>
            <div className="space-y-2 text-[11px] font-mono">
              {result.from_address && (
                <div className="bg-bg-darkest/50 border border-surface-border rounded p-2">
                  <div className="text-teal-accent/70 text-[9px] uppercase mb-1">From (P2)</div>
                  {result.from_address.display_name && (
                    <div><span className="text-text-muted">Display: </span><span className="text-text-primary">{result.from_address.display_name}</span></div>
                  )}
                  <div><span className="text-text-muted">Email: </span><span className="text-text-primary">{result.from_address.email}</span></div>
                  <div><span className="text-text-muted">Domain: </span><span className="text-text-primary">{result.from_address.domain}</span></div>
                  {result.from_address.is_free_provider && (
                    <div className="text-status-high mt-0.5">⚠ Free Email Provider</div>
                  )}
                </div>
              )}
              {result.reply_to_address && (
                <div className="bg-bg-darkest/50 border border-status-high/20 rounded p-2">
                  <div className="text-status-high text-[9px] uppercase mb-1">Reply-To ⚠</div>
                  <div><span className="text-text-muted">Email: </span><span className="text-text-primary">{result.reply_to_address.email}</span></div>
                  <div><span className="text-text-muted">Domain: </span><span className="text-text-primary">{result.reply_to_address.domain}</span></div>
                </div>
              )}
              {result.envelope_from && (
                <div className="bg-bg-darkest/50 border border-surface-border rounded p-2">
                  <div className="text-text-muted text-[9px] uppercase mb-1">Return-Path (P1)</div>
                  <div><span className="text-text-muted">Email: </span><span className="text-text-primary">{result.envelope_from.email}</span></div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Authentication + Signals */}
        <div className="lg:col-span-2 space-y-4">
          {/* Authentication Results */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-teal-accent uppercase tracking-wider mb-3">
              <Lock className="w-4 h-4" />
              <span>Email Authentication (SPF / DKIM / DMARC)</span>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <AuthChip label="SPF" value={result.authentication.spf} />
              <AuthChip label="DKIM" value={result.authentication.dkim} />
              <AuthChip label="DMARC" value={result.authentication.dmarc} />
            </div>
            <div className="mt-3 text-[11px] font-mono">
              {result.authentication.all_pass ? (
                <span className="text-status-low flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> All authentication checks pass — sender identity verified
                </span>
              ) : result.authentication.any_fail ? (
                <span className="text-status-critical flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" /> One or more authentication checks failed — sender identity cannot be verified
                </span>
              ) : (
                <span className="text-text-muted flex items-center gap-1">
                  <HelpCircle className="w-3.5 h-3.5" /> Authentication results unavailable or absent from headers
                </span>
              )}
            </div>
          </div>

          {/* Detected Signals */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-teal-accent uppercase tracking-wider">
                <ShieldAlert className="w-4 h-4" />
                <span>Detected Signals</span>
              </div>
              <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
                result.signals.length === 0
                  ? 'text-status-low border-status-low/30 bg-status-low/5'
                  : 'text-status-critical border-status-critical/30 bg-status-critical/5'
              }`}>
                {result.signals.length === 0 ? 'No signals — CLEAN' : `${result.signals.length} signal${result.signals.length > 1 ? 's' : ''} detected`}
              </span>
            </div>

            {result.signals.length === 0 ? (
              <div className="text-center py-6 text-text-muted text-xs font-mono">
                <CheckCircle2 className="w-8 h-8 text-status-low mx-auto mb-2" />
                No spoofing or deception signals detected.
              </div>
            ) : (
              <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
                {result.signals
                  .sort((a, b) => b.weight - a.weight)
                  .map((sig, i) => (
                    <SignalRow key={i} signal={sig} />
                  ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
