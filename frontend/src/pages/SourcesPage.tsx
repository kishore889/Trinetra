import React, { useState, useEffect, useCallback } from 'react';
import {
  RefreshCw,
  Database,
  Globe,
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  Wifi,
  WifiOff,
  Info,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

interface ProviderHealth {
  name: string;
  provider_type: string;
  is_available: boolean;
  api_key_configured: boolean;
  base_url: string;
  notes: string;
  last_checked?: string;
}

interface CERTInAdvisory {
  advisory_id: string;
  title: string;
  published: string;
  severity: string;
  affected_domains?: string[];
  affected_urls?: string[];
  description?: string;
}

interface CERTInData {
  provider: string;
  provider_type: string;
  note: string;
  advisory_count: number;
  advisories: CERTInAdvisory[];
}

const PROVIDER_ICONS: Record<string, React.FC<any>> = {
  LOCAL: Database,
  CERTIN: Shield,
  GOOGLE_SAFE_BROWSING: Globe,
  VIRUSTOTAL: Globe,
};

const PROVIDER_COLORS: Record<string, string> = {
  LOCAL: 'text-teal-accent border-teal-accent/40 bg-teal-accent/10',
  CERTIN: 'text-blue-400 border-blue-400/40 bg-blue-400/10',
  GOOGLE_SAFE_BROWSING: 'text-yellow-400 border-yellow-400/40 bg-yellow-400/10',
  VIRUSTOTAL: 'text-purple-400 border-purple-400/40 bg-purple-400/10',
};

const ProviderCard: React.FC<{ provider: ProviderHealth }> = ({ provider }) => {
  const [expanded, setExpanded] = useState(false);
  const Icon = PROVIDER_ICONS[provider.provider_type] || Database;
  const colorClass = PROVIDER_COLORS[provider.provider_type] || 'text-text-secondary border-surface-border bg-surface-card';

  return (
    <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden">
      <div
        className="flex items-start justify-between p-5 cursor-pointer hover:bg-surface-hover/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start gap-4">
          <div className={`w-10 h-10 rounded-lg border flex items-center justify-center shrink-0 ${colorClass}`}>
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-bold text-text-primary font-mono text-sm">{provider.name}</h3>
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${colorClass}`}>
                {provider.provider_type}
              </span>
            </div>
            <p className="text-xs text-text-muted font-mono truncate max-w-md">{provider.notes}</p>
          </div>
        </div>
        <div className="flex items-center gap-3 ml-4 shrink-0">
          {provider.is_available ? (
            <div className="flex items-center gap-1.5 text-status-low">
              <CheckCircle2 className="w-4 h-4" />
              <span className="text-xs font-mono font-bold">AVAILABLE</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-text-muted">
              <XCircle className="w-4 h-4" />
              <span className="text-xs font-mono font-bold">UNAVAILABLE</span>
            </div>
          )}
          {expanded ? <ChevronUp className="w-4 h-4 text-text-muted" /> : <ChevronDown className="w-4 h-4 text-text-muted" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-surface-border bg-bg-darkest/50 p-5 space-y-3 font-mono text-xs">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-text-muted uppercase text-[10px] tracking-wider">API Key Configured</span>
              <div className="flex items-center gap-1.5 mt-1">
                {provider.api_key_configured ? (
                  <><CheckCircle2 className="w-3.5 h-3.5 text-status-low" /><span className="text-status-low font-bold">YES</span></>
                ) : (
                  <><XCircle className="w-3.5 h-3.5 text-text-muted" /><span className="text-text-muted">NOT CONFIGURED (Optional)</span></>
                )}
              </div>
            </div>
            <div>
              <span className="text-text-muted uppercase text-[10px] tracking-wider">Base URL</span>
              <p className="text-text-secondary mt-1 truncate">{provider.base_url || 'N/A (Local Source)'}</p>
            </div>
          </div>
          <div>
            <span className="text-text-muted uppercase text-[10px] tracking-wider">Details</span>
            <p className="text-text-secondary mt-1 leading-relaxed">{provider.notes}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export const SourcesPage: React.FC = () => {
  const [providers, setProviders] = useState<ProviderHealth[]>([]);
  const [certinData, setCertinData] = useState<CERTInData | null>(null);
  const [loading, setLoading] = useState(true);
  const [certinLoading, setCertinLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<string>('');
  const [expandedAdvisory, setExpandedAdvisory] = useState<string | null>(null);

  const fetchProviders = useCallback(async () => {
    try {
      setError(null);
      const resp = await fetch('/api/v1/threat-intel/providers');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setProviders(data);
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err.message || 'Failed to fetch provider health');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchCERTIn = useCallback(async () => {
    try {
      setCertinLoading(true);
      const resp = await fetch('/api/v1/threat-intel/certin');
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setCertinData(data);
    } catch {
      // Non-critical — CERT-In data is advisory
    } finally {
      setCertinLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProviders();
    fetchCERTIn();
    const interval = setInterval(fetchProviders, 30000);
    return () => clearInterval(interval);
  }, [fetchProviders, fetchCERTIn]);

  const availableCount = providers.filter((p) => p.is_available).length;
  const configuredCount = providers.filter((p) => p.api_key_configured || p.provider_type === 'LOCAL' || p.provider_type === 'CERTIN').length;

  const severityColor = (s: string) => {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return 'text-status-critical bg-status-critical/10 border-status-critical/30';
      case 'HIGH': return 'text-status-high bg-status-high/10 border-status-high/30';
      case 'MEDIUM': return 'text-status-medium bg-status-medium/10 border-status-medium/30';
      default: return 'text-status-low bg-status-low/10 border-status-low/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Database className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Threat Intelligence Sources
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Provider health, availability, configuration, and CERT-In advisory intelligence.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefreshed && (
            <span className="text-xs text-text-muted font-mono flex items-center gap-1">
              <Clock className="w-3 h-3" /> {lastRefreshed}
            </span>
          )}
          <button
            onClick={() => { setLoading(true); fetchProviders(); fetchCERTIn(); }}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh Status</span>
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Providers', value: providers.length, color: 'text-teal-accent', icon: Database },
          { label: 'Available Now', value: availableCount, color: 'text-status-low', icon: Wifi },
          { label: 'Configured', value: configuredCount, color: 'text-blue-400', icon: CheckCircle2 },
          { label: 'CERT-In Advisories', value: certinData?.advisory_count ?? 0, color: 'text-yellow-400', icon: Shield },
        ].map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="bg-surface-default border border-surface-border rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-4 h-4 ${stat.color}`} />
                <span className="text-[10px] font-mono text-text-muted uppercase tracking-wider">{stat.label}</span>
              </div>
              <div className={`text-3xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
            </div>
          );
        })}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 flex items-center gap-2 text-xs font-mono text-status-critical">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
          <button onClick={fetchProviders} className="ml-auto underline font-bold">Retry</button>
        </div>
      )}

      {/* CERT-In Advisory Note */}
      <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 flex items-start gap-3 text-xs font-mono">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-blue-300/80 leading-relaxed">
          <span className="font-bold text-blue-400">CERT-In Intelligence Note:</span>{' '}
          CERT-In (Indian Computer Emergency Response Team) is treated as an advisory evidence/intelligence source.
          TRINETRA does NOT claim CERT-In provides a real-time phishing classification API.
          Indicators are derived from published advisories and maintained locally.
        </div>
      </div>

      {/* Provider Health Cards */}
      <div>
        <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-3">
          Provider Health &amp; Configuration
        </h2>
        {loading ? (
          <div className="bg-surface-default border border-surface-border rounded-xl p-8 text-center flex items-center justify-center gap-2 text-teal-accent font-mono text-sm">
            <Loader2 className="w-5 h-5 animate-spin" />
            <span>Loading provider status...</span>
          </div>
        ) : (
          <div className="space-y-3">
            {providers.map((p) => (
              <ProviderCard key={p.name} provider={p} />
            ))}
            {providers.length === 0 && (
              <div className="bg-surface-default border border-surface-border rounded-xl p-8 text-center text-text-muted font-mono text-sm">
                No providers returned by backend.
              </div>
            )}
          </div>
        )}
      </div>

      {/* CERT-In Advisories */}
      {certinData && (
        <div>
          <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider mb-3">
            CERT-In Advisory Index ({certinData.advisory_count} advisories)
          </h2>
          <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden">
            {certinLoading ? (
              <div className="p-8 flex items-center justify-center gap-2 text-teal-accent font-mono text-sm">
                <Loader2 className="w-5 h-5 animate-spin" /><span>Loading advisories...</span>
              </div>
            ) : (
              <div className="divide-y divide-surface-border">
                {certinData.advisories.map((adv) => (
                  <div key={adv.advisory_id} className="hover:bg-surface-hover/50 transition-colors">
                    <div
                      className="flex items-start justify-between p-4 cursor-pointer"
                      onClick={() => setExpandedAdvisory(expandedAdvisory === adv.advisory_id ? null : adv.advisory_id)}
                    >
                      <div className="flex items-start gap-3">
                        <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                        <div>
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="font-mono font-bold text-sm text-text-primary">{adv.title}</span>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${severityColor(adv.severity)}`}>
                              {adv.severity}
                            </span>
                          </div>
                          <span className="text-xs text-text-muted font-mono">{adv.advisory_id} · Published: {adv.published}</span>
                        </div>
                      </div>
                      {expandedAdvisory === adv.advisory_id
                        ? <ChevronUp className="w-4 h-4 text-text-muted shrink-0" />
                        : <ChevronDown className="w-4 h-4 text-text-muted shrink-0" />}
                    </div>
                    {expandedAdvisory === adv.advisory_id && (
                      <div className="px-4 pb-4 bg-bg-darkest/40 space-y-2 font-mono text-xs">
                        {adv.description && (
                          <p className="text-text-secondary leading-relaxed">{adv.description}</p>
                        )}
                        {adv.affected_domains && adv.affected_domains.length > 0 && (
                          <div>
                            <span className="text-text-muted uppercase text-[10px] tracking-wider">Affected Domains</span>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {adv.affected_domains.map((d) => (
                                <span key={d} className="text-status-critical bg-status-critical/10 border border-status-critical/20 px-2 py-0.5 rounded text-[11px]">{d}</span>
                              ))}
                            </div>
                          </div>
                        )}
                        {adv.affected_urls && adv.affected_urls.length > 0 && (
                          <div>
                            <span className="text-text-muted uppercase text-[10px] tracking-wider">Affected URLs</span>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {adv.affected_urls.map((u) => (
                                <span key={u} className="text-status-high bg-status-high/10 border border-status-high/20 px-2 py-0.5 rounded text-[11px] break-all">{u}</span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
                {certinData.advisories.length === 0 && (
                  <div className="p-8 text-center text-text-muted font-mono text-sm">
                    No CERT-In advisories in local index.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
