import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Plus,
  RefreshCw,
  ExternalLink,
  Globe,
  Database,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Loader2,
  Tag,
  Shield,
  Layers,
} from 'lucide-react';
import { ThreatBadge } from '../components/UIElements';

interface ThreatProvider {
  name: string;
  type: string;
  available: boolean;
  notes?: string;
  source_metadata?: Record<string, any>;
}

interface CERTInAdvisory {
  advisory_id: string;
  title: string;
  published_date: string;
  target_sectors: string[];
  severity: string;
  summary: string;
  indicators_count: number;
}

interface IndicatorMatch {
  indicator: string;
  indicator_type: string;
  source: string;
  advisory_id?: string;
  severity: string;
  confidence: number;
  description?: string;
}

export const ThreatRegistryPage: React.FC = () => {
  const [providers, setProviders] = useState<ThreatProvider[]>([]);
  const [advisories, setAdvisories] = useState<CERTInAdvisory[]>([]);
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupType, setLookupType] = useState('DOMAIN');
  const [lookupResults, setLookupResults] = useState<IndicatorMatch[] | null>(null);
  const [isSearching, setIsSearching] = useState(false);
  const [loading, setLoading] = useState(true);

  // New indicator form state
  const [showAddModal, setShowAddModal] = useState(false);
  const [newVal, setNewVal] = useState('');
  const [newType, setNewType] = useState('domain');
  const [newSev, setNewSev] = useState('HIGH');
  const [newDesc, setNewDesc] = useState('');
  const [addSuccess, setAddSuccess] = useState<string | null>(null);

  useEffect(() => {
    fetchThreatIntelData();
  }, []);

  const fetchThreatIntelData = async () => {
    setLoading(true);
    try {
      const pResp = await fetch('/api/v1/threat-intel/providers');
      if (pResp.ok) setProviders(await pResp.json());

      const cResp = await fetch('/api/v1/threat-intel/certin/advisories');
      if (cResp.ok) setAdvisories(await cResp.json());
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;

    setIsSearching(true);
    try {
      const resp = await fetch('/api/v1/threat-intel/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator_type: lookupType.toLowerCase(),
          indicator_value: lookupQuery.trim(),
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        setLookupResults(data.matches || []);
      } else {
        setLookupResults([]);
      }
    } catch {
      setLookupResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  const handleAddLocalIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newVal.trim()) return;

    try {
      const resp = await fetch('/api/v1/threat-intel/local/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator_type: newType,
          indicator_value: newVal.trim(),
          source: 'Local SOC Analyst Override',
          severity: newSev,
          description: newDesc || 'Analyst manual threat indicator entry',
        }),
      });

      if (resp.ok) {
        setAddSuccess(`Successfully added threat indicator ${newVal}!`);
        setNewVal('');
        setNewDesc('');
        setShowAddModal(false);
        fetchThreatIntelData();
      }
    } catch {
      alert('Failed to add threat indicator.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Threat Intelligence Provider Architecture & Registry
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Extensible multi-provider threat registry: CERT-In Advisories, Google Safe Browsing, VirusTotal, and Local DB.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-mono text-xs font-bold px-3.5 py-2 rounded transition-all shadow-teal-glow"
          >
            <Plus className="w-4 h-4" />
            <span>Add Local Indicator</span>
          </button>

          <button
            onClick={fetchThreatIntelData}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh Feeds</span>
          </button>
        </div>
      </div>

      {addSuccess && (
        <div className="p-3 bg-teal-accent/10 border border-teal-accent text-teal-accent text-xs font-mono rounded flex items-center justify-between">
          <span>{addSuccess}</span>
          <button onClick={() => setAddSuccess(null)}>✕</button>
        </div>
      )}

      {/* Provider Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        {providers.map((p) => (
          <div key={p.name} className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-text-primary">{p.name}</span>
              <span className={`w-2.5 h-2.5 rounded-full ${p.available ? 'bg-status-low shadow-[0_0_8px_#38D39F]' : 'bg-status-medium'}`} />
            </div>
            <div className="text-[10px] font-mono text-teal-accent uppercase">{p.type}</div>
            <p className="text-[11px] text-text-muted leading-tight">{p.notes || 'Integrated intelligence provider'}</p>
          </div>
        ))}
      </div>

      {/* Interactive Indicator Lookup Tool */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
        <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider">
          Multi-Provider Indicator Lookup Tool
        </h2>

        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row items-center gap-3">
          <select
            value={lookupType}
            onChange={(e) => setLookupType(e.target.value)}
            className="bg-bg-darkest border border-surface-border rounded p-2 text-xs font-mono text-text-primary focus:outline-none focus:border-teal-accent w-full sm:w-40"
          >
            <option value="DOMAIN">DOMAIN</option>
            <option value="URL">URL</option>
            <option value="IP">IP</option>
            <option value="SENDER">SENDER</option>
          </select>

          <input
            type="text"
            value={lookupQuery}
            onChange={(e) => setLookupQuery(e.target.value)}
            placeholder="Enter domain, URL, IP, or sender (e.g. system-update-security.info)..."
            className="flex-1 bg-bg-darkest border border-surface-border rounded p-2 text-xs font-mono text-text-primary focus:outline-none focus:border-teal-accent w-full"
          />

          <button
            type="submit"
            disabled={isSearching}
            className="w-full sm:w-auto px-5 py-2 bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-mono text-xs font-bold rounded flex items-center justify-center gap-2 shadow-teal-glow"
          >
            {isSearching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>Lookup IOC</span>
          </button>
        </form>

        {/* Results */}
        {lookupResults !== null && (
          <div className="pt-3 border-t border-surface-border space-y-2">
            <h3 className="text-[11px] font-mono text-text-muted uppercase">
              Lookup Results ({lookupResults.length} match(es) found)
            </h3>

            {lookupResults.map((m, idx) => (
              <div key={idx} className="bg-bg-darkest border border-surface-border rounded-lg p-3 space-y-1 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-teal-accent">{m.indicator}</span>
                  <ThreatBadge severity={m.severity} />
                </div>
                <div className="text-[11px] text-text-secondary">
                  Source: <span className="text-text-primary font-bold">{m.source}</span> | Type: {m.indicator_type} | Confidence: {Math.round(m.confidence * 100)}%
                </div>
                {m.description && <div className="text-[10px] text-text-muted italic">{m.description}</div>}
              </div>
            ))}

            {lookupResults.length === 0 && (
              <div className="p-3 bg-bg-darkest text-center text-xs font-mono text-text-muted rounded border border-surface-border">
                No threat indicators matched across active providers.
              </div>
            )}
          </div>
        )}
      </div>

      {/* CERT-In Advisories Table */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider">
              CERT-In Official Security Advisories
            </h2>
            <p className="text-[11px] text-text-muted">Extracted advisory threat signals integrated into risk engine</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-bg-darkest text-text-muted uppercase text-[10px] border-b border-surface-border">
              <tr>
                <th className="p-2.5">Advisory ID</th>
                <th className="p-2.5">Title</th>
                <th className="p-2.5">Published Date</th>
                <th className="p-2.5">Target Sectors</th>
                <th className="p-2.5">Severity</th>
                <th className="p-2.5">Indicators</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {advisories.map((adv) => (
                <tr key={adv.advisory_id} className="hover:bg-surface-hover/50 transition-colors">
                  <td className="p-2.5 font-bold text-teal-accent">{adv.advisory_id}</td>
                  <td className="p-2.5 text-text-primary max-w-xs truncate">{adv.title}</td>
                  <td className="p-2.5 text-text-muted">{adv.published_date}</td>
                  <td className="p-2.5 text-text-secondary">
                    {(adv.target_sectors || []).join(', ') || 'Enterprise'}
                  </td>
                  <td className="p-2.5">
                    <ThreatBadge severity={adv.severity} />
                  </td>
                  <td className="p-2.5 text-teal-vibrant font-bold">{adv.indicators_count} IOCs</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Local Indicator Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form onSubmit={handleAddLocalIndicator} className="bg-bg-dark border border-teal-accent/40 rounded-xl p-5 max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-teal-accent font-mono uppercase tracking-wider">
              Add Local Threat Indicator
            </h3>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Indicator Type</label>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value)}
                  className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
                >
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="ip">IP Address</option>
                  <option value="sender">Sender Email</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Indicator Value</label>
                <input
                  type="text"
                  value={newVal}
                  onChange={(e) => setNewVal(e.target.value)}
                  placeholder="e.g. maldomain-phish.xyz"
                  required
                  className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
                />
              </div>

              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Severity</label>
                <select
                  value={newSev}
                  onChange={(e) => setNewSev(e.target.value)}
                  className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Description</label>
                <input
                  type="text"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Reasoning for adding this IOC..."
                  className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-xs font-mono text-text-muted border border-surface-border rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 text-xs font-mono font-bold bg-teal-accent hover:bg-teal-vibrant text-bg-darkest rounded shadow-teal-glow"
              >
                Save Indicator
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
