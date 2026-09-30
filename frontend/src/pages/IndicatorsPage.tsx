import React, { useState, useEffect, useCallback } from 'react';
import {
  Target,
  Plus,
  Trash2,
  RefreshCw,
  Search,
  Filter,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Clock,
  X,
  ChevronDown,
} from 'lucide-react';

interface Indicator {
  id: string;
  indicator_type: string;
  indicator_value: string;
  source: string;
  severity: string;
  confidence: number;
  description: string | null;
  first_seen: string | null;
  last_seen: string | null;
  is_active: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-status-critical bg-status-critical/15 border-status-critical/40',
  HIGH:     'text-status-high    bg-status-high/15    border-status-high/40',
  MEDIUM:   'text-status-medium  bg-status-medium/15  border-status-medium/40',
  LOW:      'text-status-low     bg-status-low/15     border-status-low/40',
};

const TYPE_COLORS: Record<string, string> = {
  DOMAIN: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  URL:    'text-purple-400 bg-purple-400/10 border-purple-400/30',
  IP:     'text-orange-400 bg-orange-400/10 border-orange-400/30',
  EMAIL:  'text-teal-accent bg-teal-accent/10 border-teal-accent/30',
  HASH:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  SENDER: 'text-pink-400 bg-pink-400/10 border-pink-400/30',
};

interface AddIndicatorForm {
  indicator_type: string;
  indicator_value: string;
  severity: string;
  confidence: number;
  source: string;
  description: string;
}

const defaultForm: AddIndicatorForm = {
  indicator_type: 'DOMAIN',
  indicator_value: '',
  severity: 'MEDIUM',
  confidence: 1.0,
  source: 'MANUAL',
  description: '',
};

export const IndicatorsPage: React.FC = () => {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [form, setForm] = useState<AddIndicatorForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState('');
  const [showActiveOnly, setShowActiveOnly] = useState(true);

  const fetchIndicators = useCallback(async () => {
    try {
      setError(null);
      const resp = await fetch(`/api/v1/threat-intel/indicators?active_only=${showActiveOnly}&limit=200`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      setIndicators(data);
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err: any) {
      setError(err.message || 'Failed to load indicators');
    } finally {
      setLoading(false);
    }
  }, [showActiveOnly]);

  useEffect(() => {
    fetchIndicators();
  }, [fetchIndicators]);

  const handleAdd = async () => {
    if (!form.indicator_value.trim()) {
      setSubmitError('Indicator value is required.');
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      const resp = await fetch('/api/v1/threat-intel/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!resp.ok) {
        const errData = await resp.json();
        throw new Error(errData.detail || `HTTP ${resp.status}`);
      }
      const newInd: Indicator = await resp.json();
      setIndicators((prev) => [newInd, ...prev]);
      setShowAddModal(false);
      setForm(defaultForm);
    } catch (err: any) {
      setSubmitError(err.message || 'Failed to add indicator');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeactivate = async (id: string, value: string) => {
    if (!window.confirm(`Deactivate indicator "${value}"? Data is preserved for audit.`)) return;
    setDeletingId(id);
    try {
      const resp = await fetch(`/api/v1/threat-intel/indicators/${id}`, { method: 'DELETE' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      setIndicators((prev) => prev.filter((i) => i.id !== id));
    } catch (err: any) {
      alert(`Error: ${err.message}`);
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = indicators.filter((ind) => {
    const matchesSearch =
      ind.indicator_value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (ind.description || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      ind.source.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === 'ALL' || ind.indicator_type === typeFilter;
    const matchesSev = severityFilter === 'ALL' || ind.severity === severityFilter;
    return matchesSearch && matchesType && matchesSev;
  });

  const countBySeverity = (sev: string) => indicators.filter((i) => i.severity === sev).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Target className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Threat Indicators (IOC Registry)
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Local threat indicator database — domains, IPs, URLs, email addresses, and hashes.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {lastRefreshed && (
            <span className="text-xs text-text-muted font-mono flex items-center gap-1">
              <Clock className="w-3 h-3" />{lastRefreshed}
            </span>
          )}
          <button
            onClick={() => { setLoading(true); fetchIndicators(); }}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={() => { setShowAddModal(true); setSubmitError(null); }}
            className="flex items-center gap-2 bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-mono text-xs font-bold px-3.5 py-2 rounded transition-all shadow-teal-glow"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Indicator</span>
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total IOCs', value: indicators.length, color: 'text-teal-accent' },
          { label: 'Critical', value: countBySeverity('CRITICAL'), color: 'text-status-critical' },
          { label: 'High', value: countBySeverity('HIGH'), color: 'text-status-high' },
          { label: 'Medium', value: countBySeverity('MEDIUM'), color: 'text-status-medium' },
          { label: 'Low', value: countBySeverity('LOW'), color: 'text-status-low' },
        ].map((s) => (
          <div key={s.label} className="bg-surface-default border border-surface-border rounded-xl p-3 text-center">
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
            <div className="text-[10px] text-text-muted font-mono uppercase mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 flex items-center gap-2 text-xs font-mono text-status-critical">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
          <button onClick={fetchIndicators} className="ml-auto underline font-bold">Retry</button>
        </div>
      )}

      {/* Filters */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-3 flex flex-wrap items-center gap-3 font-mono text-xs">
        <div className="relative flex-1 min-w-52">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by value, source, description..."
            className="w-full bg-bg-darkest border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-text-primary focus:outline-none focus:border-teal-accent"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-text-muted" />
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent">
            <option value="ALL">All Types</option>
            {['DOMAIN','URL','IP','EMAIL','HASH','SENDER'].map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent">
            <option value="ALL">All Severities</option>
            {['CRITICAL','HIGH','MEDIUM','LOW'].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <label className="flex items-center gap-1.5 cursor-pointer text-text-secondary">
            <input
              type="checkbox"
              checked={showActiveOnly}
              onChange={(e) => setShowActiveOnly(e.target.checked)}
              className="accent-teal-accent"
            />
            Active Only
          </label>
        </div>
        <span className="text-text-muted ml-auto">{filtered.length} indicators</span>
      </div>

      {/* Indicators Table */}
      {loading ? (
        <div className="bg-surface-default border border-surface-border rounded-xl p-10 flex items-center justify-center gap-2 text-teal-accent font-mono">
          <Loader2 className="w-5 h-5 animate-spin" /><span>Loading IOC database...</span>
        </div>
      ) : (
        <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-bg-darkest/70 text-text-muted uppercase text-[10px] border-b border-surface-border">
                <tr>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Indicator Value</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Last Seen</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {filtered.map((ind) => (
                  <tr key={ind.id} className="hover:bg-surface-hover/60 transition-colors">
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${TYPE_COLORS[ind.indicator_type] || 'text-text-muted border-surface-border bg-surface-card'}`}>
                        {ind.indicator_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-text-primary font-bold max-w-xs">
                      <div className="truncate" title={ind.indicator_value}>{ind.indicator_value}</div>
                      {ind.description && (
                        <div className="text-text-muted text-[10px] font-normal truncate mt-0.5">{ind.description}</div>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-bold ${SEVERITY_COLORS[ind.severity] || 'text-text-muted border-surface-border'}`}>
                        {ind.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5">
                        <div className="w-16 bg-surface-card rounded-full h-1.5">
                          <div
                            className="h-1.5 rounded-full bg-teal-accent"
                            style={{ width: `${(ind.confidence * 100).toFixed(0)}%` }}
                          />
                        </div>
                        <span className="text-text-secondary">{(ind.confidence * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-text-secondary">{ind.source}</td>
                    <td className="py-3 px-4 text-text-muted">
                      {ind.last_seen ? new Date(ind.last_seen).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      {ind.is_active ? (
                        <span className="flex items-center gap-1 text-status-low">
                          <CheckCircle2 className="w-3.5 h-3.5" /><span>ACTIVE</span>
                        </span>
                      ) : (
                        <span className="text-text-muted">INACTIVE</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {ind.is_active && (
                        <button
                          onClick={() => handleDeactivate(ind.id, ind.indicator_value)}
                          disabled={deletingId === ind.id}
                          className="text-status-critical/70 hover:text-status-critical transition-colors p-1 rounded hover:bg-status-critical/10"
                          title="Deactivate indicator (data preserved for audit)"
                        >
                          {deletingId === ind.id
                            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            : <Trash2 className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-10 text-center text-text-muted">
                      No indicators match the current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Add Indicator Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-bg-darkest/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface-default border border-surface-border rounded-2xl w-full max-w-lg shadow-2xl">
            <div className="flex items-center justify-between p-5 border-b border-surface-border">
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-teal-accent" />
                <h2 className="font-bold text-text-primary font-mono text-sm uppercase">Add Threat Indicator</h2>
              </div>
              <button onClick={() => setShowAddModal(false)} className="text-text-muted hover:text-text-primary">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4 font-mono text-xs">
              {submitError && (
                <div className="bg-status-critical/10 border border-status-critical/30 rounded-lg p-3 text-status-critical flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />{submitError}
                </div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-text-muted uppercase text-[10px] tracking-wider block mb-1.5">Indicator Type *</label>
                  <select value={form.indicator_type} onChange={(e) => setForm({ ...form, indicator_type: e.target.value })}
                    className="w-full bg-bg-darkest border border-surface-border rounded-md px-3 py-2 text-text-primary focus:outline-none focus:border-teal-accent">
                    {['DOMAIN','URL','IP','EMAIL','HASH','SENDER'].map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-text-muted uppercase text-[10px] tracking-wider block mb-1.5">Severity</label>
                  <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}
                    className="w-full bg-bg-darkest border border-surface-border rounded-md px-3 py-2 text-text-primary focus:outline-none focus:border-teal-accent">
                    {['LOW','MEDIUM','HIGH','CRITICAL'].map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="text-text-muted uppercase text-[10px] tracking-wider block mb-1.5">Indicator Value *</label>
                <input
                  type="text"
                  value={form.indicator_value}
                  onChange={(e) => setForm({ ...form, indicator_value: e.target.value })}
                  placeholder="e.g. malicious-domain.com, 1.2.3.4, https://..."
                  className="w-full bg-bg-darkest border border-surface-border rounded-md px-3 py-2 text-text-primary focus:outline-none focus:border-teal-accent"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-text-muted uppercase text-[10px] tracking-wider block mb-1.5">Source</label>
                  <input
                    type="text"
                    value={form.source}
                    onChange={(e) => setForm({ ...form, source: e.target.value })}
                    className="w-full bg-bg-darkest border border-surface-border rounded-md px-3 py-2 text-text-primary focus:outline-none focus:border-teal-accent"
                  />
                </div>
                <div>
                  <label className="text-text-muted uppercase text-[10px] tracking-wider block mb-1.5">
                    Confidence: {(form.confidence * 100).toFixed(0)}%
                  </label>
                  <input
                    type="range"
                    min={0} max={1} step={0.05}
                    value={form.confidence}
                    onChange={(e) => setForm({ ...form, confidence: parseFloat(e.target.value) })}
                    className="w-full accent-teal-accent"
                  />
                </div>
              </div>

              <div>
                <label className="text-text-muted uppercase text-[10px] tracking-wider block mb-1.5">Description (Optional)</label>
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={2}
                  placeholder="Brief description of threat context..."
                  className="w-full bg-bg-darkest border border-surface-border rounded-md px-3 py-2 text-text-primary focus:outline-none focus:border-teal-accent resize-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 p-5 border-t border-surface-border">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 text-xs font-mono text-text-secondary hover:text-text-primary border border-surface-border rounded-md hover:border-surface-border/80 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAdd}
                disabled={submitting}
                className="flex items-center gap-2 px-4 py-2 text-xs font-mono font-bold bg-teal-accent hover:bg-teal-vibrant text-bg-darkest rounded-md transition-all shadow-teal-glow disabled:opacity-50"
              >
                {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                {submitting ? 'Adding...' : 'Add Indicator'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
