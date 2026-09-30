import React, { useState, useEffect } from 'react';
import { Settings, Save, RefreshCw, CheckCircle2, AlertTriangle, Sliders, Shield } from 'lucide-react';

interface RiskConfig {
  content_weight: number;
  url_weight: number;
  identity_weight: number;
  threat_intel_weight: number;
  graph_weight: number;
  allow_max_score: number;
  warn_max_score: number;
  quarantine_min_score: number;
  version?: string;
}

export const SettingsPage: React.FC = () => {
  const [config, setConfig] = useState<RiskConfig>({
    content_weight: 0.25,
    url_weight: 0.30,
    identity_weight: 0.20,
    threat_intel_weight: 0.15,
    graph_weight: 0.10,
    allow_max_score: 0.30,
    warn_max_score: 0.65,
    quarantine_min_score: 0.66,
  });

  const [loading, setLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const resp = await fetch('/api/v1/risk/config');
      if (resp.ok) {
        const data = await resp.json();
        setConfig(data);
      }
    } catch {
      // Keep default
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveSuccess(null);

    // Validate weights sum to 1.0
    const sum =
      config.content_weight +
      config.url_weight +
      config.identity_weight +
      config.threat_intel_weight +
      config.graph_weight;

    if (Math.abs(sum - 1.0) > 0.01) {
      alert(`Layer weights must sum to exactly 1.00 (Current sum: ${sum.toFixed(2)})`);
      setIsSaving(false);
      return;
    }

    try {
      const resp = await fetch('/api/v1/risk/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });

      if (resp.ok) {
        const updated = await resp.json();
        setConfig(updated);
        setSaveSuccess('Central Risk Engine parameters updated and applied!');
      } else {
        const errData = await resp.json();
        alert(errData.detail || 'Failed to save configuration');
      }
    } catch (err: any) {
      alert(`Error saving config: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Settings className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Central Risk Engine Configuration & Platform Settings
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Configurable weighted fusion weights, decision sensitivity thresholds, and operational parameters.
          </p>
        </div>

        <button
          onClick={fetchConfig}
          className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Reset Configuration</span>
        </button>
      </div>

      {saveSuccess && (
        <div className="p-3 bg-teal-accent/10 border border-teal-accent text-teal-accent text-xs font-mono rounded flex items-center justify-between">
          <span>{saveSuccess}</span>
          <button onClick={() => setSaveSuccess(null)}>✕</button>
        </div>
      )}

      {/* Form */}
      <form onSubmit={handleSave} className="space-y-6">
        {/* Layer Fusion Weights */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
          <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider flex items-center gap-2">
            <Sliders className="w-4 h-4" />
            <span>Layer Fusion Weights (Must sum to 1.00)</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 font-mono text-xs">
            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">Content Risk Weight</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.content_weight}
                onChange={(e) => setConfig({ ...config, content_weight: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>

            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">URL Risk Weight</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.url_weight}
                onChange={(e) => setConfig({ ...config, url_weight: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>

            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">Identity Risk Weight</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.identity_weight}
                onChange={(e) => setConfig({ ...config, identity_weight: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>

            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">Threat Intel Weight</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.threat_intel_weight}
                onChange={(e) => setConfig({ ...config, threat_intel_weight: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>

            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">Graph Risk Weight</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.graph_weight}
                onChange={(e) => setConfig({ ...config, graph_weight: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>
          </div>
        </div>

        {/* Severity Thresholds */}
        <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
          <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4" />
            <span>Decision Sensitivity Thresholds</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">ALLOW Max Threshold</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.allow_max_score}
                onChange={(e) => setConfig({ ...config, allow_max_score: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>

            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">WARN Max Threshold</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.warn_max_score}
                onChange={(e) => setConfig({ ...config, warn_max_score: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>

            <div>
              <label className="text-[10px] text-text-muted uppercase block mb-1">QUARANTINE Min Threshold</label>
              <input
                type="number"
                step="0.01"
                min="0"
                max="1"
                value={config.quarantine_min_score}
                onChange={(e) => setConfig({ ...config, quarantine_min_score: parseFloat(e.target.value) || 0 })}
                className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
              />
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isSaving}
            className="flex items-center gap-2 bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-mono text-xs font-bold px-6 py-2.5 rounded shadow-teal-glow"
          >
            <Save className="w-4 h-4" />
            <span>{isSaving ? 'Saving Configuration...' : 'Save & Apply Config'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
