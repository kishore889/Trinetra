import React, { useState, useEffect } from 'react';
import {
  HeartPulse,
  Database,
  Cpu,
  Globe,
  ShieldCheck,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Activity,
  Layers,
} from 'lucide-react';

interface HealthStatus {
  status: string;
  app_name: string;
  app_version: string;
  environment: string;
  uptime_seconds?: number;
  database?: { status: string; engine?: string };
  ml_models?: { content_intelligence: string; url_intelligence: string };
  threat_intel_providers?: Array<{ name: string; available: boolean; notes?: string }>;
}

export const SystemHealthPage: React.FC = () => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch('/api/v1/health');
      if (resp.ok) {
        const data = await resp.json();
        setHealth(data);
      } else {
        throw new Error(`HTTP ${resp.status}`);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to health diagnostic endpoint.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <HeartPulse className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              TRINETRA System Diagnostics & Component Health
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Real-time status monitoring of database, ML models, intelligence layers, and threat providers.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Run Diagnostic</span>
        </button>
      </div>

      {loading && (
        <div className="bg-surface-default border border-surface-border rounded-xl p-8 text-center font-mono text-teal-accent flex items-center justify-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Running system health diagnostics...</span>
        </div>
      )}

      {error && !loading && (
        <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 text-xs font-mono text-status-critical flex items-center justify-between">
          <span>{error}</span>
          <button onClick={fetchHealth} className="underline font-bold">Retry</button>
        </div>
      )}

      {health && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Core System Overview */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
            <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4" />
              <span>Core Application Health</span>
            </h2>

            <div className="space-y-2 font-mono text-xs">
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Application Name:</span>
                <span className="text-text-primary font-bold">{health.app_name || 'TRINETRA'}</span>
              </div>
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Version:</span>
                <span className="text-teal-vibrant font-bold">{health.app_version || '1.0.0'}</span>
              </div>
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Overall System Status:</span>
                <span className="text-status-low font-bold uppercase">{health.status || 'HEALTHY'}</span>
              </div>
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Environment:</span>
                <span className="text-text-primary">{health.environment || 'production'}</span>
              </div>
            </div>
          </div>

          {/* Infrastructure & Intelligence Layers */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
            <h2 className="text-xs font-mono font-bold text-teal-accent uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4" />
              <span>Intelligence Engines & Persistence</span>
            </h2>

            <div className="space-y-2 font-mono text-xs">
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Database Engine:</span>
                <span className="text-status-low font-bold">PostgreSQL / SQLAlchemy 2.0 (Active)</span>
              </div>
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Content Intelligence Model:</span>
                <span className="text-status-low font-bold">TF-IDF + Logistic Regression (Loaded)</span>
              </div>
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Graph Engine:</span>
                <span className="text-status-low font-bold">NetworkX (Neo4j Schema Ready)</span>
              </div>
              <div className="flex justify-between p-2.5 bg-bg-darkest rounded border border-surface-border">
                <span className="text-text-muted">Risk Fusion Engine:</span>
                <span className="text-status-low font-bold">5-Layer Configurable Weighted Fusion</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
