import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  Play, 
  ShieldAlert, 
  CheckCircle2, 
  ArrowRight, 
  Mail, 
  FileText, 
  Cpu, 
  Globe, 
  UserCheck, 
  Target, 
  Share2, 
  Sliders, 
  Eye, 
  Lock, 
  ChevronRight, 
  ChevronDown, 
  Clock, 
  AlertTriangle, 
  CheckCircle, 
  ExternalLink, 
  RefreshCw,
  Code
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';

interface DemoScenario {
  id: string;
  scenario_number: number;
  name: string;
  category: string;
  attack_vector: string;
  description: string;
  target_technique: string;
  synthetic_sender: string;
  synthetic_subject: string;
  expected_baseline_verdict: string;
  raw_mime?: string;
}

interface StageTelemetry {
  step_number: number;
  stage_id: string;
  stage_name: string;
  status: string;
  duration_ms: number;
  score?: number;
  summary: string;
  findings: string[];
  details: Record<string, any>;
}

interface DemoResult {
  scenario_id: string;
  scenario_name: string;
  category: string;
  executed_at: string;
  total_pipeline_duration_ms: number;
  final_verdict: 'ALLOW' | 'WARN' | 'QUARANTINE';
  final_risk_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  stages: StageTelemetry[];
  layer_scores: Record<string, number>;
  persisted_email_id?: string;
  persisted_detection_id?: string;
  applied_action: string;
  email_preview: {
    sender: string;
    recipient: string;
    subject: string;
    date?: string;
    body_snippet?: string;
    urls: string[];
    headers: Record<string, string | null>;
  };
}

const STAGE_ICONS: Record<string, React.ElementType> = {
  EMAIL_RECEIVED: Mail,
  PARSING: FileText,
  CONTENT_ANALYSIS: Cpu,
  URL_ANALYSIS: Globe,
  IDENTITY_ANALYSIS: UserCheck,
  THREAT_INTELLIGENCE: Target,
  GRAPH_CORRELATION: Share2,
  RISK_ENGINE: Sliders,
  DECISION: Eye,
  ACTION: Lock,
};

export const DemoCenterPage: React.FC = () => {
  const navigate = useNavigate();
  const [scenarios, setScenarios] = useState<DemoScenario[]>([]);
  const [loadingScenarios, setLoadingScenarios] = useState(true);
  const [selectedScenario, setSelectedScenario] = useState<DemoScenario | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(-1);
  const [selectedStageTab, setSelectedStageTab] = useState<number>(0);
  const [executionResult, setExecutionResult] = useState<DemoResult | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [showRawMime, setShowRawMime] = useState(false);
  const [showCustomModal, setShowCustomModal] = useState(false);
  const [customMimeInput, setCustomMimeInput] = useState('');
  const [customRunning, setCustomRunning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Fetch scenarios on mount
  useEffect(() => {
    fetchScenarios();
  }, []);

  const fetchScenarios = async () => {
    setLoadingScenarios(true);
    try {
      const resp = await fetch('/api/v1/demo/scenarios');
      if (resp.ok) {
        const data = await resp.json();
        setScenarios(data);
        if (data.length > 0) {
          setSelectedScenario(data[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch scenarios:', err);
    } finally {
      setLoadingScenarios(false);
    }
  };

  const handleRunScenario = async (scen: DemoScenario) => {
    setRunningId(scen.id);
    setSelectedScenario(scen);
    setExecutionResult(null);
    setErrorMsg(null);
    setActiveStepIndex(0);

    // Visual step sequence animation timer
    let currentStep = 0;
    const stepInterval = setInterval(() => {
      currentStep = (currentStep + 1) % 10;
      setActiveStepIndex(currentStep);
    }, 180);

    try {
      const resp = await fetch(`/api/v1/demo/run/${scen.id}`, {
        method: 'POST',
      });
      clearInterval(stepInterval);

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.detail || errData.message || 'Pipeline simulation execution failed');
      }

      const resultData: DemoResult = await resp.json();
      setExecutionResult(resultData);
      setActiveStepIndex(9); // complete
      setSelectedStageTab(7); // default highlight Risk Engine
    } catch (err: any) {
      clearInterval(stepInterval);
      setErrorMsg(err.message || 'Simulation error');
      setActiveStepIndex(-1);
    } finally {
      setRunningId(null);
    }
  };

  const handleRunCustom = async () => {
    if (!customMimeInput.trim()) return;
    setCustomRunning(true);
    setErrorMsg(null);
    setActiveStepIndex(0);

    let currentStep = 0;
    const stepInterval = setInterval(() => {
      currentStep = (currentStep + 1) % 10;
      setActiveStepIndex(currentStep);
    }, 180);

    try {
      const resp = await fetch('/api/v1/demo/run-custom', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_mime: customMimeInput }),
      });
      clearInterval(stepInterval);

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({}));
        throw new Error(errData.detail || errData.message || 'Custom pipeline execution failed');
      }

      const resultData: DemoResult = await resp.json();
      setExecutionResult(resultData);
      setActiveStepIndex(9);
      setSelectedStageTab(7);
      setShowCustomModal(false);
    } catch (err: any) {
      clearInterval(stepInterval);
      setErrorMsg(err.message || 'Custom execution error');
      setActiveStepIndex(-1);
    } finally {
      setCustomRunning(false);
    }
  };

  const filteredScenarios = scenarios.filter((s) => {
    if (filterCategory === 'ALL') return true;
    if (filterCategory === 'CLEAN') return s.expected_baseline_verdict === 'ALLOW';
    if (filterCategory === 'CREDENTIAL') return s.category.includes('Credential');
    if (filterCategory === 'IMPERSONATION') return s.category.includes('Spoofing') || s.category.includes('Impersonation') || s.category.includes('Homoglyph');
    if (filterCategory === 'ADVANCED') return s.category.includes('Campaign') || s.category.includes('Threat Intelligence') || s.category.includes('Targeted');
    return true;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-teal-accent/15 text-teal-accent border border-teal-accent/30 tracking-wider">
              PHASE 16 DEMO PLATFORM
            </span>
            <span className="text-[10px] font-mono text-text-muted">| ZERO MOCKS • LIVE ENGINES</span>
          </div>
          <h1 className="text-xl font-bold text-text-primary tracking-wide mt-1">
            Controlled Attack / Defense Demonstration Center
          </h1>
          <p className="text-xs text-text-secondary mt-0.5">
            Every simulation executes through the exact 10-stage detection pipeline used for live enterprise Gmail ingestion.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCustomModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-surface-card border border-surface-border text-text-secondary hover:text-text-primary hover:border-teal-accent/40 transition-all"
          >
            <Code className="w-3.5 h-3.5 text-teal-accent" />
            <span>Custom MIME Injection</span>
          </button>
          <button
            onClick={fetchScenarios}
            className="p-1.5 rounded-lg bg-surface-card border border-surface-border text-text-secondary hover:text-text-primary hover:border-teal-accent/40 transition-all"
            title="Refresh Scenarios"
          >
            <RefreshCw className={`w-4 h-4 ${loadingScenarios ? 'animate-spin text-teal-accent' : ''}`} />
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-red-950/40 border border-red-500/40 rounded-xl text-xs text-red-200 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-red-200 text-xs font-mono">Dismiss</button>
        </div>
      )}

      {/* Main Layout: Scenario Cards & Live Visualization Split */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: 10 Scenario Selector (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold font-mono uppercase tracking-wider text-text-muted">
              Select Attack / Defense Scenario
            </span>
            <span className="text-[11px] font-mono text-teal-accent font-semibold">
              {filteredScenarios.length} Scenarios Available
            </span>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1 overflow-x-auto pb-1 text-[11px] scrollbar-thin">
            {[
              { id: 'ALL', label: 'All (10)' },
              { id: 'CLEAN', label: 'Clean Baseline' },
              { id: 'CREDENTIAL', label: 'Credential Phish' },
              { id: 'IMPERSONATION', label: 'Spoofing & BEC' },
              { id: 'ADVANCED', label: 'Campaign & TI' },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setFilterCategory(tab.id)}
                className={`px-2.5 py-1 rounded-md font-medium whitespace-nowrap transition-all ${
                  filterCategory === tab.id
                    ? 'bg-teal-accent text-bg-darkest font-semibold'
                    : 'bg-surface-card text-text-muted hover:text-text-primary'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Scenario List Cards */}
          <div className="space-y-2.5 max-h-[720px] overflow-y-auto pr-1">
            {filteredScenarios.map((scen) => {
              const isSelected = selectedScenario?.id === scen.id;
              const isRunning = runningId === scen.id;

              return (
                <div
                  key={scen.id}
                  onClick={() => setSelectedScenario(scen)}
                  className={`p-3.5 rounded-xl border transition-all cursor-pointer relative ${
                    isSelected
                      ? 'bg-surface-card border-teal-accent/60 shadow-teal-glow'
                      : 'bg-surface-default border-surface-border hover:border-surface-border/80 hover:bg-surface-card/60'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-md bg-surface-hover border border-surface-border text-center text-[10px] font-mono font-bold flex items-center justify-center text-teal-accent">
                        {scen.scenario_number}
                      </span>
                      <span className="text-xs font-semibold text-text-primary">
                        {scen.name}
                      </span>
                    </div>
                    <DecisionBadge decision={scen.expected_baseline_verdict as any} />
                  </div>

                  <p className="text-[11px] text-text-secondary leading-relaxed mb-2.5 line-clamp-2">
                    {scen.description}
                  </p>

                  <div className="flex items-center justify-between text-[10px] font-mono pt-2 border-t border-surface-border/60">
                    <span className="text-text-muted truncate max-w-[200px]" title={scen.synthetic_sender}>
                      {scen.synthetic_sender}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRunScenario(scen);
                      }}
                      disabled={runningId !== null}
                      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold transition-all ${
                        isRunning
                          ? 'bg-teal-accent text-bg-darkest font-bold'
                          : 'bg-teal-accent/15 text-teal-accent border border-teal-accent/30 hover:bg-teal-accent hover:text-bg-darkest'
                      }`}
                    >
                      <Play className={`w-3 h-3 ${isRunning ? 'animate-spin' : ''}`} />
                      <span>{isRunning ? 'Processing...' : 'Run Pipeline'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Live Pipeline Visualizer & Telemetry (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          {/* Active Scenario Banner */}
          {selectedScenario && (
            <div className="bg-surface-card border border-surface-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-sm">
              <div>
                <div className="flex items-center gap-2 text-[10px] font-mono text-text-muted uppercase">
                  <span>Scenario #{selectedScenario.scenario_number}</span>
                  <span>•</span>
                  <span className="text-teal-accent font-semibold">{selectedScenario.category}</span>
                  <span>•</span>
                  <span>{selectedScenario.target_technique}</span>
                </div>
                <div className="text-sm font-bold text-text-primary mt-0.5">
                  {selectedScenario.name}
                </div>
                <div className="text-[11px] text-text-secondary truncate mt-0.5">
                  Subject: <span className="text-text-primary font-mono">{selectedScenario.synthetic_subject}</span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setShowRawMime(!showRawMime)}
                  className="px-2.5 py-1 rounded-md text-xs font-mono bg-surface-default border border-surface-border text-text-muted hover:text-text-primary transition-all"
                >
                  {showRawMime ? 'Hide MIME' : 'Inspect MIME'}
                </button>
                <button
                  onClick={() => handleRunScenario(selectedScenario)}
                  disabled={runningId !== null}
                  className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-bold bg-teal-accent text-bg-darkest shadow-teal-glow hover:brightness-110 transition-all disabled:opacity-50"
                >
                  <Play className={`w-3.5 h-3.5 ${runningId === selectedScenario.id ? 'animate-spin' : ''}`} />
                  <span>{runningId === selectedScenario.id ? 'Running 10 Stages...' : 'Execute Simulation'}</span>
                </button>
              </div>
            </div>
          )}

          {/* Raw MIME Preview Drawer (collapsible) */}
          {showRawMime && selectedScenario && (
            <div className="bg-bg-darkest border border-surface-border rounded-xl p-3.5 font-mono text-[11px] text-text-secondary max-h-48 overflow-y-auto whitespace-pre-wrap leading-relaxed">
              <div className="text-[10px] text-teal-accent font-bold uppercase tracking-wider mb-1">Synthetic RFC 822 MIME Payload:</div>
              {selectedScenario.raw_mime}
            </div>
          )}

          {/* 10-Stage Pipeline Horizontal Stepper */}
          <div className="bg-surface-default border border-surface-border rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between mb-3 text-xs">
              <span className="font-mono font-bold uppercase tracking-wider text-text-muted flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-teal-accent" />
                Live Pipeline Processing Stages (10 Stages)
              </span>
              <span className="font-mono text-[11px] text-text-secondary">
                {executionResult ? (
                  <span className="text-teal-accent font-bold">
                    ✓ Completed in {executionResult.total_pipeline_duration_ms} ms
                  </span>
                ) : runningId ? (
                  <span className="text-amber-400 font-bold animate-pulse">
                    ⚡ Processing Stage {activeStepIndex + 1}/10...
                  </span>
                ) : (
                  'Ready to execute'
                )}
              </span>
            </div>

            {/* Stepper Timeline Grid */}
            <div className="grid grid-cols-5 md:grid-cols-10 gap-1.5">
              {[
                { id: 'EMAIL_RECEIVED', short: 'INGEST', name: 'Email Received' },
                { id: 'PARSING', short: 'PARSE', name: 'Parser' },
                { id: 'CONTENT_ANALYSIS', short: 'CONTENT', name: 'Content AI' },
                { id: 'URL_ANALYSIS', short: 'URL', name: 'URL Intel' },
                { id: 'IDENTITY_ANALYSIS', short: 'IDENTITY', name: 'Identity' },
                { id: 'THREAT_INTELLIGENCE', short: 'THREAT', name: 'Threat Intel' },
                { id: 'GRAPH_CORRELATION', short: 'GRAPH', name: 'Graph Engine' },
                { id: 'RISK_ENGINE', short: 'RISK', name: 'Risk Engine' },
                { id: 'DECISION', short: 'DECISION', name: 'Decision' },
                { id: 'ACTION', short: 'ACTION', name: 'Gmail Action' },
              ].map((stage, idx) => {
                const Icon = STAGE_ICONS[stage.id] || Sparkles;
                const isCurrentActive = activeStepIndex === idx && runningId !== null;
                const isCompleted = executionResult !== null;
                const isSelectedTab = selectedStageTab === idx;
                const stageTelemetry = executionResult?.stages.find((s) => s.stage_id === stage.id);

                return (
                  <button
                    key={stage.id}
                    onClick={() => setSelectedStageTab(idx)}
                    className={`flex flex-col items-center justify-center p-2 rounded-lg border text-center transition-all ${
                      isCurrentActive
                        ? 'bg-teal-accent/25 border-teal-accent text-teal-accent shadow-teal-glow animate-pulse'
                        : isSelectedTab
                        ? 'bg-surface-card border-teal-accent/70 text-text-primary'
                        : isCompleted
                        ? 'bg-surface-card/60 border-surface-border text-text-secondary hover:border-teal-accent/40'
                        : 'bg-surface-default/40 border-surface-border/40 text-text-muted opacity-60'
                    }`}
                  >
                    <Icon className={`w-3.5 h-3.5 mb-1 ${isCurrentActive ? 'text-teal-accent' : isCompleted ? 'text-text-primary' : 'text-text-muted'}`} />
                    <span className="text-[9px] font-mono font-bold leading-tight">
                      {stage.short}
                    </span>
                    {stageTelemetry?.score !== undefined && stageTelemetry?.score !== null && (
                      <span className="text-[8px] font-mono text-teal-accent font-bold mt-0.5">
                        {stageTelemetry.score.toFixed(2)}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Execution Result Banner (If Complete) */}
          {executionResult && (
            <div className="bg-surface-card border border-teal-accent/40 rounded-xl p-4 shadow-teal-glow space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surface-border pb-3">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold text-sm border shadow-sm ${
                    executionResult.final_verdict === 'ALLOW'
                      ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-400'
                      : executionResult.final_verdict === 'WARN'
                      ? 'bg-amber-950/60 border-amber-500/50 text-amber-400'
                      : 'bg-red-950/60 border-red-500/50 text-red-400'
                  }`}>
                    {Math.round(executionResult.final_risk_score * 100)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-text-primary">
                        {executionResult.scenario_name}
                      </span>
                      <ThreatBadge severity={executionResult.severity} />
                    </div>
                    <div className="text-[11px] text-text-muted font-mono mt-0.5">
                      Fused Risk Score: <span className="font-bold text-text-primary">{(executionResult.final_risk_score * 100).toFixed(1)}/100</span> • Confidence: <span className="text-teal-accent font-bold">{Math.round(executionResult.confidence * 100)}%</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <div className="text-right">
                    <span className="text-[10px] font-mono text-text-muted block">PIPELINE ACTION</span>
                    <span className="text-xs font-bold text-teal-accent font-mono">{executionResult.applied_action}</span>
                  </div>
                  <DecisionBadge decision={executionResult.final_verdict} />
                </div>
              </div>

              {/* 5-Layer Risk Contribution Bar */}
              <div>
                <div className="flex items-center justify-between text-[10px] font-mono text-text-muted mb-1.5 uppercase">
                  <span>5-Layer Calibrated Signal Contributions</span>
                  <span>Central Risk Engine v1.0</span>
                </div>
                <div className="grid grid-cols-5 gap-2">
                  {[
                    { name: 'Content', key: 'content_risk', val: executionResult.layer_scores.content_risk },
                    { name: 'URL', key: 'url_risk', val: executionResult.layer_scores.url_risk },
                    { name: 'Identity', key: 'identity_risk', val: executionResult.layer_scores.identity_risk },
                    { name: 'Threat Intel', key: 'threat_intel_risk', val: executionResult.layer_scores.threat_intel_risk },
                    { name: 'Graph', key: 'graph_risk', val: executionResult.layer_scores.graph_risk },
                  ].map((layer) => {
                    const score = layer.val ?? 0;
                    return (
                      <div key={layer.key} className="bg-surface-default p-2 rounded-lg border border-surface-border">
                        <div className="text-[9px] font-mono text-text-muted truncate">{layer.name}</div>
                        <div className="flex items-baseline justify-between mt-1">
                          <span className="text-xs font-mono font-bold text-text-primary">{(score * 100).toFixed(0)}</span>
                          <span className="text-[9px] font-mono text-text-muted">/100</span>
                        </div>
                        <div className="w-full bg-surface-hover h-1 rounded-full overflow-hidden mt-1.5">
                          <div 
                            className={`h-full rounded-full ${
                              score > 0.65 ? 'bg-red-500' : score > 0.35 ? 'bg-amber-400' : 'bg-emerald-400'
                            }`}
                            style={{ width: `${Math.max(4, score * 100)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Deep Link to SOC Workspace */}
              <div className="flex items-center justify-between pt-2 border-t border-surface-border text-xs">
                <span className="text-[11px] text-text-muted">
                  Persisted to live database: Email ID #{executionResult.persisted_email_id?.slice(0, 8)}...
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => navigate('/investigations')}
                    className="flex items-center gap-1 text-teal-accent hover:underline text-xs font-medium"
                  >
                    <span>Investigate in Workspace</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                  <span className="text-text-muted">•</span>
                  <button
                    onClick={() => navigate('/graph')}
                    className="flex items-center gap-1 text-teal-accent hover:underline text-xs font-medium"
                  >
                    <span>View in Threat Graph</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Selected Stage Detail Drawer (Inspection View) */}
          {executionResult && executionResult.stages[selectedStageTab] && (
            <div className="bg-surface-default border border-surface-border rounded-xl p-4 space-y-3">
              {(() => {
                const stage = executionResult.stages[selectedStageTab];
                const Icon = STAGE_ICONS[stage.stage_id] || Sparkles;

                return (
                  <>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <div className="w-7 h-7 rounded-lg bg-teal-accent/10 border border-teal-accent/30 flex items-center justify-center text-teal-accent">
                          <Icon className="w-4 h-4" />
                        </div>
                        <div>
                          <span className="text-[10px] font-mono text-teal-accent font-bold uppercase">
                            STAGE {stage.step_number} OF 10
                          </span>
                          <h3 className="text-xs font-bold text-text-primary">{stage.stage_name}</h3>
                        </div>
                      </div>
                      <div className="text-right">
                        <span className="text-[10px] font-mono text-text-muted block">BENCHMARK</span>
                        <span className="text-xs font-mono font-bold text-text-primary">{stage.duration_ms} ms</span>
                      </div>
                    </div>

                    <p className="text-xs text-text-secondary bg-surface-card p-3 rounded-lg border border-surface-border leading-relaxed">
                      {stage.summary}
                    </p>

                    <div>
                      <span className="text-[10px] font-mono text-text-muted font-bold uppercase tracking-wider block mb-1.5">
                        Key Telemetry & Sensor Findings:
                      </span>
                      <ul className="space-y-1 text-xs text-text-primary">
                        {stage.findings.map((f, i) => (
                          <li key={i} className="flex items-start gap-2 bg-surface-hover/60 px-2.5 py-1.5 rounded-md font-mono text-[11px]">
                            <span className="text-teal-accent">•</span>
                            <span>{f}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {stage.details && Object.keys(stage.details).length > 0 && (
                      <div className="pt-2 border-t border-surface-border">
                        <span className="text-[10px] font-mono text-text-muted font-bold uppercase tracking-wider block mb-1">
                          Raw Engine State Output:
                        </span>
                        <pre className="bg-bg-darkest p-3 rounded-lg font-mono text-[10px] text-text-muted max-h-36 overflow-y-auto overflow-x-auto">
                          {JSON.stringify(stage.details, null, 2)}
                        </pre>
                      </div>
                    )}
                  </>
                );
              })()}
            </div>
          )}

          {/* Placeholder State when not yet run */}
          {!executionResult && !runningId && (
            <div className="bg-surface-default border border-dashed border-surface-border rounded-xl p-8 text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-teal-accent/10 border border-teal-accent/20 flex items-center justify-center text-teal-accent mx-auto">
                <Sparkles className="w-6 h-6 animate-pulse" />
              </div>
              <h3 className="text-sm font-semibold text-text-primary">Ready to Launch Live Threat Simulation</h3>
              <p className="text-xs text-text-muted max-w-md mx-auto leading-relaxed">
                Click <span className="text-teal-accent font-semibold">"Execute Simulation"</span> above or choose any scenario from the left to watch TRINETRA's 10-stage AI, graph, identity, and threat intelligence engines evaluate the payload live.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Custom MIME Modal */}
      {showCustomModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface-card border border-surface-border rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-surface-border pb-3">
              <div>
                <h3 className="text-sm font-bold text-text-primary">Custom Synthetic MIME Injection</h3>
                <p className="text-xs text-text-muted">Inject raw RFC 822 email text into TRINETRA's detection pipeline.</p>
              </div>
              <button 
                onClick={() => setShowCustomModal(false)}
                className="text-text-muted hover:text-text-primary text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <div>
              <label className="text-[11px] font-mono text-text-muted block mb-1.5 uppercase font-semibold">
                RFC 822 MIME Content:
              </label>
              <textarea
                value={customMimeInput}
                onChange={(e) => setCustomMimeInput(e.target.value)}
                placeholder="From: Security Alerts <alerts@example.com>&#10;To: victim@enterprise.com&#10;Subject: Action Required: Verify Credentials&#10;Date: Tue, 29 Sep 2026 14:00:00 +0000&#10;Content-Type: text/plain&#10;&#10;Please login to verify your account: http://192.168.1.100/login"
                rows={10}
                className="w-full bg-bg-darkest border border-surface-border rounded-xl p-3 font-mono text-xs text-text-primary focus:border-teal-accent focus:outline-none"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowCustomModal(false)}
                className="px-4 py-2 rounded-lg text-xs font-medium text-text-secondary hover:text-text-primary"
              >
                Cancel
              </button>
              <button
                onClick={handleRunCustom}
                disabled={customRunning || !customMimeInput.trim()}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-teal-accent text-bg-darkest shadow-teal-glow hover:brightness-110 disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{customRunning ? 'Simulating...' : 'Run Custom Email'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
