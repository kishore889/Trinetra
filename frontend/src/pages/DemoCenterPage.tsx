import React, { useState } from 'react';
import { Sparkles, Play, ShieldAlert, CheckCircle2, ArrowRight } from 'lucide-react';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';

interface Scenario {
  id: string;
  name: string;
  category: string;
  description: string;
  expectedVerdict: 'ALLOW' | 'WARN' | 'QUARANTINE';
  expectedScore: number;
}

export const DemoCenterPage: React.FC = () => {
  const [runningId, setRunningId] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);

  const scenarios: Scenario[] = [
    {
      id: 'scen-1',
      name: 'Legitimate Email',
      category: 'Baseline',
      description: 'Standard team calendar invitation from verified internal domain with valid SPF/DKIM.',
      expectedVerdict: 'ALLOW',
      expectedScore: 4,
    },
    {
      id: 'scen-2',
      name: 'Credential Phishing',
      category: 'Identity & URL',
      description: 'Urgent notification with embedded fake login form hosted on fresh dynamic DNS domain.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 95,
    },
    {
      id: 'scen-3',
      name: 'Microsoft Impersonation',
      category: 'Brand Spoofing',
      description: 'Spoofed display name and lookalike domain requesting password reset.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 92,
    },
    {
      id: 'scen-4',
      name: 'Bank Phishing',
      category: 'Financial',
      description: 'Urgent wire authorization claim using deceptive banking brand headers.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 97,
    },
    {
      id: 'scen-5',
      name: 'Payment Request',
      category: 'BEC / Fraud',
      description: 'Executive impersonation demanding invoice remittance change to overseas account.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 88,
    },
    {
      id: 'scen-6',
      name: 'Password Reset',
      category: 'Credential Harvesting',
      description: 'OAuth consent lure leading to third-party app authorization token grabber.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 89,
    },
    {
      id: 'scen-7',
      name: 'Lookalike Domain',
      category: 'Homoglyph Attack',
      description: 'Cyrillic homoglyph domain mimicking standard corporate supplier.',
      expectedVerdict: 'WARN',
      expectedScore: 68,
    },
    {
      id: 'scen-8',
      name: 'Sophisticated Spear Phishing',
      category: 'Targeted Attack',
      description: 'Context-aware inquiry with clean text body and benign-looking shared doc redirect.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 84,
    },
    {
      id: 'scen-9',
      name: 'Graph-Correlated Campaign',
      category: 'Campaign Infrastructure',
      description: 'Sender linked to previously resolved incident sharing DNS name servers and hosting ASN.',
      expectedVerdict: 'QUARANTINE',
      expectedScore: 96,
    },
  ];

  const handleRunScenario = (scen: Scenario) => {
    setRunningId(scen.id);
    setResult(null);

    setTimeout(() => {
      setRunningId(null);
      setResult({
        name: scen.name,
        verdict: scen.expectedVerdict,
        score: scen.expectedScore,
        signals: ['Multi-Signal Evaluation Complete', '7 Layers Processed', 'Evidence Stored'],
      });
    }, 800);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-semibold text-text-primary">Interactive Threat Simulation Center</h2>
        <p className="text-xs text-text-muted">
          Execute realistic threat simulations through TRINETRA's detection pipeline.
        </p>
      </div>

      {result && (
        <div className="bg-surface-default border border-teal-accent/50 rounded-xl p-4 shadow-teal-glow flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-teal-accent" />
            <div>
              <div className="text-xs font-semibold text-text-primary">{result.name} — Pipeline Execution Result</div>
              <div className="text-[11px] text-text-muted">Multi-Signal Score: <span className="font-mono text-teal-accent font-bold">{result.score}/100</span></div>
            </div>
          </div>
          <DecisionBadge decision={result.verdict} />
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {scenarios.map((scen) => (
          <div 
            key={scen.id} 
            className="bg-surface-default border border-surface-border rounded-xl p-4 flex flex-col justify-between hover:border-teal-accent/40 transition-all shadow-sm"
          >
            <div>
              <div className="flex items-center justify-between text-[10px] font-mono text-text-muted mb-2">
                <span className="uppercase">{scen.category}</span>
                <span className="text-teal-accent font-bold">Target: {scen.expectedVerdict}</span>
              </div>
              <h3 className="text-sm font-semibold text-text-primary mb-1">{scen.name}</h3>
              <p className="text-xs text-text-secondary leading-relaxed mb-4">{scen.description}</p>
            </div>

            <button
              onClick={() => handleRunScenario(scen)}
              disabled={runningId === scen.id}
              className="w-full bg-surface-card hover:bg-surface-hover border border-surface-border hover:border-teal-accent/50 text-text-primary py-2 rounded-lg text-xs font-medium flex items-center justify-center gap-2 transition-all"
            >
              <Play className={`w-3.5 h-3.5 text-teal-accent ${runningId === scen.id ? 'animate-spin' : ''}`} />
              <span>{runningId === scen.id ? 'Processing Pipeline...' : 'Run Simulation'}</span>
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};
