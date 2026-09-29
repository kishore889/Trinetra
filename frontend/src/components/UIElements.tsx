import React from 'react';
import type { SeverityLevel, DecisionType } from '../types';

export const ThreatBadge: React.FC<{ severity: SeverityLevel }> = ({ severity }) => {
  const styles: Record<SeverityLevel, string> = {
    CRITICAL: 'bg-status-critical/15 text-status-critical border-status-critical/40 shadow-[0_0_8px_rgba(255,92,103,0.3)]',
    HIGH: 'bg-status-high/15 text-status-high border-status-high/40',
    MEDIUM: 'bg-status-medium/15 text-status-medium border-status-medium/40',
    LOW: 'bg-status-low/15 text-status-low border-status-low/40',
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider border ${styles[severity]}`}>
      {severity}
    </span>
  );
};

export const DecisionBadge: React.FC<{ decision: DecisionType }> = ({ decision }) => {
  const styles: Record<DecisionType, string> = {
    QUARANTINE: 'bg-status-critical/20 text-status-critical border-status-critical/40',
    WARN: 'bg-status-high/20 text-status-high border-status-high/40',
    ALLOW: 'bg-status-low/20 text-status-low border-status-low/40',
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${styles[decision]}`}>
      {decision}
    </span>
  );
};

export const MetricCard: React.FC<{
  title: string;
  value: string | number;
  change?: string;
  isPositive?: boolean;
  icon: React.ReactNode;
}> = ({ title, value, change, isPositive, icon }) => {
  return (
    <div className="bg-surface-default hover:bg-surface-hover border border-surface-border rounded-xl p-4 transition-all duration-200 hover:shadow-teal-glow hover:border-teal-accent/40 relative overflow-hidden group">
      <div className="flex items-center justify-between text-text-muted mb-2">
        <span className="text-xs font-medium tracking-wide uppercase">{title}</span>
        <div className="text-teal-accent/80 group-hover:text-teal-accent transition-colors">
          {icon}
        </div>
      </div>
      <div className="flex items-baseline justify-between">
        <span className="text-2xl font-bold font-mono text-text-primary tracking-tight">{value}</span>
        {change && (
          <span className={`text-[11px] font-medium font-mono ${isPositive ? 'text-status-low' : 'text-status-high'}`}>
            {change}
          </span>
        )}
      </div>
      <div className="absolute -bottom-6 -right-6 w-20 h-20 bg-teal-accent/5 rounded-full blur-xl pointer-events-none" />
    </div>
  );
};
