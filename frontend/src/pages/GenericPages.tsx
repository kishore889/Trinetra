import React from 'react';

export const GenericPage: React.FC<{ title: string; subtitle: string }> = ({ title, subtitle }) => {
  return (
    <div className="bg-surface-default border border-surface-border rounded-xl p-8 text-center max-w-2xl mx-auto my-12">
      <h2 className="text-lg font-bold text-text-primary mb-2">{title}</h2>
      <p className="text-xs text-text-muted leading-relaxed mb-6">{subtitle}</p>
      <div className="inline-block bg-bg-darkest/60 border border-teal-accent/30 text-teal-accent px-3 py-1.5 rounded-full text-xs font-mono">
        Active SOC View Ready
      </div>
    </div>
  );
};
