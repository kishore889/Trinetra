import React from 'react';
import { Search, Bell, ShieldCheck, UserCheck } from 'lucide-react';

interface TopbarProps {
  currentRouteName?: string;
}

export const Topbar: React.FC<TopbarProps> = ({ currentRouteName = 'SOC Dashboard' }) => {
  return (
    <header className="h-16 bg-bg-darkest/90 backdrop-blur border-b border-surface-border px-6 flex items-center justify-between z-10 shrink-0">
      {/* Breadcrumb / Title */}
      <div className="flex items-center gap-3">
        <span className="text-xs text-text-muted font-mono uppercase tracking-wider">TRINETRA</span>
        <span className="text-text-muted">/</span>
        <h1 className="text-sm font-semibold text-text-primary tracking-wide">{currentRouteName}</h1>
      </div>

      {/* Center Global Search */}
      <div className="relative w-80 max-w-sm hidden md:block">
        <Search className="w-4 h-4 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
        <input
          type="text"
          placeholder="Search IOCs, domains, hashes, message-ids..."
          className="w-full bg-surface-default border border-surface-border text-xs rounded-full pl-9 pr-4 py-1.5 text-text-primary placeholder:text-text-muted focus:outline-none focus:border-teal-accent focus:shadow-teal-glow transition-all"
        />
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* Gmail Pub/Sub Status Badge */}
        <div className="flex items-center gap-2 bg-surface-default border border-surface-border px-2.5 py-1 rounded-full text-[11px] text-text-secondary">
          <ShieldCheck className="w-3.5 h-3.5 text-teal-accent" />
          <span>Gmail Pub/Sub: <span className="text-teal-accent font-semibold">Live</span></span>
        </div>

        {/* Notifications */}
        <button className="relative p-2 rounded-full hover:bg-surface-hover text-text-secondary hover:text-text-primary transition-colors">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-status-critical animate-pulse" />
        </button>

        {/* Analyst Profile */}
        <div className="flex items-center gap-2.5 border-l border-surface-border pl-4">
          <div className="w-8 h-8 rounded-full bg-surface-card border border-teal-accent/30 flex items-center justify-center text-teal-accent">
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="text-left text-xs leading-tight hidden lg:block">
            <div className="font-medium text-text-primary">SOC Analyst</div>
            <div className="text-[10px] text-text-muted font-mono">analyst@trinetra.ai</div>
          </div>
        </div>
      </div>
    </header>
  );
};
