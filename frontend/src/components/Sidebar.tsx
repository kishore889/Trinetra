import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldAlert, 
  Activity, 
  Database, 
  Share2, 
  Mail, 
  Search, 
  Lock, 
  AlertTriangle, 
  Bot, 
  Settings, 
  HeartPulse, 
  Sparkles,
  Eye
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navSections = [
    {
      title: 'OVERVIEW',
      items: [
        { name: 'Dashboard', path: '/', icon: Activity },
        { name: 'Analytics', path: '/analytics', icon: Database }
      ]
    },
    {
      title: 'THREAT INTELLIGENCE',
      items: [
        { name: 'Threats', path: '/threats', icon: ShieldAlert },
        { name: 'Threat Graph', path: '/graph', icon: Share2 }
      ]
    },
    {
      title: 'EMAIL SECURITY',
      items: [
        { name: 'Live Emails', path: '/live-emails', icon: Mail },
        { name: 'Investigations', path: '/investigations', icon: Search },
        { name: 'Quarantine', path: '/quarantine', icon: Lock }
      ]
    },
    {
      title: 'OPERATIONS',
      items: [
        { name: 'Incidents', path: '/incidents', icon: AlertTriangle },
        { name: 'SOC Co-Pilot', path: '/copilot', icon: Bot },
        { name: 'Demo Center', path: '/demo', icon: Sparkles }
      ]
    },
    {
      title: 'ADMINISTRATION',
      items: [
        { name: 'Gmail Connection', path: '/gmail', icon: Mail },
        { name: 'System Health', path: '/health', icon: HeartPulse },
        { name: 'Settings', path: '/settings', icon: Settings }
      ]
    }
  ];

  return (
    <aside className="w-64 bg-bg-dark border-r border-surface-border flex flex-col h-screen select-none shrink-0 z-20">
      <div className="h-16 flex items-center gap-3 px-5 border-b border-surface-border bg-bg-darkest">
        <div className="w-9 h-9 rounded-lg bg-teal-accent/10 border border-teal-accent/40 flex items-center justify-center text-teal-accent shadow-teal-glow">
          <Eye className="w-5 h-5 animate-pulse" />
        </div>
        <div>
          <span className="font-extrabold text-lg tracking-wider text-text-primary block leading-none">
            TRINETRA
          </span>
          <span className="text-[10px] tracking-widest text-teal-accent uppercase font-mono font-semibold">
            SOC INTELLIGENCE
          </span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-5">
        {navSections.map((section, idx) => (
          <div key={idx}>
            <div className="px-3 mb-2 text-[10px] font-mono tracking-wider text-text-muted font-bold uppercase">
              {section.title}
            </div>
            <div className="space-y-1">
              {section.items.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-all duration-150 ${
                        isActive
                          ? 'bg-teal-accent/15 text-teal-accent border border-teal-accent/30 shadow-teal-glow'
                          : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover'
                      }`
                    }
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.name}</span>
                  </NavLink>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="p-3 border-t border-surface-border bg-bg-darkest/70 flex items-center justify-between text-[11px] text-text-muted">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-status-low shadow-[0_0_8px_#38D39F]" />
          <span>Pipeline Active</span>
        </div>
        <span className="font-mono text-[10px]">v1.0.0</span>
      </div>
    </aside>
  );
};
