import React, { useState, useEffect } from 'react';
import { RefreshCw, AlertOctagon, CheckCircle2, Clock, ShieldCheck, UploadCloud, Link as LinkIcon, Paperclip } from 'lucide-react';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';
import type { EmailProcessingState } from '../types';

interface IngestedEmail {
  id: string;
  message_id: string;
  sender: string;
  sender_domain: string;
  recipient: string;
  subject: string;
  received_at: string;
  state: EmailProcessingState;
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
  urls_count: number;
  attachments_count: number;
}

export const LiveEmailsPage: React.FC = () => {
  const [emails, setEmails] = useState<IngestedEmail[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isUploading, setIsUploading] = useState(false);

  const fetchLiveEmails = async () => {
    setIsRefreshing(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/emails?limit=50');
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) {
          setEmails(data);
          return;
        }
      }
    } catch {
      // offline / mock fallback
    } finally {
      setIsRefreshing(false);
    }

    // Default mock preview if backend inbox is empty
    setEmails([
      {
        id: 'mock-1',
        message_id: 'msg-9921@micros0ft-support.com',
        sender: 'security-update@micros0ft-support.com',
        sender_domain: 'micros0ft-support.com',
        recipient: 'cfo@company.com',
        subject: 'Urgent: Verify Your Microsoft 365 Account Immediately',
        received_at: new Date().toISOString(),
        state: 'ANALYZED',
        spf_result: 'FAIL',
        dkim_result: 'NONE',
        dmarc_result: 'FAIL',
        urls_count: 2,
        attachments_count: 0,
      },
      {
        id: 'mock-2',
        message_id: 'msg-9922@vendor-corp.net',
        sender: 'billing@vendor-corp.net',
        sender_domain: 'vendor-corp.net',
        recipient: 'accounts@company.com',
        subject: 'Remittance Advisory #INV-4921',
        received_at: new Date(Date.now() - 360000).toISOString(),
        state: 'ACTION_PENDING',
        spf_result: 'PASS',
        dkim_result: 'PASS',
        dmarc_result: 'PASS',
        urls_count: 1,
        attachments_count: 1,
      },
    ]);
  };

  useEffect(() => {
    fetchLiveEmails();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('http://localhost:8000/api/v1/emails/ingest-raw', {
        method: 'POST',
        body: formData,
      });
      if (res.ok) {
        await fetchLiveEmails();
      }
    } catch {
      // handled
    } finally {
      setIsUploading(false);
      e.target.value = '';
    }
  };

  const getStateBadge = (state: EmailProcessingState) => {
    const map: Record<EmailProcessingState, { label: string; color: string; icon: any }> = {
      RECEIVED: { label: 'Received', color: 'text-text-muted border-text-muted/30', icon: Clock },
      PARSING: { label: 'Parsing', color: 'text-teal-accent border-teal-accent/30', icon: RefreshCw },
      ANALYZING: { label: 'Analyzing', color: 'text-status-medium border-status-medium/30', icon: RefreshCw },
      ANALYZED: { label: 'Analyzed', color: 'text-teal-vibrant border-teal-vibrant/30', icon: CheckCircle2 },
      ACTION_PENDING: { label: 'Action Pending', color: 'text-status-high border-status-high/30', icon: AlertOctagon },
      ACTIONED: { label: 'Actioned', color: 'text-status-low border-status-low/30', icon: ShieldCheck },
      FAILED: { label: 'Failed', color: 'text-status-critical border-status-critical/30', icon: AlertOctagon },
    };
    const config = map[state] || map.RECEIVED;
    const Icon = config.icon;

    return (
      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono border ${config.color} bg-bg-darkest/40`}>
        <Icon className={`w-3 h-3 ${state === 'ANALYZING' || state === 'PARSING' ? 'animate-spin' : ''}`} />
        {config.label}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-text-primary tracking-wide">Live Email Ingestion & Telemetry</h2>
          <p className="text-xs text-text-muted">Real-time Gmail Pub/Sub push feed tracking multi-state processing</p>
        </div>
        <div className="flex items-center gap-3">
          {/* File Upload for .eml RFC 822 MIME Testing */}
          <label className="cursor-pointer flex items-center gap-2 bg-surface-card hover:bg-surface-hover border border-teal-accent/40 text-xs px-3 py-1.5 rounded-lg text-teal-accent transition-all shadow-teal-glow">
            <UploadCloud className="w-3.5 h-3.5" />
            <span>{isUploading ? 'Ingesting MIME...' : 'Ingest .EML File'}</span>
            <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} className="hidden" />
          </label>

          <button 
            onClick={fetchLiveEmails}
            className="flex items-center gap-2 bg-surface-default hover:bg-surface-hover border border-surface-border text-xs px-3 py-1.5 rounded-lg text-text-primary transition-all hover:border-teal-accent/50"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-teal-accent ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Refresh Feed</span>
          </button>
        </div>
      </div>

      <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-text-secondary">
            <thead className="bg-bg-darkest/60 text-text-muted font-mono uppercase tracking-wider text-[10px] border-b border-surface-border">
              <tr>
                <th className="py-3 px-4">Processing State</th>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">Sender</th>
                <th className="py-3 px-4">Domain</th>
                <th className="py-3 px-4">Auth (SPF/DKIM/DMARC)</th>
                <th className="py-3 px-4">IOC Entities</th>
                <th className="py-3 px-4">Ingested At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border font-sans">
              {emails.map((email) => (
                <tr key={email.id} className="hover:bg-surface-hover/80 transition-colors">
                  <td className="py-3 px-4 whitespace-nowrap">
                    {getStateBadge(email.state)}
                  </td>
                  <td className="py-3 px-4 font-medium text-text-primary max-w-sm truncate">
                    {email.subject}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-teal-accent/90 max-w-[180px] truncate">
                    {email.sender}
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-text-secondary">
                    {email.sender_domain}
                  </td>
                  <td className="py-3 px-4 font-mono text-[10px]">
                    <span className="flex items-center gap-1.5">
                      <span className={email.spf_result === 'PASS' ? 'text-status-low' : 'text-status-critical'}>
                        SPF:{email.spf_result || 'N/A'}
                      </span>
                      <span>•</span>
                      <span className={email.dkim_result === 'PASS' ? 'text-status-low' : 'text-status-critical'}>
                        DKIM:{email.dkim_result || 'N/A'}
                      </span>
                      <span>•</span>
                      <span className={email.dmarc_result === 'PASS' ? 'text-status-low' : 'text-status-critical'}>
                        DMARC:{email.dmarc_result || 'N/A'}
                      </span>
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-3 text-text-muted font-mono text-[11px]">
                      <span className="flex items-center gap-1" title="Extracted URLs">
                        <LinkIcon className="w-3 h-3 text-teal-accent" />
                        <span>{email.urls_count}</span>
                      </span>
                      <span className="flex items-center gap-1" title="Attachments (Metadata only)">
                        <Paperclip className="w-3 h-3 text-text-secondary" />
                        <span>{email.attachments_count}</span>
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-text-muted whitespace-nowrap">
                    {new Date(email.received_at).toLocaleTimeString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
