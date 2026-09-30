import React, { useState, useEffect } from 'react';
import {
  RefreshCw,
  AlertOctagon,
  CheckCircle2,
  Clock,
  ShieldCheck,
  UploadCloud,
  Link as LinkIcon,
  Paperclip,
  Loader2,
  AlertTriangle,
  Mail,
  Search,
  Filter,
} from 'lucide-react';
import { ThreatBadge, DecisionBadge } from '../components/UIElements';

interface IngestedEmail {
  id: string;
  message_id: string;
  sender: string;
  sender_domain: string;
  recipient: string;
  subject: string;
  received_at: string;
  state: string;
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
  urls_count: number;
  attachments_count: number;
}

export const LiveEmailsPage: React.FC = () => {
  const [emails, setEmails] = useState<IngestedEmail[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [stateFilter, setStateFilter] = useState<string>('ALL');

  const fetchLiveEmails = async () => {
    try {
      setError(null);
      const res = await fetch('/api/v1/emails?limit=100');
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch live email stream.`);
      const data = await res.json();
      setEmails(data);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch live emails from backend');
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchLiveEmails();

    // Listen for SSE real-time events
    let sse: EventSource | null = null;
    try {
      sse = new EventSource('/api/v1/realtime/stream');
      sse.onmessage = () => {
        fetchLiveEmails();
      };
    } catch {}

    const interval = setInterval(fetchLiveEmails, 8000);
    return () => {
      if (sse) sse.close();
      clearInterval(interval);
    };
  }, []);

  const handleManualPoll = async () => {
    setIsRefreshing(true);
    try {
      await fetch('/api/v1/monitor/poll', { method: 'POST' });
      await fetchLiveEmails();
    } catch {
      await fetchLiveEmails();
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/v1/emails/ingest-raw', {
        method: 'POST',
        body: formData,
      });
      if (res.ok) {
        await fetchLiveEmails();
      } else {
        alert('File ingestion failed: Server returned error.');
      }
    } catch (err: any) {
      alert(`MIME Ingestion error: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  const filteredEmails = emails.filter((em) => {
    const matchesSearch =
      em.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      em.sender.toLowerCase().includes(searchTerm.toLowerCase()) ||
      em.recipient.toLowerCase().includes(searchTerm.toLowerCase()) ||
      em.message_id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesState = stateFilter === 'ALL' || em.state === stateFilter;
    return matchesSearch && matchesState;
  });

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Mail className="w-6 h-6 text-teal-accent" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              Live Email Ingestion & Stream Monitoring
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Zero-execution MIME parsing, technical authentication (SPF/DKIM/DMARC), and live ingestion monitoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label className="cursor-pointer flex items-center gap-2 bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-mono text-xs font-bold px-3.5 py-2 rounded transition-all shadow-teal-glow">
            <UploadCloud className="w-4 h-4" />
            <span>{isUploading ? 'Ingesting MIME...' : 'Ingest .EML File'}</span>
            <input type="file" accept=".eml,.msg,.txt" onChange={handleFileUpload} className="hidden" />
          </label>

          <button
            onClick={handleManualPoll}
            disabled={isRefreshing}
            className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Trigger Polling</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-3 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
        <div className="relative w-full sm:w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-text-muted" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by sender, subject, message ID..."
            className="w-full bg-bg-darkest border border-surface-border rounded-md pl-8 pr-3 py-1.5 text-text-primary focus:outline-none focus:border-teal-accent"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-3.5 h-3.5 text-text-muted" />
          <span className="text-text-muted uppercase text-[10px]">State:</span>
          <select
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
            className="bg-bg-darkest border border-surface-border rounded p-1.5 text-text-primary focus:outline-none focus:border-teal-accent"
          >
            <option value="ALL">All States ({emails.length})</option>
            <option value="RECEIVED">RECEIVED</option>
            <option value="ANALYZING">ANALYZING</option>
            <option value="QUARANTINED">QUARANTINED</option>
            <option value="RELEASED">RELEASED</option>
            <option value="SAFE">SAFE</option>
            <option value="REVIEW">REVIEW</option>
          </select>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="bg-surface-default border border-surface-border rounded-xl p-8 text-center font-mono text-teal-accent flex items-center justify-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Fetching live email stream from database...</span>
        </div>
      )}

      {/* Error State */}
      {error && !loading && (
        <div className="bg-status-critical/10 border border-status-critical/40 rounded-xl p-4 flex items-center justify-between text-xs font-mono text-status-critical">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            <span>{error}</span>
          </div>
          <button onClick={fetchLiveEmails} className="underline font-bold">Retry</button>
        </div>
      )}

      {/* Email List Table */}
      {!loading && !error && (
        <div className="bg-surface-default border border-surface-border rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-bg-darkest/70 text-text-muted uppercase text-[10px] border-b border-surface-border">
                <tr>
                  <th className="py-3 px-4">State</th>
                  <th className="py-3 px-4">Message ID</th>
                  <th className="py-3 px-4">Subject</th>
                  <th className="py-3 px-4">Sender</th>
                  <th className="py-3 px-4">Recipient</th>
                  <th className="py-3 px-4">SPF / DKIM / DMARC</th>
                  <th className="py-3 px-4">URLs</th>
                  <th className="py-3 px-4">Received</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {filteredEmails.map((em) => (
                  <tr key={em.id} className="hover:bg-surface-hover/80 transition-colors">
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        em.state === 'QUARANTINED' ? 'bg-status-critical/20 border-status-critical/50 text-status-critical' :
                        em.state === 'SAFE' || em.state === 'RELEASED' ? 'bg-teal-accent/20 border-teal-accent/50 text-teal-accent' :
                        em.state === 'REVIEW' ? 'bg-status-medium/20 border-status-medium/50 text-status-medium' :
                        'bg-surface-card border-surface-border text-text-secondary'
                      }`}>
                        {em.state}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-text-muted max-w-[140px] truncate">{em.message_id}</td>
                    <td className="py-3 px-4 text-text-primary font-bold max-w-xs truncate">{em.subject}</td>
                    <td className="py-3 px-4 text-teal-accent max-w-[180px] truncate">{em.sender}</td>
                    <td className="py-3 px-4 text-text-secondary max-w-[180px] truncate">{em.recipient}</td>
                    <td className="py-3 px-4 whitespace-nowrap text-[10px]">
                      <span className={`mr-1 px-1 rounded ${em.spf_result === 'pass' ? 'text-status-low bg-status-low/10' : 'text-status-critical bg-status-critical/10'}`}>
                        SPF:{em.spf_result || 'none'}
                      </span>
                      <span className={`mr-1 px-1 rounded ${em.dkim_result === 'pass' ? 'text-status-low bg-status-low/10' : 'text-status-critical bg-status-critical/10'}`}>
                        DKIM:{em.dkim_result || 'none'}
                      </span>
                      <span className={`px-1 rounded ${em.dmarc_result === 'pass' ? 'text-status-low bg-status-low/10' : 'text-status-critical bg-status-critical/10'}`}>
                        DMARC:{em.dmarc_result || 'none'}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="flex items-center gap-1 text-text-muted">
                        <LinkIcon className="w-3 h-3 text-teal-accent" />
                        {em.urls_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-text-muted whitespace-nowrap text-[11px]">
                      {new Date(em.received_at).toLocaleTimeString()}
                    </td>
                  </tr>
                ))}

                {filteredEmails.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-text-muted">
                      No emails found in live stream matching selected criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
