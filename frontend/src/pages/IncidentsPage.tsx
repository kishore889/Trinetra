import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  RefreshCw,
  Search,
  Filter,
  UserCheck,
  FileText,
  Loader2,
  ChevronRight,
} from 'lucide-react';
import { ThreatBadge } from '../components/UIElements';

interface IncidentItem {
  id: string;
  email_id: string;
  title: string;
  status: string;
  severity: string;
  summary?: string;
  resolution_notes?: string;
  created_at: string;
  updated_at: string;
}

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(null);
  const [newStatus, setNewStatus] = useState('RESOLVED');
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);

  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const resp = await fetch('/api/v1/incidents');
      if (resp.ok) {
        const data = await resp.json();
        setIncidents(data);
      }
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedIncident) return;

    setIsUpdating(true);
    try {
      const resp = await fetch(`/api/v1/incidents/${selectedIncident.id}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: newStatus,
          resolution_notes: resolutionNotes || 'Analyst resolved incident',
        }),
      });

      if (resp.ok) {
        setSelectedIncident(null);
        setResolutionNotes('');
        fetchIncidents();
      }
    } catch {
      alert('Failed to update incident status');
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-status-critical" />
            <h1 className="text-xl font-bold text-text-primary tracking-wide font-mono uppercase">
              SOC Incident Management & Response
            </h1>
          </div>
          <p className="text-xs text-text-secondary mt-1 font-mono">
            Track and resolve formal security incidents escalated from high-risk phishing detections.
          </p>
        </div>

        <button
          onClick={fetchIncidents}
          className="flex items-center gap-2 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent font-mono text-xs px-3.5 py-2 rounded transition-all"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Incidents</span>
        </button>
      </div>

      {loading && (
        <div className="bg-surface-default border border-surface-border rounded-xl p-8 text-center font-mono text-teal-accent flex items-center justify-center gap-2">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Loading security incidents...</span>
        </div>
      )}

      {!loading && (
        <div className="bg-surface-default border border-surface-border rounded-xl p-5 space-y-4">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-bg-darkest text-text-muted uppercase text-[10px] border-b border-surface-border">
                <tr>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Incident Title</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Summary</th>
                  <th className="p-3">Created</th>
                  <th className="p-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border font-sans">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-surface-hover/50 transition-colors font-mono">
                    <td className="p-3">
                      <ThreatBadge severity={inc.severity} />
                    </td>
                    <td className="p-3 font-bold text-text-primary max-w-xs truncate">{inc.title}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        inc.status === 'OPEN' ? 'bg-status-critical/20 border-status-critical/50 text-status-critical' :
                        inc.status === 'INVESTIGATING' ? 'bg-status-medium/20 border-status-medium/50 text-status-medium' :
                        'bg-teal-accent/20 border-teal-accent/50 text-teal-accent'
                      }`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="p-3 text-text-muted max-w-sm truncate">{inc.summary}</td>
                    <td className="p-3 text-text-muted text-[11px]">
                      {inc.created_at ? new Date(inc.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td className="p-3">
                      <button
                        onClick={() => {
                          setSelectedIncident(inc);
                          setNewStatus(inc.status);
                          setResolutionNotes(inc.resolution_notes || '');
                        }}
                        className="px-2.5 py-1 bg-surface-card border border-teal-accent/40 hover:border-teal-accent text-teal-accent text-[11px] font-bold rounded"
                      >
                        Manage
                      </button>
                    </td>
                  </tr>
                ))}

                {incidents.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-6 text-center text-text-muted font-mono">
                      No active security incidents recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Incident Manage Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <form onSubmit={handleUpdateStatus} className="bg-bg-dark border border-teal-accent/40 rounded-xl p-5 max-w-md w-full space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold text-teal-accent font-mono uppercase tracking-wider">
              Manage Incident: {selectedIncident.title}
            </h3>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Status</label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value)}
                  className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
              </div>

              <div>
                <label className="text-[10px] text-text-muted uppercase block mb-1">Resolution Notes</label>
                <textarea
                  value={resolutionNotes}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  placeholder="Enter notes on containment or resolution..."
                  rows={3}
                  className="w-full bg-bg-darkest border border-surface-border rounded p-2 text-text-primary focus:outline-none focus:border-teal-accent"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 text-xs font-mono text-text-muted border border-surface-border rounded"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isUpdating}
                className="px-4 py-2 text-xs font-mono font-bold bg-teal-accent hover:bg-teal-vibrant text-bg-darkest rounded shadow-teal-glow"
              >
                {isUpdating ? 'Saving...' : 'Update Incident'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
