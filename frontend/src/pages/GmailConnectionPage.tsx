import React, { useState, useEffect } from 'react';
import { 
  Mail, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  RefreshCw, 
  ExternalLink, 
  Lock, 
  Key, 
  Radio, 
  FileCode2,
  Trash2
} from 'lucide-react';
import { useSearchParams } from 'react-router-dom';

type ConnectionState = 'NOT_CONNECTED' | 'CONNECTING' | 'CONNECTED' | 'CONNECTION_ERROR' | 'DISCONNECTED';

interface AccountStatus {
  is_connected: boolean;
  email_address: string | null;
  account_id: string | null;
  watch_active: boolean;
  is_configured: boolean;
}

export const GmailConnectionPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [state, setState] = useState<ConnectionState>('NOT_CONNECTED');
  const [account, setAccount] = useState<AccountStatus>({
    is_connected: false,
    email_address: null,
    account_id: null,
    watch_active: false,
    is_configured: false,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchStatus = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/auth/google/status');
      if (res.ok) {
        const data: AccountStatus = await res.json();
        setAccount(data);
        if (data.is_connected) {
          setState('CONNECTED');
        } else {
          setState('NOT_CONNECTED');
        }
      } else {
        // Fallback for mock/offline UI testing
        setState('NOT_CONNECTED');
      }
    } catch {
      // Backend not running or unreachable
      setState('NOT_CONNECTED');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const urlStatus = searchParams.get('status');
    const emailParam = searchParams.get('email');
    const msgParam = searchParams.get('message');

    if (urlStatus === 'connected' && emailParam) {
      setState('CONNECTED');
      setAccount({
        is_connected: true,
        email_address: emailParam,
        account_id: 'GMAIL-ACC-99',
        watch_active: true,
        is_configured: true,
      });
    } else if (urlStatus === 'error') {
      setState('CONNECTION_ERROR');
      setErrorMessage(msgParam || 'Google OAuth consent failed or was cancelled.');
    } else {
      fetchStatus();
    }
  }, [searchParams]);

  const handleConnect = async () => {
    setState('CONNECTING');
    try {
      const res = await fetch('http://localhost:8000/api/v1/auth/google/url');
      if (res.ok) {
        const data = await res.json();
        window.location.href = data.authorization_url;
      } else {
        setState('CONNECTION_ERROR');
        setErrorMessage('Failed to retrieve OAuth authorization URL. Check if GOOGLE_CLIENT_ID is configured.');
      }
    } catch {
      setState('CONNECTION_ERROR');
      setErrorMessage('Backend API unreachable at http://localhost:8000. Ensure TRINETRA FastAPI server is running.');
    }
  };

  const handleDisconnect = async () => {
    setIsLoading(true);
    try {
      await fetch('http://localhost:8000/api/v1/auth/google/disconnect', { method: 'POST' });
    } catch {
      // proceed with local UI disconnect
    } finally {
      setState('DISCONNECTED');
      setAccount({
        is_connected: false,
        email_address: null,
        account_id: null,
        watch_active: false,
        is_configured: account.is_configured,
      });
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Title */}
      <div>
        <h2 className="text-base font-semibold text-text-primary tracking-wide">Gmail Ingestion & OAuth 2.0 Integration</h2>
        <p className="text-xs text-text-muted">
          Authorize TRINETRA with Google Workspace or Gmail to enable real-time Pub/Sub push ingestion.
        </p>
      </div>

      {/* Main Connection Status Card */}
      <div className="bg-surface-default border border-surface-border rounded-xl p-6 shadow-teal-glow">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-surface-border">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-teal-accent/15 border border-teal-accent/40 flex items-center justify-center text-teal-accent shadow-teal-glow shrink-0">
              <Mail className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-bold text-text-primary">Google Account Service Connector</span>
                {state === 'CONNECTED' && (
                  <span className="bg-status-low/20 text-status-low border border-status-low/40 px-2 py-0.5 rounded text-[10px] font-mono font-bold">
                    ACTIVE
                  </span>
                )}
                {state === 'CONNECTING' && (
                  <span className="bg-status-medium/20 text-status-medium border border-status-medium/40 px-2 py-0.5 rounded text-[10px] font-mono font-bold animate-pulse">
                    CONNECTING...
                  </span>
                )}
                {state === 'CONNECTION_ERROR' && (
                  <span className="bg-status-critical/20 text-status-critical border border-status-critical/40 px-2 py-0.5 rounded text-[10px] font-mono font-bold">
                    ERROR
                  </span>
                )}
                {(state === 'NOT_CONNECTED' || state === 'DISCONNECTED') && (
                  <span className="bg-text-muted/20 text-text-muted border border-text-muted/40 px-2 py-0.5 rounded text-[10px] font-mono font-bold">
                    NOT CONNECTED
                  </span>
                )}
              </div>

              {state === 'CONNECTED' && account.email_address ? (
                <div className="text-xs text-text-secondary font-mono mt-1">
                  Connected Account: <span className="text-teal-accent font-semibold">{account.email_address}</span>
                </div>
              ) : (
                <p className="text-xs text-text-muted leading-relaxed">
                  No Gmail account linked. Connect an account to ingest incoming emails via Gmail Watch & Pub/Sub.
                </p>
              )}
            </div>
          </div>

          {/* Action Button */}
          <div className="flex items-center gap-3">
            {state === 'CONNECTED' ? (
              <button
                onClick={handleDisconnect}
                disabled={isLoading}
                className="bg-surface-card hover:bg-status-critical/20 text-status-critical border border-status-critical/40 text-xs px-4 py-2 rounded-lg font-semibold flex items-center gap-2 transition-all"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Disconnect Account</span>
              </button>
            ) : (
              <button
                onClick={handleConnect}
                disabled={state === 'CONNECTING' || isLoading}
                className="bg-teal-accent hover:bg-teal-vibrant text-bg-darkest text-xs px-5 py-2 rounded-lg font-bold flex items-center gap-2 shadow-teal-glow transition-all disabled:opacity-50"
              >
                {state === 'CONNECTING' ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Redirecting to Google...</span>
                  </>
                ) : (
                  <>
                    <Key className="w-4 h-4" />
                    <span>Connect Gmail with Google</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Error Alert if needed */}
        {state === 'CONNECTION_ERROR' && (
          <div className="mt-4 p-3 bg-status-critical/15 border border-status-critical/40 rounded-lg text-xs text-status-critical flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>OAuth Connection Error: {errorMessage}</span>
          </div>
        )}

        {/* Security & Scopes Information */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-6">
          <div className="bg-surface-card border border-surface-border rounded-lg p-3.5">
            <div className="flex items-center gap-2 text-teal-accent text-xs font-semibold mb-1">
              <Lock className="w-3.5 h-3.5" />
              <span>Token Vault Encryption</span>
            </div>
            <p className="text-[11px] text-text-muted leading-relaxed">
              Tokens are encrypted at rest using AES-256 before storage. OAuth secrets are never sent to the browser.
            </p>
          </div>

          <div className="bg-surface-card border border-surface-border rounded-lg p-3.5">
            <div className="flex items-center gap-2 text-teal-accent text-xs font-semibold mb-1">
              <Radio className="w-3.5 h-3.5" />
              <span>Real-Time Ingestion</span>
            </div>
            <p className="text-[11px] text-text-muted leading-relaxed">
              Utilizes Gmail Watch & Google Cloud Pub/Sub push notifications for sub-second email event detection.
            </p>
          </div>

          <div className="bg-surface-card border border-surface-border rounded-lg p-3.5">
            <div className="flex items-center gap-2 text-teal-accent text-xs font-semibold mb-1">
              <FileCode2 className="w-3.5 h-3.5" />
              <span>Least Privilege Scopes</span>
            </div>
            <p className="text-[11px] text-text-muted leading-relaxed">
              Restricted exclusively to <code className="text-teal-accent">gmail.readonly</code>, <code className="text-teal-accent">gmail.modify</code>, and profile identity.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
