import type { ThreatDetection, LiveEmail } from '../types';

export const mockDetections: ThreatDetection[] = [
  {
    id: 'DET-9821',
    severity: 'CRITICAL',
    subject: 'Urgent: Verify Your Microsoft 365 Account Immediately',
    sender: 'security-update@micros0ft-support.com',
    threatType: 'Credential Phishing',
    riskScore: 94,
    detectedAt: '2 mins ago',
    source: 'Gmail Ingestion (Pub/Sub)',
    action: 'QUARANTINE'
  },
  {
    id: 'DET-9820',
    severity: 'HIGH',
    subject: 'Overdue Invoice #INV-88901 - Remittance Required',
    sender: 'billing@acc0unts-dept-corp.net',
    threatType: 'Payment Fraud',
    riskScore: 82,
    detectedAt: '14 mins ago',
    source: 'Gmail Ingestion (Pub/Sub)',
    action: 'QUARANTINE'
  },
  {
    id: 'DET-9819',
    severity: 'MEDIUM',
    subject: 'Shipping delivery failure: Update destination address',
    sender: 'notification@fedex-tracking-portal.info',
    threatType: 'Malicious URL',
    riskScore: 61,
    detectedAt: '42 mins ago',
    source: 'Gmail Ingestion (Pub/Sub)',
    action: 'WARN'
  },
  {
    id: 'DET-9818',
    severity: 'LOW',
    subject: 'Weekly Team Schedule & Project Roadmap Update',
    sender: 'alex.taylor@internal-org.com',
    threatType: 'Account Impersonation',
    riskScore: 18,
    detectedAt: '1 hour ago',
    source: 'Gmail Ingestion (Pub/Sub)',
    action: 'ALLOW'
  },
  {
    id: 'DET-9817',
    severity: 'CRITICAL',
    subject: 'Action Required: Bank of America wire transfer notification',
    sender: 'alert@bofa-security-auth.com',
    threatType: 'Brand Impersonation',
    riskScore: 97,
    detectedAt: '1.5 hours ago',
    source: 'Gmail Ingestion (Pub/Sub)',
    action: 'QUARANTINE'
  }
];

export const mockLiveEmails: LiveEmail[] = [
  {
    id: 'EML-10492',
    sender: 'security-update@micros0ft-support.com',
    subject: 'Urgent: Verify Your Microsoft 365 Account Immediately',
    receivedAt: '12:44:10',
    riskScore: 94,
    severity: 'CRITICAL',
    threatSignals: ['Lookalike Domain', 'Credential Harvest Pattern', 'SPF Hard Fail'],
    state: 'ACTIONED',
    action: 'QUARANTINE'
  },
  {
    id: 'EML-10493',
    sender: 'hr-portal@corp-survey-internal.org',
    subject: 'Mandatory Employee Benefits Enrollment Form',
    receivedAt: '12:45:02',
    riskScore: 78,
    severity: 'HIGH',
    threatSignals: ['Suspicious Redirect', 'Unverified DKIM'],
    state: 'ANALYZING',
    action: 'WARN'
  },
  {
    id: 'EML-10494',
    sender: 'news@techdigest-daily.com',
    subject: 'AI Breakthroughs in Cybersecurity 2026',
    receivedAt: '12:46:19',
    riskScore: 8,
    severity: 'LOW',
    threatSignals: ['Clean Reputation', 'Valid SPF/DKIM/DMARC'],
    state: 'ACTIONED',
    action: 'ALLOW'
  },
  {
    id: 'EML-10495',
    sender: 'payroll@global-payment-portal.ru',
    subject: 'Direct Deposit Account Update Needed',
    receivedAt: '12:47:33',
    riskScore: 89,
    severity: 'CRITICAL',
    threatSignals: ['High Risk TLD', 'Financial Urgency Keywords', 'Lookalike Sender'],
    state: 'ACTION_PENDING',
    action: 'QUARANTINE'
  }
];
