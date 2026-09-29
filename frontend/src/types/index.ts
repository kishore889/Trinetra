export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DecisionType = 'ALLOW' | 'WARN' | 'QUARANTINE';
export type EmailProcessingState = 'RECEIVED' | 'PARSING' | 'ANALYZING' | 'ANALYZED' | 'ACTION_PENDING' | 'ACTIONED' | 'FAILED';

export interface ThreatDetection {
  id: string;
  severity: SeverityLevel;
  subject: string;
  sender: string;
  threatType: 'Credential Phishing' | 'Account Impersonation' | 'Malicious URL' | 'Payment Fraud' | 'Brand Impersonation' | 'Suspicious Attachment';
  riskScore: number;
  detectedAt: string;
  source: string;
  action: DecisionType;
}

export interface LiveEmail {
  id: string;
  sender: string;
  subject: string;
  receivedAt: string;
  riskScore: number;
  severity: SeverityLevel;
  threatSignals: string[];
  state: EmailProcessingState;
  action: DecisionType;
}

export interface MetricData {
  title: string;
  value: string | number;
  change?: string;
  isPositive?: boolean;
  iconName: string;
}
