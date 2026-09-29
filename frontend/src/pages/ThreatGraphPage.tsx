import React, { useMemo } from 'react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  Handle, 
  Position, 
  Node, 
  Edge 
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Mail, Globe, Server, ShieldAlert, Cpu } from 'lucide-react';

const CustomNode = ({ data }: { data: any }) => {
  return (
    <div className={`p-3 rounded-lg border bg-surface-default text-text-primary shadow-lg min-w-[140px] text-xs font-mono ${data.borderColor || 'border-teal-accent/40'}`}>
      <Handle type="target" position={Position.Top} className="!bg-teal-accent" />
      <div className="flex items-center gap-2 mb-1">
        {data.icon}
        <span className="font-bold text-[10px] text-text-muted uppercase">{data.type}</span>
      </div>
      <div className="text-xs truncate font-semibold">{data.label}</div>
      <div className="text-[10px] text-teal-accent mt-0.5">{data.risk}</div>
      <Handle type="source" position={Position.Bottom} className="!bg-teal-accent" />
    </div>
  );
};

export const ThreatGraphPage: React.FC = () => {
  const nodeTypes = useMemo(() => ({ custom: CustomNode }), []);

  const initialNodes: Node[] = [
    {
      id: 'email-1',
      type: 'custom',
      position: { x: 250, y: 30 },
      data: { 
        type: 'Email', 
        label: 'Urgent M365 Auth', 
        risk: 'Risk: 94/100', 
        borderColor: 'border-status-critical',
        icon: <Mail className="w-3.5 h-3.5 text-status-critical" /> 
      }
    },
    {
      id: 'sender-1',
      type: 'custom',
      position: { x: 80, y: 150 },
      data: { 
        type: 'Sender', 
        label: 'security-update@micros0ft', 
        risk: 'Spoofed Actor', 
        borderColor: 'border-status-high',
        icon: <Cpu className="w-3.5 h-3.5 text-status-high" /> 
      }
    },
    {
      id: 'domain-1',
      type: 'custom',
      position: { x: 80, y: 280 },
      data: { 
        type: 'Domain', 
        label: 'micros0ft-support.com', 
        risk: 'Lookalike Domain', 
        borderColor: 'border-status-critical',
        icon: <Globe className="w-3.5 h-3.5 text-status-critical" /> 
      }
    },
    {
      id: 'url-1',
      type: 'custom',
      position: { x: 420, y: 150 },
      data: { 
        type: 'URL', 
        label: 'auth-portal-micros0ft.online', 
        risk: 'Harvest Endpoint', 
        borderColor: 'border-status-critical',
        icon: <ShieldAlert className="w-3.5 h-3.5 text-status-critical" /> 
      }
    },
    {
      id: 'ip-1',
      type: 'custom',
      position: { x: 420, y: 280 },
      data: { 
        type: 'IP Infrastructure', 
        label: '185.220.101.5', 
        risk: 'Malicious ASN', 
        borderColor: 'border-status-high',
        icon: <Server className="w-3.5 h-3.5 text-status-high" /> 
      }
    },
  ];

  const initialEdges: Edge[] = [
    { id: 'e1', source: 'email-1', target: 'sender-1', label: 'SENT_BY', animated: true, style: { stroke: '#16D9D0' } },
    { id: 'e2', source: 'sender-1', target: 'domain-1', label: 'HOSTED_ON', style: { stroke: '#16D9D0' } },
    { id: 'e3', source: 'email-1', target: 'url-1', label: 'CONTAINS', animated: true, style: { stroke: '#FF5C67' } },
    { id: 'e4', source: 'url-1', target: 'ip-1', label: 'RESOLVES_TO', style: { stroke: '#16D9D0' } },
    { id: 'e5', source: 'domain-1', target: 'ip-1', label: 'SHARES_INFRASTRUCTURE', animated: true, style: { stroke: '#FF9F43' } },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-text-primary">Threat Intelligence Graph</h2>
          <p className="text-xs text-text-muted">NetworkX graph analysis mapping infrastructure, senders, domains, and campaigns</p>
        </div>
      </div>

      <div className="w-full h-[620px] bg-bg-darkest/90 border border-surface-border rounded-xl relative overflow-hidden">
        <ReactFlow
          nodes={initialNodes}
          edges={initialEdges}
          nodeTypes={nodeTypes}
          fitView
        >
          <Background color="#168F8A" gap={20} size={1} />
          <Controls className="!bg-surface-default !border-surface-border !text-text-primary" />
        </ReactFlow>
      </div>
    </div>
  );
};
