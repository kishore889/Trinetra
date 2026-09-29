import React, { useState } from 'react';
import { Bot, Send, ShieldCheck, Terminal, AlertTriangle, FileText, CheckCircle2 } from 'lucide-react';

export const CopilotPage: React.FC = () => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: 'Greetings Analyst. I am the TRINETRA SOC Co-Pilot. I assist in synthesizing multi-signal intelligence, explaining risk vectors, and drafting incident response actions. How can I assist with active telemetry today?'
    }
  ]);
  const [input, setInput] = useState('');

  const handleSend = () => {
    if (!input.trim()) return;
    const userMsg = input;
    setMessages((prev) => [...prev, { role: 'user', text: userMsg }]);
    setInput('');

    setTimeout(() => {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: `[TRINETRA Evidence Synthesis]\nAnalysis of query regarding: "${userMsg}"\n- Correlation Engine detects 2 shared indicators with Campaign #CAMP-08\n- Primary Vector: Typo-squatted credential portal\n- Recommended immediate action: Quarantine matching message threads across organization and add IP to firewall perimeter drop rule.`
        }
      ]);
    }, 600);
  };

  return (
    <div className="h-[calc(100vh-140px)] flex flex-col bg-surface-default border border-surface-border rounded-xl overflow-hidden shadow-teal-glow">
      <div className="p-4 border-b border-surface-border bg-bg-darkest flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-teal-accent/15 border border-teal-accent/40 flex items-center justify-center text-teal-accent">
            <Bot className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-text-primary">TRINETRA SOC Co-Pilot</h2>
            <p className="text-[10px] text-text-muted font-mono">Specialized Security Intelligence Assistant (Ground-Truth Evidence Only)</p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-teal-accent bg-teal-accent/10 px-2.5 py-1 rounded border border-teal-accent/20">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Evidence Integrity Verified</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4 font-sans text-xs">
        {messages.map((m, idx) => (
          <div key={idx} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-xl p-3.5 rounded-xl border whitespace-pre-line leading-relaxed ${
                m.role === 'user'
                  ? 'bg-teal-accent/20 text-text-primary border-teal-accent/40 rounded-br-none'
                  : 'bg-bg-darkest/80 text-text-secondary border-surface-border rounded-bl-none font-mono text-[11px]'
              }`}
            >
              {m.text}
            </div>
          </div>
        ))}
      </div>

      <div className="p-3 border-t border-surface-border bg-bg-darkest/70 flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          placeholder="Ask SOC Co-Pilot to summarize an incident, explain risk scores, or prepare an audit..."
          className="flex-1 bg-surface-default border border-surface-border rounded-lg px-3 py-2 text-xs text-text-primary focus:outline-none focus:border-teal-accent"
        />
        <button
          onClick={handleSend}
          className="bg-teal-accent hover:bg-teal-vibrant text-bg-darkest font-semibold px-4 rounded-lg flex items-center justify-center transition-colors"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
