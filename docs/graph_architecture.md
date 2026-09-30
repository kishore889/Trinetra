# TRINETRA — Graph Intelligence Architecture

The **Graph Intelligence Engine** models entities (senders, recipient mailboxes, domains, IP addresses, URLs, attachments) and their structural relationships using **NetworkX** (with native support for **Neo4j** in cloud environments).

---

## Entity-Relationship Graph Schema

```
(Sender: "attacker@fake-bank.com") ──[SENT]──► (Email: "Msg-102")
        │                                           │
  [HAS_DOMAIN]                                  [CONTAINS_URL]
        ▼                                           ▼
(Domain: "fake-bank.com")                   (URL: "http://185.220.101.4/login")
        │                                           │
  [RESOLVES_TO]                                [HOSTED_ON]
        └───────────────────► (IP: "185.220.101.4") ◄┘
```

---

## Graph Correlation Capabilities

1. **Shared Infrastructure Detection**: Identifies multiple distinct senders using the same suspicious IP address or hosting server.
2. **Campaign Discovery**: Correlates across multiple emails to discover coordinated phishing campaigns targeting multiple organizational mailboxes.
3. **Graph Risk Score Calculation**: Computes centrality metrics, high-risk entity degree, and propagation paths to output a `graph_risk` sub-score (0.0 to 1.0).
