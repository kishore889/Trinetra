# TRINETRA — Central Risk Engine & Decision Matrix

The **Central Risk Engine** aggregates signals from all 5 intelligence sub-layers into a unified risk score (0.0 to 1.0), confidence bound, and actionable decision (`ALLOW`, `WARN`, `QUARANTINE`).

---

## Weighted Risk Formula

$$\text{Final Risk Score} = \sum_{l \in \text{Layers}} w_l \cdot S_l$$

Where:

- $w_{\text{content}} = 0.25$ (Content NLP & Phishing Intent)
- $w_{\text{url}} = 0.30$ (URL Structure, Homoglyphs & Typo-Squatting)
- $w_{\text{identity}} = 0.20$ (Domain Age, Display Name Spoofing, SPF/DKIM/DMARC)
- $w_{\text{threat\_intel}} = 0.15$ (CERT-In, VirusTotal, Safe Browsing, Local IOCs)
- $w_{\text{graph}} = 0.10$ (Graph Infrastructure & Entity Correlation)

---

## Decision Threshold Matrix

| Risk Score Range | Decision Verdict | Automated Response Action |
| :--- | :--- | :--- |
| `0.00` – `0.39` | **`ALLOW`** | Inbox Delivery |
| `0.40` – `0.69` | **`WARN`** | Apply Security Warning Banner + Review Queue |
| `0.70` – `1.00` | **`QUARANTINE`** | Move to Gmail Trash/Quarantine + Apply TRINETRA Label |

*Note: All weights and decision thresholds are dynamically configurable at runtime via `/api/v1/risk/config` or environment variables.*
