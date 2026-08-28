# PhishGuard AI — Capstone Project Report & Technical Architecture

## 1. Executive Summary & Problem Statement
Traditional cybersecurity threat scanners evaluate indicators of compromise (IoCs), static blacklists, or signature heuristics in isolation. This approach suffers from two systemic vulnerabilities:
1. **Zero-Day Blindspots**: Attackers frequently deploy ephemeral, freshly registered domains, randomized subdomains (DGA), and subtle punycode homoglyphs that evade traditional signature blacklists.
2. **The "One-Size-Fits-All" Flaw**: Human users exhibit vastly different cybersecurity literacy levels. High-tech security jargon overwhelms novice users, while vague warnings fail to provide actionable telemetry for technical analysts.

**PhishGuard AI** resolves these challenges by introducing an **Adaptive, Explainable Cybersecurity Platform** featuring:
- **Personalized Risk Scoring**: Combines multi-model inference (Phishing Random Forest/XGBoost + Zero-Day Isolation Forest + NLP Social Engineering Analysis) modulated by dynamic user risk multipliers.
- **Explainable AI (SHAP)**: Computes exact feature attributions for every prediction, producing human-readable explanations tailored to the user's demonstrated proficiency tier.
- **Adaptive Phishing Reflex Training**: Realistic simulation inbox that dynamically adjusts user vulnerability scores based on reaction time and reporting accuracy.
- **Pre-Click Defense Shield**: Browser-level protection modal that intercepts dangerous destination navigation before execution.
- **Crowdsourced Intelligence Feed & Spatial Threat Map**: Real-time Leaflet.js threat density mesh with cross-scan threat correlation.

---

## 2. Technical Architecture & Tech Stack

```
                     ┌──────────────────────────────────────────────┐
                     │          React + Vite + Tailwind CSS         │
                     │  (Chart.js Waterfall + Leaflet.js Heatmap)   │
                     └──────────────────────┬───────────────────────┘
                                            │ REST API (Bearer JWT)
                                            ▼
                     ┌──────────────────────────────────────────────┐
                     │              FastAPI Backend (v1)            │
                     │      - Pydantic v2 Schema Validation         │
                     │      - Decoupled Service Orchestrator        │
                     └───────┬──────────────┬──────────────┬────────┘
                             │              │              │
        ┌────────────────────┴──┐    ┌──────┴──────┐    ┌──┴──────────────────┐
        ▼                       ▼    ▼             ▼    ▼                     ▼
┌──────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│  Phishing Model  │ │  Zero-Day IF   │ │   TreeSHAP     │ │  Social Eng    │
│  (Random Forest) │ │(IsolationForest│ │(Explainable AI)│ │  (NLP Engine)   │
└──────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘
        │                       │               │               │
        └───────────────────────┼───────────────┼───────────────┘
                                │               │
                                ▼               ▼
                    ┌─────────────────┐ ┌─────────────────┐
                    │ MySQL Database  │ │ MongoDB Atlas   │
                    │ (Users, Scans,  │ │ (Raw Payloads,  │
                    │  Risk Logs)     │ │  SHAP Docs,     │
                    │                 │ │  Chat Memory)   │
                    └─────────────────┘ └─────────────────┘
```

---

## 3. Machine Learning & XAI Model Inventory

| Model Component | Algorithm / Framework | Training Data / Benchmark | Real Trained vs Mock |
|---|---|---|---|
| **Phishing Classifier** | Random Forest (100 Estimators) / Scikit-Learn | Calibrated UCI Phishing Websites & PhishTank lexical/structural feature distribution | **Real Trained Model** (Active inference) |
| **Zero-Day Anomaly Detector** | Isolation Forest (120 Estimators, Contamination 0.08) | High-dimensional normal web traffic distribution; flags statistical outliers in feature space | **Real Trained Model** (Active inference) |
| **Explainable AI (XAI)** | TreeSHAP (`shap.TreeExplainer`) | Computes exact marginal Shapley values for all 16 extracted feature vectors per target | **Real Trained Explainer** (Active calculation) |
| **Social Engineering NLP** | Multi-Tactic Heuristic NLP Matcher | Urgency, Authority, Fear, Scarcity, Financial Bait, Credential Harvesting Lexicons | **Real NLP Engine** (Active inference) |
| **Human Vulnerability Engine** | Exponential Decay & Penalty Algorithm | Dynamic state machine adapting on simulation reactions and click rates | **Real Behavioral Model** (Active state tracking) |
| **Cyber-Safety Chatbot** | Domain-Specific RAG Knowledge Engine + Gemini LLM fallback | NIST Cybersecurity Framework + OWASP Top Phishing Playbooks | **Real Hybrid Engine** (Active conversational memory in MongoDB) |

---

## 4. Dual-Database Schema

### MySQL Relational Tables (SQLAlchemy ORM)
- `users`: User identity, hashed bcrypt credentials, active risk profile tier (`Novice`, `Intermediate`, `Advanced`, `High-Risk`), vulnerability index (0.0 to 1.0).
- `scan_history`: User-isolated scan log (target, verdict, composite risk score, foreign key to user, MongoDB document pointers).
- `risk_score_logs`: Granular component weights (phishing probability, zero-day anomaly score, NLP score, user multiplier).
- `scam_reports`: Crowdsourced scam submissions with geocoded coordinates, categories, and moderation status.
- `community_threats`: Aggregated threat indicators with global outbreak counts.

### MongoDB Unstructured Collections (Motor Async)
- `scan_raw_data`: Full raw request payload, extracted 16-feature dictionary, model version metadata.
- `shap_explanations`: Full SHAP feature attribution objects, base values, personalized explanations, and tailored remediation steps.
- `chatbot_conversations`: Multi-turn conversational chat sessions, detected threat tags, and recommended remediation logs.
- `adaptive_learning_logs`: Simulation telemetry (response times, action types, vulnerability deltas).
- `community_intel_raw`: Raw incident descriptions and evidentiary screenshots.

---

## 5. Defense Flow & Acceptance Verification

1. **Pre-Click Interception**: Client queries `/api/v1/scan/pre-click`. If threat score $\ge 55$, a high-priority warning shield blocks navigation.
2. **Feature Extraction**: Real-time extraction of URL entropy (Shannon randomness), punycode homoglyphs, brand token spoofing, subdomains, and SSL cert validity.
3. **SHAP Waterfall Generation**: TreeSHAP generates positive risk drivers (e.g. `+0.38` for brand keywords) and negative risk mitigators (e.g. `-0.15` for domain age).
4. **Adaptive Simulation Feedback**: Users who report simulations in $<15\text{s}$ earn vulnerability index reductions (e.g. $0.40 \rightarrow 0.32$).
