# TRINETRA — Machine Learning & Content Intelligence

TRINETRA uses a multi-stage **Content Intelligence Pipeline** combining TF-IDF vectorization, a Logistic Regression / Naive Bayes classifier, and rule-based heuristic intent extraction.

---

## Content Intelligence Pipeline

```
Raw Email Subject & Body
        │
        ▼
[ Text Cleaning & Normalization ] ──▶ Strip HTML tags, lowercasing, stopword removal
        │
        ▼
[ TF-IDF Feature Extraction ]     ──▶ Word & n-gram feature vectors (ngram_range=(1,2))
        │
        ▼
[ Machine Learning Classifier ]  ──▶ Probability score of phishing vs. legitimate
        │
        ▼
[ Heuristic Phishing Intent ]    ──▶ Urgency, credential requests, financial demands, links
        │
        ▼
[ Content Risk Score (0.0 - 1.0) ]
```

---

## Model Artifact Persistence

- **Vectorizer**: Saved to `models/tfidf_vectorizer.pkl`
- **Classifier**: Saved to `models/phishing_classifier.pkl`
- **Fallback**: If un-trained or during fresh startup, TRINETRA uses a calibrated heuristic content analyzer (`app/services/content_engine.py`) that scores content with zero external dependencies.

---

## Model Re-Training Workflow

Analyst feedback recorded in the **HITL Review Queue** (`TRUE_POSITIVE`, `FALSE_POSITIVE`, `TRUE_NEGATIVE`, `FALSE_NEGATIVE`) can be exported via `/api/v1/review/export` to generate retrained model checkpoints.

*Note: Per TRINETRA architectural rules, auto-retraining on single user clicks is prohibited to prevent data poisoning attacks.*
