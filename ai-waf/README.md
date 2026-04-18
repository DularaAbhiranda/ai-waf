# AI-Powered Web Application Firewall (WAF)

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange?logo=scikit-learn)
![mitmproxy](https://img.shields.io/badge/Proxy-mitmproxy-green)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red?logo=streamlit)
![Tests](https://img.shields.io/badge/Tests-32%20unit%20%7C%2015%20E2E-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

A full-stack, AI-powered Web Application Firewall built entirely from scratch in Python. Every HTTP request passing through the proxy is scored in real time by a trained Random Forest classifier and either allowed or blocked — no static rule lists, just a model that learned from 61,065 real HTTP requests.

Tested live against **DVWA (Damn Vulnerable Web Application)** with **15/15 end-to-end tests passing** and **zero false positives**.

---

## What It Does

```
Browser / Client
      |
      |  HTTP request
      ▼
┌─────────────────────────────┐
│   WAF Proxy  (port 8080)    │
│                             │
│  1. Extract 15 features     │
│  2. Normalize with Scaler   │
│  3. RandomForest scores it  │
│  4. Pattern-override check  │
│  5. ALLOW ──or── BLOCK 403  │
└──────────┬──────────────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
Target App    SQLite DB  ──▶  Streamlit Dashboard
(DVWA :9090)  (events.db)     + Auto-Retrainer Daemon
```

---

## Features

- **Real-time HTTP interception** via mitmproxy — every request scored before it reaches the server
- **Random Forest classifier** trained on 61,065 real HTTP requests (CSIC 2010 dataset)
- **15 hand-engineered features** — structural URL metrics combined with regex-based attack pattern flags
- **Pattern-override safety rule** — prevents false positives on clean traffic with zero attack signatures
- **Live Streamlit dashboard** — 4 tabs covering traffic monitoring, attack analysis, auto-retraining, and model info
- **Auto-retraining daemon** — checks for drift every 30 min, retrains every 24h, only deploys if F1 improves
- **Drift detection** — Z-score on score distribution + block rate absolute difference monitoring
- **SHAP explainability** — feature importance plots showing why the model made each decision
- **Full test coverage** — 32 unit tests (pytest) + 15 live end-to-end tests against DVWA

---

## Model Performance

| Metric | Score |
|---|---|
| Accuracy | 87.82% |
| Precision | 81.47% |
| Recall | 91.02% |
| F1 Score | 85.98% |
| **ROC-AUC** | **96.21%** |
| CV F1 — 5-fold | 85.41% ± 0.17% |

Trained on 61,065 HTTP requests · Random Forest 200 trees · class\_weight='balanced' · StandardScaler

---

## Attack Coverage — 15/15 Live Tests Passed

| Attack Type | Payload Example | Result |
|---|---|---|
| SQL Injection | `' UNION SELECT 1,2,3--` | 🚫 BLOCKED |
| SQL Injection | `' OR '1'='1` | 🚫 BLOCKED |
| SQL Injection | `SLEEP(5)` blind | 🚫 BLOCKED |
| SQL Injection | `DROP TABLE users` | 🚫 BLOCKED |
| XSS | `<script>alert(document.cookie)</script>` | 🚫 BLOCKED |
| XSS | `<img onerror=alert(1)>` | 🚫 BLOCKED |
| XSS | `javascript:alert(1)` | 🚫 BLOCKED |
| Path Traversal | `../../etc/passwd` | 🚫 BLOCKED |
| Path Traversal | `%2e%2e%2fetc%2fshadow` | 🚫 BLOCKED |
| Command Injection | `127.0.0.1; cat /etc/passwd` | 🚫 BLOCKED |
| Command Injection | `127.0.0.1 \| whoami` | 🚫 BLOCKED |
| Null Byte | `file.php%00.jpg` | 🚫 BLOCKED |
| Normal page | `/login.php` | ✅ ALLOWED |
| Normal page | `/setup.php` | ✅ ALLOWED |
| Normal page | `/about.php` | ✅ ALLOWED |

---

## Dashboard — 4 Tabs

| Tab | What's Inside |
|---|---|
| 📡 **Live Traffic** | Request timeline, traffic split pie, ML score histogram, method breakdown, events table, blocked IPs |
| ⚔️ **Attack Analysis** | Attack type breakdown, score box plot (attack vs normal), attack KPIs, blocked request detail table |
| 🔄 **Auto-Retraining** | Drift KPIs, alerts, manual retrain button, F1 history chart, retrain log, archived models |
| 🤖 **Model Info** | Performance metric bars, full model config, all 15 features explained |

---

## Project Structure

```
ai-waf/
├── src/
│   ├── config.py               # Central settings — threshold, paths, ports
│   ├── data_parser.py          # Parse CSIC 2010 raw HTTP text files
│   ├── feature_extractor.py    # Build 15-feature vectors → data/processed.csv
│   ├── trainer.py              # Train RandomForest, 5-fold CV, save model
│   ├── evaluator.py            # Confusion matrix, ROC curve, SHAP plots
│   ├── proxy_interceptor.py    # mitmproxy addon — the WAF core
│   ├── logger.py               # Thread-safe SQLite event logger
│   ├── drift_detector.py       # Z-score + block rate drift checks
│   └── retrainer.py            # Auto-retrain daemon (24h cycle)
│
├── dashboard/
│   ├── app.py                  # Streamlit live dashboard (4 tabs)
│   └── simulate_traffic.py     # Inject realistic sample events into SQLite
│
├── tests/
│   ├── test_waf.py             # 32 unit tests (pytest) — all pass
│   ├── live_waf_test.py        # 15 live end-to-end tests vs DVWA
│   └── vulnerable_app.py       # Local Flask target app (backup)
│
├── data/                       # CSIC 2010 dataset — download separately
├── models/                     # Trained artifacts — generated locally
├── logs/                       # SQLite event DB — runtime generated
├── notebooks/
│   └── 01_eda.ipynb            # Exploratory data analysis
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| HTTP Proxy | mitmproxy + mitmdump |
| ML Model | scikit-learn — RandomForestClassifier |
| Data Processing | pandas, numpy |
| Model Persistence | joblib |
| Explainability | SHAP |
| Event Storage | SQLite (Python built-in) |
| Dashboard | Streamlit + Plotly |
| Target Test App | DVWA — Damn Vulnerable Web Application (Docker) |
| Unit Testing | pytest |
| Language | Python 3.11 |
| Training Data | CSIC 2010 HTTP Dataset (61,065 requests) |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Docker Desktop (for DVWA)

### 1. Clone and install

```bash
git clone https://github.com/DularaAbhiranda/ai-waf.git
cd ai-waf
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Mac / Linux
pip install -r requirements.txt
```

### 2. Get the dataset

Download the [CSIC 2010 HTTP Dataset](https://www.kaggle.com/datasets/issam87/csic2010) and put both files in `data/`:
```
data/normalTrafficTrain.txt
data/anomalousTrafficTest.txt
```

### 3. Train the model

```bash
python -m src.feature_extractor    # → data/processed.csv
python -m src.trainer              # → models/model_final.pkl
python -m src.evaluator            # → evaluation plots
```

### 4. Start DVWA (target app)

```bash
docker run -d -p 9090:80 --name dvwa vulnerables/web-dvwa
```

Wait ~10 seconds, then open `http://localhost:9090`

### 5. Run the full system

Open 3 terminals in the project root:

```bash
# Terminal 1 — WAF Proxy
venv\Scripts\activate
mitmdump -s src/proxy_interceptor.py --listen-port 8080

# Terminal 2 — Live Dashboard
venv\Scripts\activate
streamlit run dashboard/app.py
# → open http://localhost:8501

# Terminal 3 — Auto-Retrainer daemon
venv\Scripts\activate
python -m src.retrainer --daemon
```

### 6. Verify it works

```bash
venv\Scripts\activate
python tests/live_waf_test.py
# Expected: 15/15 PASSED
```

---

## How the Decision Works

```
Every HTTP request:

  Extract 15 features (URL length, path depth, has_sql, has_xss ...)
       ↓
  Normalize with StandardScaler
       ↓
  RandomForest → P(attack) score  [0.0 – 1.0]
       ↓
  Pattern-override check:
  if ALL attack flags == 0 AND special_chars < 3:
      → ALLOW  (prevents false positives on clean apps)
  else:
      score ≥ 0.5 → BLOCK 403
      score < 0.5 → ALLOW 200
       ↓
  Log to SQLite → Dashboard updates
```

---

## Running Tests

```bash
# 32 unit tests — no proxy needed
python -m pytest tests/test_waf.py -v

# 15 live end-to-end tests — proxy + DVWA must be running
python tests/live_waf_test.py
```

---

## How It Was Built — 6-Week Plan

| Week | What Was Built |
|---|---|
| 1 | Project setup, folder structure, config, dataset |
| 2 | Data parsing, feature engineering, EDA notebook |
| 3 | Model training, evaluation, SHAP explainability |
| 4 | mitmproxy interceptor, SQLite logger, live testing |
| 5 | Streamlit dashboard (4 tabs, Plotly charts) |
| 6 | Auto-retraining daemon, drift detection, final polish |

---

## Limitations

This is a **learning and portfolio project**, not a production system.

- Trained on CSIC 2010 — a 2010 Spanish e-commerce app. May need retraining for other apps.
- Runs as a forward proxy. A production WAF would sit as a reverse proxy in front of the server.
- No HTTPS/TLS inspection in current setup.
- Not hardened against adversarial evasion or high-volume traffic.
- Single-tenant — one model, one proxy, one database.

---

## Dataset

**CSIC 2010 HTTP Dataset** — Created by the Spanish National Research Council (CSIC) specifically for WAF evaluation. Contains 36,000 normal and 25,065 attack HTTP requests against a simulated e-commerce application. Available on [Kaggle](https://www.kaggle.com/datasets/issam87/csic2010).

---

## License

MIT — do whatever you want with it.
