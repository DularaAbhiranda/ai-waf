# AI-Powered Web Application Firewall (WAF)

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange?logo=scikit-learn)
![mitmproxy](https://img.shields.io/badge/Proxy-mitmproxy-green)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red?logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

A full-stack AI-powered Web Application Firewall built from scratch in Python. It intercepts every HTTP request through a proxy, scores it using a trained Random Forest classifier, and blocks threats like SQL injection, XSS, path traversal, and command injection in real time.

---

## Features

- **Real-time HTTP interception** via mitmproxy
- **Machine learning classifier** — Random Forest trained on 61,065 real HTTP requests (CSIC 2010 dataset)
- **15 engineered features** — structural URL metrics + regex-based attack pattern flags
- **Pattern-override safety rule** — prevents false positives on clean traffic
- **Live Streamlit dashboard** — traffic timeline, score distribution, block/allow breakdown, event table
- **Auto-retraining daemon** — retrains every 24h, compares F1 before swapping models
- **Drift detection** — Z-score + block rate monitoring with dashboard alerts
- **SHAP explainability** — feature importance plots to understand model decisions
- **Full test suite** — 32 unit tests + 15 live end-to-end tests against DVWA

---

## Model Performance

| Metric | Value |
|---|---|
| Accuracy | 87.82% |
| Precision | 81.47% |
| Recall | 91.02% |
| F1 Score | 85.98% |
| ROC-AUC | **96.21%** |
| CV F1 (5-fold) | 85.41% ± 0.17% |

---

## System Architecture

```
  Browser / curl
       |
       | HTTP (via proxy)
       v
+-------------------------+
|   mitmproxy :8080       |
|  proxy_interceptor.py   |
|                         |
|  1. Extract 15 features |
|  2. StandardScaler      |
|  3. RandomForest score  |
|  4. Pattern-override    |
|  5. ALLOW / BLOCK 403   |
+---+---+-----------------+
    |   |
    |   +-----> SQLite (events.db)
    |                |
    v                v
Target App     Streamlit Dashboard :8501
(DVWA :9090)   + Auto-Retrainer daemon
```

---

## Attack Coverage

| Attack Type | Example Payload | Result |
|---|---|---|
| SQL Injection | `' UNION SELECT 1,2,3--` | BLOCKED |
| SQL Injection | `' OR '1'='1` | BLOCKED |
| XSS | `<script>alert(document.cookie)</script>` | BLOCKED |
| XSS | `<img onerror=alert(1)>` | BLOCKED |
| Path Traversal | `../../etc/passwd` | BLOCKED |
| Path Traversal | `%2e%2e%2fetc%2fshadow` | BLOCKED |
| Command Injection | `127.0.0.1; cat /etc/passwd` | BLOCKED |
| Command Injection | `127.0.0.1 \| whoami` | BLOCKED |
| Null Byte | `file.php%00.jpg` | BLOCKED |

---

## Project Structure

```
ai-waf/
├── src/
│   ├── config.py               # Central settings (threshold, paths, ports)
│   ├── data_parser.py          # Parse CSIC 2010 raw HTTP text files
│   ├── feature_extractor.py    # Extract 15 features -> processed.csv
│   ├── trainer.py              # Train RandomForest, 5-fold CV, save model
│   ├── evaluator.py            # Confusion matrix, ROC, SHAP plots
│   ├── proxy_interceptor.py    # mitmproxy addon (WAF core)
│   ├── logger.py               # SQLite event logger (thread-safe)
│   ├── drift_detector.py       # Z-score + block rate drift detection
│   └── retrainer.py            # Auto-retrain daemon (24h cycle)
│
├── dashboard/
│   ├── app.py                  # Streamlit live dashboard
│   └── simulate_traffic.py     # Inject sample events into SQLite
│
├── tests/
│   ├── test_waf.py             # 32 unit tests (pytest)
│   ├── live_waf_test.py        # 15 live end-to-end tests vs DVWA
│   └── vulnerable_app.py       # Local Flask vulnerable app (backup target)
│
├── data/                       # Raw CSIC 2010 dataset (not tracked in git)
├── models/                     # Trained model artifacts (not tracked in git)
├── logs/                       # SQLite event DB (not tracked in git)
├── notebooks/
│   └── 01_eda.ipynb            # Exploratory data analysis
│
└── requirements.txt
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Proxy / Intercept | mitmproxy |
| ML Framework | scikit-learn (RandomForestClassifier) |
| Data Processing | pandas, numpy |
| Model Persistence | joblib |
| Explainability | SHAP |
| Event Storage | SQLite |
| Dashboard | Streamlit + Plotly |
| Target Test App | DVWA (Docker) |
| Unit Testing | pytest |
| Language | Python 3.11 |
| Dataset | CSIC 2010 HTTP Dataset (61,065 requests) |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker Desktop (for DVWA target app)

### 1. Clone and Install

```bash
git clone https://github.com/YOUR_USERNAME/ai-waf.git
cd ai-waf
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
```

### 2. Prepare the Dataset

Download the [CSIC 2010 HTTP Dataset](https://www.kaggle.com/datasets/issam87/csic2010) and place the files in `data/`:
```
data/normalTrafficTrain.txt
data/anomalousTrafficTest.txt
```

### 3. Train the Model

```bash
python -m src.feature_extractor   # Build features -> data/processed.csv
python -m src.trainer             # Train model   -> models/model_final.pkl
python -m src.evaluator           # Generate evaluation plots
```

### 4. Start DVWA (Target App)

```bash
docker run -d -p 9090:80 --name dvwa vulnerables/web-dvwa
```

Wait ~10 seconds then visit `http://localhost:9090`

### 5. Run the Full System (4 terminals)

**Terminal 1 — WAF Proxy**
```bash
venv\Scripts\activate
mitmdump -s src/proxy_interceptor.py --listen-port 8080
```

**Terminal 2 — Dashboard**
```bash
venv\Scripts\activate
streamlit run dashboard/app.py
```
Open `http://localhost:8501`

**Terminal 3 — Auto-Retrainer**
```bash
venv\Scripts\activate
python -m src.retrainer --daemon
```

**Terminal 4 — Run Live Tests**
```bash
venv\Scripts\activate
python tests/live_waf_test.py
```
Expected: `15 / 15 PASSED`

---

## Running the Test Suite

```bash
# Unit tests (32 tests, no proxy needed)
python -m pytest tests/test_waf.py -v

# Live end-to-end tests (requires proxy + DVWA running)
python tests/live_waf_test.py
```

---

## How It Works

### 1. Feature Extraction
Every HTTP request is converted into a 15-dimensional numeric vector:

| # | Feature | Description |
|---|---|---|
| 1 | method_is_post | 1 if POST, 0 otherwise |
| 2 | url_length | Total character length of URL |
| 3 | path_depth | Number of `/` in URL path |
| 4 | query_length | Length of query string |
| 5 | num_query_params | Number of `&` separated params |
| 6 | body_length | Length of request body |
| 7 | num_body_params | Number of body params |
| 8 | content_length | Content-Length header value |
| 9 | has_cookie | 1 if Cookie header present |
| 10 | has_sql | SQL pattern detected (regex) |
| 11 | has_xss | XSS pattern detected (regex) |
| 12 | has_path_traversal | `../` pattern detected (regex) |
| 13 | has_cmd_injection | Shell injection detected (regex) |
| 14 | has_null_byte | `%00` detected (regex) |
| 15 | special_char_count | Count of `< > ' " ; ( ) = \|` |

### 2. ML Scoring
Features are normalized with `StandardScaler` and scored by the `RandomForestClassifier`, which returns `P(attack)` — a probability between 0.0 and 1.0.

### 3. Pattern-Override Safety Rule
If all 5 attack pattern flags are 0 and `special_char_count < 3`, the request is always allowed regardless of the ML score. This prevents false positives on legitimate traffic from apps outside the training data distribution.

### 4. Decision
```
score >= 0.5  AND  any attack pattern detected  →  BLOCK (403)
score <  0.5  OR   no attack patterns           →  ALLOW (200)
```

### 5. Auto-Retraining
The daemon checks for drift every 30 minutes using Z-score on score distribution and absolute block rate difference. If drift is detected, it retrains and only deploys the new model if F1 improves. Old models are archived with a timestamp.

---

## Disclaimer

This is a **learning and portfolio project**. It is not a production-grade firewall and should not be used to protect real systems. It is not hardened against adversarial evasion, high traffic volumes, or real threat actors.

---

## Dataset

CSIC 2010 HTTP Dataset — generated by the Spanish National Research Council (CSIC) for WAF testing. Contains 36,000 normal and 25,065 attack HTTP requests targeting a simulated e-commerce web application.

---

## License

MIT License
