# CSIC 2010 HTTP Dataset

## What is it?
The CSIC 2010 dataset contains HTTP requests generated for an e-commerce web application.
It is widely used for training and evaluating web intrusion detection and WAF systems.

- ~36,000 normal requests
- ~25,000 anomalous requests (SQLi, XSS, buffer overflow, CSRF, etc.)

## How to Download

### Option 1 — Official Source
1. Go to: https://www.tic.itefi.csic.es/dataset/data/
2. Request access or download directly (the dataset is publicly available for research).
3. Download the files:
   - `normalTrafficTraining.txt`
   - `normalTrafficTest.txt`
   - `anomalousTrafficTest.txt`

### Option 2 — Kaggle Mirror (easier)
1. Go to: https://www.kaggle.com/datasets/deeplearner001/csic-2010-http-dataset
2. Download the ZIP archive.
3. Extract it.

## Where to Place the Files
Place all downloaded files in this `data/` folder:

```
ai-waf/
└── data/
    ├── normalTrafficTraining.txt
    ├── normalTrafficTest.txt
    └── anomalousTrafficTest.txt
```

## File Format
Each file contains raw HTTP requests separated by blank lines. Example:

```
GET /tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n+Ib%E9rico&precio=... HTTP/1.1
User-Agent: Mozilla/5.0
Pragma: no-cache
Cache-control: no-cache
Accept: text/xml,application/xml,...
Accept-Language: es
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Host: localhost:8080
Connection: keep-alive
```

## Next Step
After placing the files, run the preprocessing notebook in `notebooks/` to parse and
convert these raw HTTP requests into a structured CSV for ML training.
