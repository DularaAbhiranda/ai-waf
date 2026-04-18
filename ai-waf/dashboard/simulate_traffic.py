"""
simulate_traffic.py
-------------------
Injects realistic-looking WAF events directly into the SQLite log so the
dashboard has data to display without needing a real mitmproxy session.

Simulates a mix of:
  - Normal browsing traffic (images, pages, forms)
  - SQL injection attempts
  - XSS attacks
  - Path traversal
  - Command injection

Run with:
    cd ai-waf/
    venv/Scripts/activate
    python dashboard/simulate_traffic.py [--n 200] [--delay 0.05]
"""

import sys, os, argparse, time, random
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pandas as pd
import joblib
from src.proxy_interceptor import extract_features_from_request, WafAddon
from src.logger import log_event, clear_all
from src.config import THRESHOLD

# ── traffic templates ─────────────────────────────────────────────────────────

NORMAL_REQUESTS = [
    ("GET",  "http://localhost:8080/tienda1/publico/vaciar.jsp?B2=Vaciar+carrito",
             "/tienda1/publico/vaciar.jsp",   "B2=Vaciar+carrito", ""),
    ("GET",  "http://localhost:8080/tienda1/publico/home.jsp",
             "/tienda1/publico/home.jsp",     "", ""),
    ("GET",  "http://localhost:8080/tienda1/imagenes/logo.jpg",
             "/tienda1/imagenes/logo.jpg",    "", ""),
    ("GET",  "http://localhost:8080/tienda1/publico/caracteristicas.jsp?idP=3",
             "/tienda1/publico/caracteristicas.jsp", "idP=3", ""),
    ("POST", "http://localhost:8080/tienda1/publico/autenticar.jsp",
             "/tienda1/publico/autenticar.jsp", "",
             "modo=entrar&login=alice&pwd=SecurePass1&remember=on&B1=Entrar"),
    ("GET",  "http://localhost:8080/tienda1/miembros/cuenta.jsp",
             "/tienda1/miembros/cuenta.jsp",  "", ""),
    ("GET",  "http://localhost:8080/tienda1/publico/registro.jsp?modo=registro",
             "/tienda1/publico/registro.jsp", "modo=registro", ""),
    ("GET",  "http://localhost:8080/tienda1/publico/listaproductos.jsp?categoria=2",
             "/tienda1/publico/listaproductos.jsp", "categoria=2", ""),
]

ATTACK_REQUESTS = [
    # SQL injection
    ("GET",
     "http://localhost:8080/tienda1/publico/anadir.jsp?id=2' UNION SELECT username,password FROM users--",
     "/tienda1/publico/anadir.jsp",
     "id=2' UNION SELECT username,password FROM users--", ""),
    ("POST",
     "http://localhost:8080/tienda1/publico/autenticar.jsp",
     "/tienda1/publico/autenticar.jsp", "",
     "login=admin'--&pwd=anything&B1=Entrar"),
    ("GET",
     "http://localhost:8080/tienda1/publico/caracteristicas.jsp?idP=1 OR 1=1",
     "/tienda1/publico/caracteristicas.jsp", "idP=1 OR 1=1", ""),
    # XSS
    ("POST",
     "http://localhost:8080/tienda1/publico/comentar.jsp",
     "/tienda1/publico/comentar.jsp", "",
     "comentario=<script>document.cookie</script>&B1=Enviar"),
    ("GET",
     "http://localhost:8080/tienda1/publico/buscar.jsp?q=<img src=x onerror=alert(1)>",
     "/tienda1/publico/buscar.jsp",
     "q=<img src=x onerror=alert(1)>", ""),
    # Path traversal
    ("GET",
     "http://localhost:8080/tienda1/publico/../../etc/passwd",
     "/tienda1/publico/../../etc/passwd", "", ""),
    ("GET",
     "http://localhost:8080/tienda1/publico/%2e%2e/%2e%2e/etc/shadow",
     "/tienda1/publico/%2e%2e/%2e%2e/etc/shadow", "", ""),
    # Command injection
    ("GET",
     "http://localhost:8080/tienda1/publico/ping.jsp?host=localhost;cat /etc/passwd",
     "/tienda1/publico/ping.jsp", "host=localhost;cat /etc/passwd", ""),
    # Null byte
    ("GET",
     "http://localhost:8080/tienda1/publico/file.jsp?name=../../etc/passwd%00.jpg",
     "/tienda1/publico/file.jsp", "name=../../etc/passwd%00.jpg", ""),
]

CLIENT_IPS = [
    "127.0.0.1", "192.168.1.10", "192.168.1.11",
    "10.0.0.5",  "172.16.0.3",   "203.0.113.42",  # attacker IPs
    "198.51.100.7", "192.0.2.1",
]

ATTACKER_IPS = CLIENT_IPS[5:]   # last 3 are "attackers"
NORMAL_IPS   = CLIENT_IPS[:5]


def simulate(n: int = 200, delay: float = 0.05, clear: bool = False):
    if clear:
        clear_all()
        print("Cleared existing events.")

    addon = WafAddon()
    import pandas as pd
    feature_cols = list(pd.read_csv("data/processed.csv").drop(columns=["label"]).columns)

    blocked = 0
    allowed = 0

    print(f"Simulating {n} requests (delay={delay}s) ...")

    for i in range(n):
        # 65% normal, 35% attack
        is_attack = random.random() < 0.35

        if is_attack:
            method, url, path, query, body = random.choice(ATTACK_REQUESTS)
            client_ip = random.choice(ATTACKER_IPS)
            headers   = {}
        else:
            method, url, path, query, body = random.choice(NORMAL_REQUESTS)
            client_ip = random.choice(NORMAL_IPS)
            headers   = {"cookie": f"JSESSIONID={''.join(random.choices('ABCDEF0123456789', k=32))}"}

        feats  = extract_features_from_request(method, url, path, query, body, headers)
        df_row = pd.DataFrame([feats], columns=feature_cols)
        score  = float(addon.model.predict_proba(addon.scaler.transform(df_row))[0][1])
        label  = 1 if score >= THRESHOLD else 0
        action = "BLOCK" if label == 1 else "ALLOW"

        log_event(method, url, path, score, label, action, client_ip)

        if action == "BLOCK":
            blocked += 1
        else:
            allowed += 1

        if (i + 1) % 50 == 0:
            print(f"  {i+1}/{n}  blocked={blocked}  allowed={allowed}")

        if delay > 0:
            time.sleep(delay)

    print(f"\nDone. Logged {n} events: {blocked} BLOCKED, {allowed} ALLOWED.")
    print(f"Block rate: {blocked/n*100:.1f}%")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate WAF traffic")
    parser.add_argument("--n",     type=int,   default=200,  help="Number of requests")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between requests (s)")
    parser.add_argument("--clear", action="store_true",      help="Clear existing events first")
    args = parser.parse_args()

    simulate(n=args.n, delay=args.delay, clear=args.clear)
