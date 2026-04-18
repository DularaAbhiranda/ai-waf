"""
vulnerable_app.py
-----------------
A deliberately vulnerable Flask web app used as the WAF's target for testing.

This app intentionally has security holes — DO NOT run in production.
Its purpose is to give the AI-WAF real HTTP traffic to intercept and classify.

Endpoints:
  GET  /                          — Home page
  GET  /products?id=<int>         — Product listing (SQLi vulnerable)
  GET  /search?q=<str>            — Search (XSS vulnerable)
  POST /login                     — Login form (SQLi + brute force vulnerable)
  GET  /file?name=<str>           — File viewer (path traversal vulnerable)
  GET  /ping?host=<str>           — Ping tool (command injection vulnerable)
  GET  /api/users                 — User list (info disclosure)
  POST /comment                   — Comment form (XSS vulnerable)

Run with:
    cd ai-waf/
    venv/Scripts/activate
    python tests/vulnerable_app.py
    # Runs on http://localhost:9090
"""

from flask import Flask, request, jsonify, make_response
import os

app = Flask(__name__)
app.secret_key = "totally-insecure-key-123"

# ── fake data ─────────────────────────────────────────────────────────────────
PRODUCTS = {
    1: {"name": "Laptop",     "price": 999.99,  "stock": 10},
    2: {"name": "Mouse",      "price": 29.99,   "stock": 50},
    3: {"name": "Keyboard",   "price": 79.99,   "stock": 30},
    4: {"name": "Monitor",    "price": 399.99,  "stock": 5},
}
USERS = [
    {"id": 1, "username": "admin",  "password": "admin123",   "role": "admin"},
    {"id": 2, "username": "alice",  "password": "alice456",   "role": "user"},
    {"id": 3, "username": "bob",    "password": "bob789",     "role": "user"},
]
COMMENTS = []


def page(title, body):
    """Render a simple HTML page."""
    return f"""
    <html>
    <head>
      <title>{title} — VulnShop</title>
      <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }}
        h1 {{ color: #e53e3e; }}
        nav a {{ margin-right: 16px; color: #3182ce; }}
        .card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; }}
        .warning {{ background: #fff5f5; border-color: #fc8181; padding: 8px 12px; border-radius: 4px; }}
        input, button {{ padding: 8px 12px; margin: 4px; }}
        button {{ background: #e53e3e; color: white; border: none; border-radius: 4px; cursor: pointer; }}
      </style>
    </head>
    <body>
      <h1>VulnShop</h1>
      <div class="warning">⚠️ This is a deliberately vulnerable test application for WAF testing</div>
      <nav>
        <a href="/">Home</a>
        <a href="/products?id=1">Products</a>
        <a href="/search?q=laptop">Search</a>
        <a href="/login">Login</a>
        <a href="/api/users">API Users</a>
      </nav>
      <hr/>
      <h2>{title}</h2>
      {body}
    </body>
    </html>
    """


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    body = """
    <p>Welcome to VulnShop — a deliberately insecure demo store.</p>
    <div class="card">
      <b>Try these pages:</b><br/>
      <a href="/products?id=1">Browse Products</a><br/>
      <a href="/search?q=mouse">Search</a><br/>
      <a href="/login">Login</a>
    </div>
    <div class="card">
      <form method="POST" action="/comment">
        <input name="text" placeholder="Leave a comment..." size="40"/>
        <button type="submit">Post</button>
      </form>
      <b>Comments:</b>
      """ + "".join(f"<p>• {c}</p>" for c in COMMENTS[-5:]) + """
    </div>
    """
    return page("Home", body)


@app.route("/products")
def products():
    """SQLi vulnerable — id is inserted directly."""
    product_id = request.args.get("id", "")
    # Simulate SQL query exposure (intentionally vulnerable)
    sim_query = f"SELECT * FROM products WHERE id = {product_id}"

    product = PRODUCTS.get(int(product_id)) if product_id.isdigit() else None
    if product:
        body = f"""
        <div class="card">
          <b>{product['name']}</b><br/>
          Price: ${product['price']}<br/>
          Stock: {product['stock']}
        </div>
        <p><small>Query: <code>{sim_query}</code></small></p>
        """
    else:
        body = f"""
        <p>No product found for id=<b>{product_id}</b></p>
        <p><small>Query: <code>{sim_query}</code></small></p>
        """
    return page("Product", body)


@app.route("/search")
def search():
    """XSS vulnerable — query is reflected without escaping."""
    q = request.args.get("q", "")
    results = [p for p in PRODUCTS.values() if q.lower() in p["name"].lower()]
    body = f"""
    <form><input name="q" value="{q}" size="30"/> <button>Search</button></form>
    <p>Results for: <b>{q}</b></p>
    """ + "".join(
        f'<div class="card">{p["name"]} — ${p["price"]}</div>' for p in results
    )
    return page("Search", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    """SQLi + brute force vulnerable."""
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Simulate vulnerable query
        sim_query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        # Simple check (not using the query — just simulated)
        user = next((u for u in USERS if u["username"] == username
                     and u["password"] == password), None)
        msg = f"<p style='color:green'>Welcome, {user['username']}!</p>" if user \
              else f"<p style='color:red'>Login failed. Query: <code>{sim_query}</code></p>"

    body = f"""
    <form method="POST">
      <input name="username" placeholder="Username" /><br/>
      <input name="password" type="password" placeholder="Password" /><br/>
      <button>Login</button>
    </form>
    {msg}
    """
    return page("Login", body)


@app.route("/file")
def file_view():
    """Path traversal vulnerable."""
    name = request.args.get("name", "readme.txt")
    safe_content = {
        "readme.txt": "Welcome to VulnShop v1.0",
        "about.txt":  "This is a test application.",
    }
    content = safe_content.get(name, f"[File not found: {name}]")
    body = f"""
    <form><input name="name" value="{name}" size="30"/> <button>View</button></form>
    <div class="card"><pre>{content}</pre></div>
    <p><small>Loading: <code>/var/www/html/{name}</code></small></p>
    """
    return page("File Viewer", body)


@app.route("/ping")
def ping():
    """Command injection vulnerable endpoint."""
    host = request.args.get("host", "")
    body = f"""
    <form><input name="host" value="{host}" size="30" placeholder="hostname"/> <button>Ping</button></form>
    <div class="card">
      <p>Simulated: <code>ping -c 1 {host}</code></p>
      <pre>[Ping output would appear here]</pre>
    </div>
    """
    return page("Ping Tool", body)


@app.route("/api/users")
def api_users():
    """Information disclosure — returns all users including passwords."""
    return jsonify(USERS)


@app.route("/comment", methods=["POST"])
def comment():
    """XSS via stored comment."""
    text = request.form.get("text", "")
    COMMENTS.append(text)          # stored without sanitisation
    return home()


@app.route("/health")
def health():
    return jsonify({"status": "ok", "app": "VulnShop"})


if __name__ == "__main__":
    print("=" * 55)
    print("  VulnShop — Deliberately Vulnerable Target App")
    print("  Running on http://localhost:9090")
    print("  Route traffic through WAF at http://localhost:8080")
    print("=" * 55)
    app.run(host="0.0.0.0", port=9090, debug=False)
