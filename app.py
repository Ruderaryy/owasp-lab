from flask import Flask, render_template, request, jsonify, g
import sqlite3
import bcrypt
from collections import defaultdict
import time

app = Flask(__name__)
app.secret_key = "owasp-learn-secret"

# Simple in-memory attempt tracker
login_attempts = defaultdict(list)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect("demo.db")
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def seed():
    db = sqlite3.connect("demo.db")
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, salary INTEGER)")
    db.execute("CREATE TABLE IF NOT EXISTS users_plain (username TEXT PRIMARY KEY, password TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS users_hashed (username TEXT PRIMARY KEY, password TEXT)")
    db.execute("DELETE FROM users")
    db.execute("INSERT INTO users VALUES (1,'alice','pass123','user',50000)")
    db.execute("INSERT INTO users VALUES (2,'bob','pass456','user',60000)")
    db.execute("INSERT INTO users VALUES (3,'admin','admin123','admin',99999)")
    db.commit()
    db.close()

@app.route("/")
def index():
    return render_template("index.html")

# ── A01: Broken Access Control ──────────────────────────────────────────────
@app.route("/a01")
def a01():
    return render_template("vulnerabilities/a01_broken_access_control.html")

# VULNERABLE — no check, any user_id works
@app.route("/a01/vulnerable/profile")
def a01_vuln():
    uid = request.args.get("id", 1)
    user = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if user:
        return jsonify({"id": user["id"], "username": user["username"],
                        "role": user["role"], "salary": user["salary"]})
    return jsonify({"error": "Not found"}), 404

# SECURE — only your own profile
@app.route("/a01/secure/profile")
def a01_secure():
    logged_in_as = 1  # pretend alice is logged in
    requested_id = int(request.args.get("id", 1))
    if requested_id != logged_in_as:
        return jsonify({"error": "🚫 Access Denied — you can only view your own profile."}), 403
    user = get_db().execute("SELECT id, username, role, salary FROM users WHERE id=?",
                            (logged_in_as,)).fetchone()
    return jsonify(dict(user))

# ----------------------------------------------------------------------------------------------------------------------------

# ── A02: Security Misconfiguration ──────────────────────────────────────────
@app.route("/a02")
def a02():
    return render_template("vulnerabilities/a02_security_misconfiguration.html")

# VULNERABLE — exposes full stack trace + internal info
@app.route("/a02/vulnerable/user")
def a02_vuln():
    uid = request.args.get("id")
    #  No input validation, crashes with full debug info exposed
    user = get_db().execute("SELECT * FROM users WHERE id=?", (int(uid),)).fetchone()
    if not user:
        raise Exception(f"User {uid} not found. DB path: demo.db, Table: users, Server: Flask/Python")
    return jsonify(dict(user))

# SECURE — generic error, no internal details
@app.route("/a02/secure/user")
def a02_secure():
    uid = request.args.get("id")
    try:
        if not uid or not uid.isdigit():
            return jsonify({"error": "Invalid request."}), 400
        user = get_db().execute("SELECT * FROM users WHERE id=?", (int(uid),)).fetchone()
        if not user:
            return jsonify({"error": "User not found."}), 404
        return jsonify(dict(user))
    except Exception:
        # ✅ Log internally, return generic message
        return jsonify({"error": "Something went wrong. Please try again."}), 500
    
# ----------------------------------------------------------------------------------------------------------------------------

# ── A03: Software Supply Chain Failures ─────────────────────────────────────
@app.route("/a03")
def a03():
    return render_template("vulnerabilities/a03_supply_chain.html")

@app.route("/a03/vulnerable/process", methods=["POST"])
def a03_vuln():
    data = request.get_json(force=True)
    user_input = data.get("text", "")
    malicious_log = f"[EXFILTRATED] User data sent to attacker.com: '{user_input}'"
    result = user_input.upper()
    return jsonify({
        "result": result,
        "malicious_side_effect": malicious_log
    })

@app.route("/a03/secure/process", methods=["POST"])
def a03_secure():
    data = request.get_json(force=True)
    user_input = data.get("text", "")
    result = user_input.upper()
    return jsonify({"result": result})

# ----------------------------------------------------------------------------------------------------------------------------

# ── A04: Cryptographic Failures ─────────────────────────────────────────────
@app.route("/a04")
def a04():
    return render_template("vulnerabilities/a04_cryptographic_failures.html")

# VULNERABLE — stores and checks plaintext passwords
@app.route("/a04/vulnerable/register", methods=["POST"])
def a04_vuln_register():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    #  Storing password as plain text
    get_db().execute("INSERT OR REPLACE INTO users_plain VALUES (?,?)", (username, password))
    get_db().commit()
    return jsonify({
        "message": "User registered!",
        "stored_as": password  # showing what's actually in DB
    })

@app.route("/a04/vulnerable/login", methods=["POST"])
def a04_vuln_login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    #  Direct plaintext comparison
    user = get_db().execute(
        "SELECT * FROM users_plain WHERE username=? AND password=?",
        (username, password)
    ).fetchone()
    if user:
        return jsonify({"message": f"Welcome {username}!", "password_in_db": user["password"]})
    return jsonify({"error": "Invalid credentials"}), 401

# SECURE — bcrypt hashed passwords
@app.route("/a04/secure/register", methods=["POST"])
def a04_secure_register():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    #  Hash with bcrypt before storing
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    get_db().execute("INSERT OR REPLACE INTO users_hashed VALUES (?,?)", (username, hashed))
    get_db().commit()
    return jsonify({
        "message": "User registered!",
        "stored_as": hashed  # showing the hash, not the real password
    })

@app.route("/a04/secure/login", methods=["POST"])
def a04_secure_login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    user = get_db().execute(
        "SELECT * FROM users_hashed WHERE username=?", (username,)
    ).fetchone()
    if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
        #  bcrypt compares safely, never exposes the hash
        return jsonify({"message": f"Welcome {username}! Password verified securely."})
    return jsonify({"error": "Invalid credentials"}), 401

# ----------------------------------------------------------------------------------------------------------------------------

# ── A05: Injection (SQL Injection) ──────────────────────────────────────────
@app.route("/a05")
def a05():
    return render_template("vulnerabilities/a05_injection.html")

# VULNERABLE — string formatting directly into SQL query
@app.route("/a05/vulnerable/login", methods=["POST"])
def a05_vuln_login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    #  Direct string interpolation — attacker controls the query!
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        user = get_db().execute(query).fetchone()
        if user:
            return jsonify({
                "message": f" Logged in as {user['username']} (role: {user['role']})",
                "query_executed": query
            })
        return jsonify({
            "message": " Invalid credentials",
            "query_executed": query
        }), 401
    except Exception as e:
        return jsonify({"error": str(e), "query_executed": query}), 500

# SECURE — parameterized queries
@app.route("/a05/secure/login", methods=["POST"])
def a05_secure_login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    #  Parameterized query — user input never touches the SQL structure
    user = get_db().execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    ).fetchone()
    if user:
        return jsonify({"message": f" Logged in as {user['username']} (role: {user['role']})"})
    return jsonify({"message": " Invalid credentials"}), 401

# ----------------------------------------------------------------------------------------------------------------------------

# ── A06: Insecure Design ─────────────────────────────────────────────────────
@app.route("/a06")
def a06():
    return render_template("vulnerabilities/a06_insecure_design.html")

# VULNERABLE — no rate limiting, unlimited login attempts
@app.route("/a06/vulnerable/login", methods=["POST"])
def a06_vuln_login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    user = get_db().execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    ).fetchone()
    if user:
        return jsonify({"message": f"✅ Logged in as {user['username']}!"})
    #  No tracking, no lockout — attacker can try forever
    return jsonify({"message": " Invalid credentials. Try again."}), 401

# SECURE — rate limiting: max 5 attempts per IP per minute
@app.route("/a06/secure/login", methods=["POST"])
def a06_secure_login():
    ip = request.remote_addr
    now = time.time()

    # Clean attempts older than 60 seconds
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < 60]

    #  Block if too many attempts
    if len(login_attempts[ip]) >= 5:
        wait = int(60 - (now - login_attempts[ip][0]))
        return jsonify({
            "error": f" Too many attempts. Try again in {wait} seconds.",
            "attempts": len(login_attempts[ip])
        }), 429

    login_attempts[ip].append(now)

    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    user = get_db().execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    ).fetchone()
    if user:
        login_attempts[ip] = []  # reset on success
        return jsonify({
            "message": f"✅ Logged in as {user['username']}!",
            "attempts_used": len(login_attempts[ip])
        })
    return jsonify({
        "message": " Invalid credentials.",
        "attempts_remaining": 5 - len(login_attempts[ip])
    }), 401

# ----------------------------------------------------------------------------------------------------------------------------

if __name__ == "__main__":
    seed()
    app.run(debug=True)