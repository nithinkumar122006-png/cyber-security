import os
import re
import socket
import hashlib
import secrets
import string
from datetime import datetime
from urllib.parse import urlparse

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "CHANGE-THIS-SECRET-BEFORE-DEPLOYMENT")
CORS(app, supports_credentials=True)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cybersecurity_management"),
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def current_user():
    return session.get("user")

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Please log in first."}), 401
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    try:
        conn = get_db()
        conn.close()
        return jsonify({"status": "ok", "database": "connected"})
    except mysql.connector.Error as exc:
        return jsonify({"status": "error", "database": "not connected",
                        "detail": str(exc)}), 503

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("full_name") or "").strip()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not name or not username or not email or len(password) < 8:
        return jsonify({"error": "Enter all fields. Password must contain at least 8 characters."}), 400
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter a valid email address."}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        is_first = cur.fetchone()[0] == 0
        role = "admin" if is_first else "user"
        cur.execute(
            "INSERT INTO users (full_name, username, email, password_hash, role) VALUES (%s,%s,%s,%s,%s)",
            (name, username, email, generate_password_hash(password), role)
        )
        conn.commit()
        user_id = cur.lastrowid
        cur.close()
        conn.close()
        session["user"] = {"id": user_id, "name": name, "username": username, "role": role}
        return jsonify({"message": "Account created.", "user": session["user"]})
    except mysql.connector.IntegrityError:
        return jsonify({"error": "Username or email already exists."}), 409
    except mysql.connector.Error as exc:
        return jsonify({"error": f"Database error: {exc}"}), 503

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    identity = (data.get("identity") or "").strip()
    password = data.get("password") or ""
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username=%s OR email=%s LIMIT 1", (identity, identity.lower()))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row or not check_password_hash(row["password_hash"], password):
            return jsonify({"error": "Invalid username/email or password."}), 401
        session["user"] = {"id": row["id"], "name": row["full_name"],
                           "username": row["username"], "role": row["role"]}
        return jsonify({"message": "Logged in.", "user": session["user"]})
    except mysql.connector.Error as exc:
        return jsonify({"error": f"Database error: {exc}"}), 503

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out."})

@app.get("/api/me")
def me():
    if not current_user():
        return jsonify({"user": None})
    return jsonify({"user": current_user()})

@app.get("/api/stats")
@login_required
def stats():
    user = current_user()
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=%s", (user["id"],))
        scans = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scan_history WHERE user_id=%s AND result_status='Warning'", (user["id"],))
        warnings = cur.fetchone()[0]
        cur.close()
        conn.close()
        return jsonify({"scans": scans, "warnings": warnings, "modules": 8})
    except mysql.connector.Error as exc:
        return jsonify({"error": str(exc)}), 503

def save_scan(scan_type, target, status, summary):
    user = current_user()
    if not user:
        return
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scan_history (user_id, scan_type, target, result_status, result_summary) VALUES (%s,%s,%s,%s,%s)",
            (user["id"], scan_type, target[:500] if target else None, status, summary[:4000])
        )
        conn.commit()
        cur.close()
        conn.close()
    except mysql.connector.Error:
        pass

@app.post("/api/password/analyze")
@login_required
def analyze_password():
    password = (request.get_json(silent=True) or {}).get("password", "")
    if not isinstance(password, str) or not password:
        return jsonify({"error": "Enter a password to analyse."}), 400
    checks = {
        "At least 12 characters": len(password) >= 12,
        "Uppercase letter": bool(re.search(r"[A-Z]", password)),
        "Lowercase letter": bool(re.search(r"[a-z]", password)),
        "Number": bool(re.search(r"\d", password)),
        "Special character": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    score = sum(checks.values())
    strength = "Very strong" if score == 5 else "Strong" if score == 4 else "Moderate" if score == 3 else "Weak"
    tips = [label for label, passed in checks.items() if not passed]
    # Never store or log the supplied password.
    return jsonify({"strength": strength, "score": score, "checks": checks, "tips": tips})

@app.get("/api/password/generate")
@login_required
def generate_password():
    length = min(max(request.args.get("length", default=18, type=int), 12), 64)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password) and any(c in "!@#$%^&*()-_=+" for c in password)):
            return jsonify({"password": password})

@app.post("/api/url/check")
@login_required
def check_url():
    raw = ((request.get_json(silent=True) or {}).get("url") or "").strip()
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({"error": "Enter a valid http or https URL."}), 400
    host = parsed.hostname.lower()
    flags = []
    if parsed.scheme == "http":
        flags.append("The URL uses HTTP rather than encrypted HTTPS.")
    if parsed.username or parsed.password:
        flags.append("The URL contains embedded login information.")
    if len(raw) > 100:
        flags.append("The URL is unusually long.")
    if "xn--" in host:
        flags.append("The hostname contains punycode; verify the spelling carefully.")
    if host.count("-") >= 3:
        flags.append("The hostname contains several hyphens.")
    if re.search(r"(login|verify|update|secure|account|banking)", host):
        flags.append("The hostname uses words commonly seen in deceptive links.")
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        flags.append("The URL uses an IP address instead of a recognizable domain.")
    status = "Warning" if flags else "Informational"
    summary = " ".join(flags) if flags else "No obvious suspicious pattern was detected by this basic local heuristic."
    save_scan("URL check", raw, status, summary)
    return jsonify({"status": status, "flags": flags,
                    "note": "This is a basic pattern check, not a reputation lookup or guarantee that a site is safe."})

@app.post("/api/file/hash")
@login_required
def file_hash():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return jsonify({"error": "Choose a file first."}), 400
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = upload.stream.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > 20 * 1024 * 1024:
            return jsonify({"error": "File exceeds the 20 MB limit."}), 413
        digest.update(chunk)
    sha = digest.hexdigest()
    save_scan("File hash", upload.filename, "Informational", f"SHA-256: {sha}; size: {total} bytes")
    return jsonify({"filename": upload.filename, "size": total, "sha256": sha,
                    "note": "This calculates a file fingerprint only. It does not determine whether the file is malware."})

@app.post("/api/network/check")
@login_required
def network_check():
    host = ((request.get_json(silent=True) or {}).get("host") or "").strip()
    # Restrict this basic connectivity check to localhost/private IPs or localhost names.
    try:
        ip = socket.gethostbyname(host)
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if not (addr.is_private or addr.is_loopback or addr.is_link_local):
            return jsonify({"error": "For safety, this tool only checks localhost or private/local network addresses."}), 400
        with socket.create_connection((ip, 80), timeout=2):
            reachable = True
    except (OSError, ValueError):
        reachable = False
        ip = "unresolved"
    result = "Reachable on TCP port 80" if reachable else "No connection on TCP port 80 (or host unavailable)"
    save_scan("Network check", host, "Informational", result)
    return jsonify({"host": host, "resolved_ip": ip, "result": result,
                    "note": "This checks only TCP port 80; it is not a full network or port scan. Only test systems you own or are authorized to assess."})

@app.get("/api/history")
@login_required
def history():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, scan_type, target, result_status, result_summary, created_at FROM scan_history WHERE user_id=%s ORDER BY created_at DESC LIMIT 100", (user["id"],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for row in rows:
        if isinstance(row.get("created_at"), datetime):
            row["created_at"] = row["created_at"].strftime("%Y-%m-%d %H:%M")
    return jsonify({"history": rows})

@app.get("/api/quiz")
@login_required
def quiz():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, question, option_a, option_b, option_c, option_d FROM awareness_questions ORDER BY id")
    questions = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"questions": questions})

@app.post("/api/quiz/answer")
@login_required
def quiz_answer():
    data = request.get_json(silent=True) or {}
    qid, answer = data.get("id"), (data.get("answer") or "").upper()
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT correct_option, explanation FROM awareness_questions WHERE id=%s", (qid,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({"error": "Question not found."}), 404
    return jsonify({"correct": answer == row["correct_option"], "explanation": row["explanation"]})

@app.get("/api/admin/users")
@login_required
def admin_users():
    if current_user().get("role") != "admin":
        return jsonify({"error": "Admin access required."}), 403
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, full_name, username, email, role, created_at FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.close()
    conn.close()
    for row in users:
        if isinstance(row.get("created_at"), datetime):
            row["created_at"] = row["created_at"].strftime("%Y-%m-%d %H:%M")
    return jsonify({"users": users})

@app.get("/api/report")
@login_required
def report():
    user = current_user()
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT scan_type, target, result_status, result_summary, created_at FROM scan_history WHERE user_id=%s ORDER BY created_at DESC LIMIT 100", (user["id"],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    lines = ["CYBERSECURITY ACTIVITY REPORT", f"User: {user['name']}", f"Generated: {datetime.now():%Y-%m-%d %H:%M}", ""]
    for row in rows:
        lines.extend([f"{row['created_at']} | {row['scan_type']} | {row['result_status']}",
                      f"Target: {row['target'] or '-'}", f"Details: {row['result_summary'] or '-'}", ""])
    from flask import Response
    return Response("\n".join(lines), mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=security-report.txt"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
