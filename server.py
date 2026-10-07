"""SecureShare server. Stores ONLY ciphertext + hash + signature + wrapped key. Never sees plaintext or private keys."""
import os, re, sqlite3, secrets, hashlib, hmac, time, base64
from functools import wraps
from flask import Flask, request, jsonify, g, send_file
import crypto_utils as cu

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt BLOB, pw_hash BLOB,
  enc_pub TEXT, sig_pub TEXT, created REAL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER, expires REAL);
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, sender_id INTEGER, recipient_id INTEGER, filename TEXT,
  mode TEXT, iv BLOB, wrapped_key BLOB, sha256 TEXT, signature BLOB, ct_sha256 TEXT, size INTEGER, created REAL);
"""
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s, validate=True)


def create_app(data_dir="data"):
    store = os.path.join(data_dir, "storage")
    os.makedirs(store, exist_ok=True)
    root_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(__name__, static_folder=root_dir, static_url_path="/static")
    app.config.update(DB=os.path.join(data_dir, "secureshare.db"), STORE=store, MAX_CONTENT_LENGTH=64 * 2**20)
    with sqlite3.connect(app.config["DB"]) as c:
        c.executescript(SCHEMA)
    failures = {}                                           # username -> (count, first_ts) for login lockout

    @app.get("/")
    def index():
        return send_file(os.path.join(root_dir, "index.html"))

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def _close(_):
        d = g.pop("db", None)
        if d:
            d.close()

    def auth(f):
        @wraps(f)
        def wrapper(*a, **k):
            h = request.headers.get("Authorization", "")
            tok = h[7:] if h.startswith("Bearer ") else ""
            row = db().execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
                               "WHERE s.token_hash=? AND s.expires>?",
                               (hashlib.sha256(tok.encode()).hexdigest(), time.time())).fetchone()
            if not row:
                return jsonify(error="authentication required"), 401
            g.user = row
            return f(*a, **k)
        return wrapper

    def pwhash(pw, salt):
        return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)

    @app.post("/api/register")
    def register():
        d = request.get_json(silent=True) or {}
        u, pw = d.get("username", ""), d.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", u) or len(pw) < 8:
            return jsonify(error="username 3-32 chars [A-Za-z0-9_], password >= 8 chars"), 400
        try:
            for k in ("enc_pub", "sig_pub"):
                if cu.load_pub(d[k].encode()).key_size < 2048:
                    raise ValueError
        except Exception:
            return jsonify(error="valid RSA-2048+ public keys required"), 400
        salt = os.urandom(16)
        try:
            db().execute("INSERT INTO users(username,salt,pw_hash,enc_pub,sig_pub,created) VALUES(?,?,?,?,?,?)",
                         (u, salt, pwhash(pw, salt), d["enc_pub"], d["sig_pub"], time.time()))
            db().commit()
        except sqlite3.IntegrityError:
            return jsonify(error="username taken"), 409
        return jsonify(ok=True), 201

    @app.post("/api/login")
    def login():
        d = request.get_json(silent=True) or {}
        u, pw = d.get("username", ""), d.get("password", "")
        cnt, ts = failures.get(u, (0, 0))
        if cnt >= 5 and time.time() - ts < 30:
            return jsonify(error="too many failed attempts; retry later"), 429
        row = db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row or not hmac.compare_digest(pwhash(pw, row["salt"]), row["pw_hash"]):
            failures[u] = (cnt + 1 if time.time() - ts < 30 else 1, time.time())
            return jsonify(error="invalid credentials"), 401
        failures.pop(u, None)
        tok = secrets.token_urlsafe(32)
        db().execute("INSERT INTO sessions VALUES(?,?,?)",
                     (hashlib.sha256(tok.encode()).hexdigest(), row["id"], time.time() + 3600))
        db().commit()
        return jsonify(token=tok)

    @app.get("/api/users/<name>/keys")
    @auth
    def keys(name):
        r = db().execute("SELECT enc_pub,sig_pub FROM users WHERE username=?", (name,)).fetchone()
        return (jsonify(enc_pub=r["enc_pub"], sig_pub=r["sig_pub"]) if r else (jsonify(error="no such user"), 404))

    @app.post("/api/files")
    @auth
    def upload():
        d = request.get_json(silent=True) or {}
        try:
            rcpt = db().execute("SELECT id FROM users WHERE username=?", (d["recipient"],)).fetchone()
            if not rcpt or d["mode"] not in ("GCM", "CBC") or not re.fullmatch(r"[0-9a-f]{64}", d["sha256"]):
                raise ValueError
            iv, wk, sig, ct = b64d(d["iv"]), b64d(d["wrapped_key"]), b64d(d["signature"]), b64d(d["ciphertext"])
            fname = os.path.basename(str(d["filename"]))[:120] or "file"
        except Exception:
            return jsonify(error="malformed upload"), 400
        # server-side sanity: signature over the claimed hash must verify under the sender's registered key
        if not cu.verify(cu.load_pub(g.user["sig_pub"].encode()), sig, d["sha256"].encode()):
            return jsonify(error="invalid digital signature"), 400
        cur = db().execute("INSERT INTO files(sender_id,recipient_id,filename,mode,iv,wrapped_key,sha256,signature,"
                           "ct_sha256,size,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (g.user["id"], rcpt["id"], fname, d["mode"], iv, wk, d["sha256"], sig,
                            cu.sha256_hex(ct), len(ct), time.time()))
        db().commit()
        with open(os.path.join(store, f"{cur.lastrowid}.bin"), "wb") as f:
            f.write(ct)
        return jsonify(id=cur.lastrowid), 201

    def _row(fid):
        return db().execute("SELECT f.*, s.username sender, r.username recipient, s.sig_pub FROM files f "
                            "JOIN users s ON s.id=f.sender_id JOIN users r ON r.id=f.recipient_id WHERE f.id=?",
                            (fid,)).fetchone()

    def _ct(fid):
        with open(os.path.join(store, f"{fid}.bin"), "rb") as f:
            return f.read()

    @app.get("/api/files")
    @auth
    def list_files():
        rows = db().execute("SELECT id FROM files WHERE sender_id=? OR recipient_id=? ORDER BY id DESC",
                            (g.user["id"], g.user["id"])).fetchall()
        out = []
        for x in rows:
            r, ct = _row(x["id"]), _ct(x["id"])
            out.append(dict(id=r["id"], filename=r["filename"], sender=r["sender"], recipient=r["recipient"],
                            mode=r["mode"], size=r["size"], sha256=r["sha256"], created=r["created"],
                            storage="Intact" if cu.sha256_hex(ct) == r["ct_sha256"] else "Modified",
                            signature="Valid" if cu.verify(cu.load_pub(r["sig_pub"].encode()), r["signature"],
                                                           r["sha256"].encode()) else "Invalid"))
        return jsonify(files=out)

    @app.get("/api/files/<int:fid>")
    @auth
    def download(fid):
        r = _row(fid)
        if not r:
            return jsonify(error="not found"), 404
        if g.user["id"] not in (r["sender_id"], r["recipient_id"]):
            return jsonify(error="forbidden"), 403
        return jsonify(id=fid, filename=r["filename"], sender=r["sender"], recipient=r["recipient"], mode=r["mode"],
                       iv=b64e(r["iv"]), wrapped_key=b64e(r["wrapped_key"]), sha256=r["sha256"],
                       signature=b64e(r["signature"]), ciphertext=b64e(_ct(fid)))

    @app.get("/dashboard")
    def dashboard():
        return DASH

    return app


DASH = """<!doctype html><meta charset=utf-8><title>SecureShare Ledger</title>
<style>
body{margin:0;background:#efe9dc;color:#1d1b16;font:15px/1.5 Georgia,serif}
main{max-width:960px;margin:0 auto;padding:32px 20px}
h1{font-size:34px;margin:0}h1 span{font:12px ui-monospace,monospace;letter-spacing:.15em;color:#7a2e1d;display:block}
form{display:flex;gap:8px;margin:20px 0}input,button{font:inherit;padding:8px 10px;border:1.5px solid #1d1b16;background:#fbf8f1}
button{background:#1d1b16;color:#efe9dc;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:12px}th{font:11px ui-monospace,monospace;letter-spacing:.12em;text-align:left;border-bottom:2px solid #1d1b16;padding:6px}
td{padding:8px 6px;border-bottom:1px solid #c9c0ab;vertical-align:top}.h{font:11px ui-monospace,monospace;color:#5b564a;word-break:break-all}
.s{display:inline-block;font:700 11px ui-monospace,monospace;letter-spacing:.08em;padding:2px 7px;border:2px solid;transform:rotate(-2deg)}
.ok{color:#1f6b3a}.bad{color:#b3261e}p.n{color:#5b564a;font-size:13px}
</style><main><h1><span>SECURESHARE / ACCESS LEDGER</span>Files in your custody</h1>
<form id=f><input id=u placeholder=username required><input id=p type=password placeholder=password required><button>Open ledger</button></form>
<p class=n id=m>Server-side checks only: ciphertext integrity at rest and signature on the stored hash. Full decrypt + SHA-256 + signature verification happens in the client (<code>client.py download</code>).</p>
<table id=t hidden><thead><tr><th>ID<th>FILE<th>FROM &rarr; TO<th>MODE<th>STORAGE<th>SIGNATURE<th>SHA-256 (original)</thead><tbody></tbody></table></main>
<script>
const chip=(v,good)=>{const s=document.createElement('span');s.className='s '+(v===good?'ok':'bad');s.textContent=v==='Intact'||v==='Valid'?(v==='Intact'?'INTACT':'VERIFIED'):(v==='Modified'?'MODIFIED':'INVALID');return s};
f.onsubmit=async e=>{e.preventDefault();m.className='n';
 const l=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});
 if(!l.ok){m.textContent='Login failed: '+(await l.json()).error;return}
 const {token}=await l.json();const r=await (await fetch('/api/files',{headers:{Authorization:'Bearer '+token}})).json();
 const b=t.querySelector('tbody');b.innerHTML='';t.hidden=false;
 r.files.forEach(x=>{const tr=b.insertRow();[x.id,x.filename,x.sender+' \\u2192 '+x.recipient,'AES-256-'+x.mode].forEach(v=>tr.insertCell().textContent=v);
  tr.insertCell().append(chip(x.storage,'Intact'));tr.insertCell().append(chip(x.signature,'Valid'));const c=tr.insertCell();c.className='h';c.textContent=x.sha256});};
</script>"""

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--data", default="data")
    ap.add_argument("--cert"); ap.add_argument("--key")
    a = ap.parse_args()
    ctx = (a.cert, a.key) if a.cert and a.key else None   # pass --cert/--key to serve over TLS
    create_app(a.data).run("127.0.0.1", a.port, ssl_context=ctx)
