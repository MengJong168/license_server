from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
from datetime import datetime, timedelta
import random
import csv
import io
from collections import defaultdict
from zoneinfo import ZoneInfo

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"  # change in production

PHNOM_PENH_TZ = ZoneInfo("Asia/Phnom_Penh")

def now_pp_date():
    return datetime.now(PHNOM_PENH_TZ).date()

DB = "database.db"


def db():
    return sqlite3.connect(DB)


# ===================== INIT DB =====================
with db() as con:
    # Main license table: lock to app_id + bind to hwid + rollback protection
    con.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license TEXT UNIQUE,
        hwid TEXT,
        app_id TEXT,
        start TEXT,
        expiry TEXT,
        last_seen TEXT
    )
    """)

    # Best-effort upgrades for older DBs
    for col in ["hwid", "app_id", "start", "expiry", "last_seen"]:
        try:
            con.execute(f"ALTER TABLE licenses ADD COLUMN {col} TEXT")
        except Exception:
            pass

    # If your old DB had "mac", copy it into hwid once (optional)
    try:
        con.execute("""
        UPDATE licenses
        SET hwid = mac
        WHERE (hwid IS NULL OR hwid='') AND mac IS NOT NULL AND mac!=''
        """)
        con.commit()
    except Exception:
        pass

    # Logs table (keep last_seen OUT of logs; logs are event history)
    con.execute("""
    CREATE TABLE IF NOT EXISTS verify_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license TEXT,
        hwid TEXT,
        app_id TEXT,
        status TEXT,
        ip TEXT,
        created_at TEXT
    )
    """)

    # Upgrade logs table if it existed before without app_id
    try:
        con.execute("ALTER TABLE verify_logs ADD COLUMN app_id TEXT")
    except Exception:
        pass

# ===================== DATE + STATUS HELPERS =====================
def parse_date(s: str):
    return datetime.strptime(s, "%Y-%m-%d")


def today_date():
    return now_pp_date()

def is_invalid_range(start: str, expiry: str) -> bool:
    if not start or not expiry:
        return False
    try:
        return parse_date(start).date() > parse_date(expiry).date()
    except Exception:
        return True


def is_not_started(start: str) -> bool:
    if not start:
        return False
    try:
        return today_date() < parse_date(start).date()
    except Exception:
        return False


def is_expired(expiry: str) -> bool:
    if not expiry:
        return False
    try:
        return today_date() > parse_date(expiry).date()
    except Exception:
        return True


def calc_status(hwid: str, start: str, expiry: str) -> str:
    if is_invalid_range(start, expiry):
        return "INVALID_DATES"
    if is_not_started(start):
        return "NOT_STARTED"
    if is_expired(expiry):
        return "EXPIRED"
    if hwid:
        return "USED"
    return "OK"


def normalize_date_or_empty(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    try:
        parse_date(s)
        return s
    except Exception:
        return ""


def validate_range_or_reject(start: str, expiry: str) -> bool:
    if start and expiry:
        try:
            return parse_date(start).date() <= parse_date(expiry).date()
        except Exception:
            return False
    return True


def client_ip():
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Forwarded-For")
        or request.remote_addr
    )


def log_verify(lic: str, hwid: str, app_id: str, status: str):
    with db() as con:
        con.execute(
            "INSERT INTO verify_logs (license, hwid, app_id, status, ip, created_at) VALUES (?,?,?,?,?,?)",
            (lic, hwid, app_id, status, client_ip(), datetime.now().isoformat(timespec="seconds"))
        )
        con.commit()


# ===================== LICENSE GENERATOR =====================
def gen_license_key(groups=4, group_len=4):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    parts = ["".join(random.choice(alphabet) for _ in range(group_len)) for _ in range(groups)]
    return "NEXUS-" + "-".join(parts)


# ===================== ADMIN LOGIN =====================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("user") == "admin" and request.form.get("pass") == "admin123":
            session["admin"] = True
            return redirect("/dashboard")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ===================== DASHBOARD (search + filters) =====================
@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect("/")

    q = (request.args.get("q") or "").strip()
    status_filter = (request.args.get("status") or "").strip().upper()

    start_from = normalize_date_or_empty(request.args.get("start_from"))
    start_to = normalize_date_or_empty(request.args.get("start_to"))
    exp_from = normalize_date_or_empty(request.args.get("exp_from"))
    exp_to = normalize_date_or_empty(request.args.get("exp_to"))

    con = db()

    where = []
    params = []

    if q:
        where.append("(license LIKE ? OR hwid LIKE ? OR app_id LIKE ?)")
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]

    # date filters (string compare works for YYYY-MM-DD)
    if start_from:
        where.append("start >= ?")
        params.append(start_from)
    if start_to:
        where.append("start <= ?")
        params.append(start_to)
    if exp_from:
        where.append("expiry >= ?")
        params.append(exp_from)
    if exp_to:
        where.append("expiry <= ?")
        params.append(exp_to)

    sql = "SELECT id, license, hwid, start, expiry, app_id FROM licenses"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC"

    rows = con.execute(sql, tuple(params)).fetchall()

    # tuple for template: (id, license, hwid, start, expiry, app_id, status)
    licenses = []
    for rid, lic, hwid, start, expiry, app_id in rows:
        hwid = hwid or ""
        start = start or ""
        expiry = expiry or ""
        app_id = app_id or ""
        st = calc_status(hwid, start, expiry)
        if status_filter and st != status_filter:
            continue
        licenses.append((rid, lic, hwid, start, expiry, app_id, st))

    return render_template(
        "dashboard.html",
        licenses=licenses,
        q=q,
        status=status_filter,
        start_from=start_from,
        start_to=start_to,
        exp_from=exp_from,
        exp_to=exp_to
    )


# ===================== ADD LICENSE =====================
@app.route("/add", methods=["POST"])
def add():
    if not session.get("admin"):
        return redirect("/")

    lic = (request.form.get("license") or "").strip()
    start = normalize_date_or_empty(request.form.get("start"))
    exp = normalize_date_or_empty(request.form.get("expiry"))

    if not lic:
        return redirect("/dashboard")

    if not validate_range_or_reject(start, exp):
        return redirect("/dashboard")

    con = db()
    try:
        con.execute("INSERT INTO licenses (license, start, expiry) VALUES (?,?,?)", (lic, start, exp))
        con.commit()
    except sqlite3.IntegrityError:
        pass

    return redirect("/dashboard")


# ===================== AUTO GENERATE =====================
@app.route("/generate", methods=["POST"])
def generate():
    if not session.get("admin"):
        return redirect("/")

    start = normalize_date_or_empty(request.form.get("start"))
    exp = normalize_date_or_empty(request.form.get("expiry"))
    count_raw = (request.form.get("count") or "1").strip()

    try:
        count = int(count_raw)
    except Exception:
        count = 1
    count = max(1, min(count, 500))

    if not validate_range_or_reject(start, exp):
        return redirect("/dashboard")

    con = db()
    made = 0
    while made < count:
        key = gen_license_key()
        try:
            con.execute("INSERT INTO licenses (license, start, expiry) VALUES (?,?,?)", (key, start, exp))
            con.commit()
            made += 1
        except sqlite3.IntegrityError:
            continue

    return redirect("/dashboard")


# ===================== DELETE LICENSE =====================
@app.route("/delete/<int:id>")
def delete(id):
    if not session.get("admin"):
        return redirect("/")

    con = db()
    con.execute("DELETE FROM licenses WHERE id=?", (id,))
    con.commit()
    return redirect("/dashboard")


# ===================== RESET HWID =====================
@app.route("/reset/<int:id>")
def reset(id):
    if not session.get("admin"):
        return redirect("/")

    con = db()
    con.execute("UPDATE licenses SET hwid=NULL WHERE id=?", (id,))
    con.commit()
    return redirect("/dashboard")


# ===================== RESET APP LOCK =====================
@app.route("/reset_app/<int:id>")
def reset_app(id):
    if not session.get("admin"):
        return redirect("/")

    con = db()
    con.execute("UPDATE licenses SET app_id=NULL WHERE id=?", (id,))
    con.commit()
    return redirect("/dashboard")


# ===================== EXTEND EXPIRY =====================
@app.route("/extend/<int:id>", methods=["POST"])
def extend(id):
    if not session.get("admin"):
        return redirect("/")

    new_exp = normalize_date_or_empty(request.form.get("expiry"))

    con = db()
    row = con.execute("SELECT start FROM licenses WHERE id=?", (id,)).fetchone()
    if not row:
        return redirect("/dashboard")
    start = row[0] or ""

    if not validate_range_or_reject(start, new_exp):
        return redirect("/dashboard")

    con.execute("UPDATE licenses SET expiry=? WHERE id=?", (new_exp, id))
    con.commit()
    return redirect("/dashboard")


# ===================== EXPORT CSV =====================
@app.route("/export.csv")
def export_csv():
    if not session.get("admin"):
        return redirect("/")

    con = db()
    rows = con.execute("SELECT id, license, hwid, start, expiry, app_id FROM licenses ORDER BY id DESC").fetchall()

    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id", "license", "hwid", "start", "expiry", "app_id", "status"])

    for rid, lic, hwid, start, expiry, app_id in rows:
        hwid = hwid or ""
        start = start or ""
        expiry = expiry or ""
        app_id = app_id or ""
        status = calc_status(hwid, start, expiry)
        w.writerow([rid, lic, hwid, start, expiry, app_id, status])

    csv_data = output.getvalue()
    return app.response_class(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=licenses.csv"}
    )


# ===================== LOGS PAGE =====================
@app.route("/logs")
def logs():
    if not session.get("admin"):
        return redirect("/")

    con = db()
    rows = con.execute(
        "SELECT id, license, hwid, app_id, status, ip, created_at FROM verify_logs ORDER BY id DESC LIMIT 500"
    ).fetchall()
    return render_template("logs.html", logs=rows)


# ===================== STATS PAGE =====================
@app.route("/stats")
def stats():
    if not session.get("admin"):
        return redirect("/")

    con = db()

    lic_rows = con.execute("SELECT license, hwid, start, expiry FROM licenses").fetchall()
    counts = defaultdict(int)
    for lic, hwid, start, expiry in lic_rows:
        st = calc_status(hwid or "", (start or ""), (expiry or ""))
        counts[st] += 1
    counts["TOTAL"] = len(lic_rows)

    # last 30 days verify volume
    logs_rows = con.execute(
        "SELECT created_at FROM verify_logs ORDER BY id DESC LIMIT 5000"
    ).fetchall()

    per_day = defaultdict(int)
    for (created_at,) in logs_rows:
        if not created_at:
            continue
        day = str(created_at)[:10]
        per_day[day] += 1

    days = sorted(per_day.keys())
    if len(days) > 30:
        days = days[-30:]
    per_day_list = [(d, per_day[d]) for d in days]

    return render_template("stats.html", counts=counts, per_day=per_day_list)


# ===================== VERIFY API (HWID + APP LOCK) =====================
@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    lic = (data.get("license") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    app_id = (data.get("app_id") or "").strip()

    if not lic or not hwid or not app_id:
        log_verify(lic, hwid, app_id, "BAD_REQUEST")
        return jsonify({"status": "bad_request"}), 400

    con = db()
    row = con.execute(
        "SELECT hwid, start, expiry, app_id, last_seen FROM licenses WHERE license=?",
        (lic,)
    ).fetchone()

    if not row:
        log_verify(lic, hwid, app_id, "INVALID")
        return jsonify({"status": "invalid"})

    saved_hwid = row[0] or ""
    start = row[1] or ""
    expiry = row[2] or ""
    saved_app = row[3] or ""
    last_seen = row[4] or ""

    # ================= ROLLBACK PROTECTION =================
    # Use Phnom Penh date (server-side). If you don't have now_pp_date(), use today_date().
    today = now_pp_date()  # <-- define this with ZoneInfo("Asia/Phnom_Penh")
    today_str = today.strftime("%Y-%m-%d")

    if last_seen:
        try:
            last_seen_date = datetime.strptime(last_seen, "%Y-%m-%d").date()
            if today < last_seen_date:
                log_verify(lic, hwid, app_id, "TIME_TAMPERED")
                return jsonify({"status": "time_tampered"})
        except Exception:
            # if last_seen is invalid/corrupted, overwrite below
            pass

    # update last_seen on every verify attempt (blocks going backward next time)
    con.execute("UPDATE licenses SET last_seen=? WHERE license=?", (today_str, lic))
    con.commit()
    # =======================================================

    # date rules
    if is_invalid_range(start, expiry):
        log_verify(lic, hwid, app_id, "INVALID_DATES")
        return jsonify({"status": "invalid_dates"})
    if is_not_started(start):
        log_verify(lic, hwid, app_id, "NOT_STARTED")
        return jsonify({"status": "not_started", "start": start})
    if is_expired(expiry):
        log_verify(lic, hwid, app_id, "EXPIRED")
        return jsonify({"status": "expired", "expiry": expiry})

    # IMPORTANT: lock license to ONE app
    if saved_app and saved_app != app_id:
        log_verify(lic, hwid, app_id, "APP_MISMATCH")
        return jsonify({"status": "app_mismatch", "allowed_app": saved_app})

    # first-time set app_id
    if not saved_app:
        con.execute("UPDATE licenses SET app_id=? WHERE license=?", (app_id, lic))
        con.commit()

    # hwid binding
    if saved_hwid and saved_hwid != hwid:
        log_verify(lic, hwid, app_id, "USED")
        return jsonify({"status": "used"})

    if not saved_hwid:
        con.execute("UPDATE licenses SET hwid=? WHERE license=?", (hwid, lic))
        con.commit()

    log_verify(lic, hwid, app_id, "OK")
    return jsonify({"status": "ok"})



if __name__ == "__main__":
    app.run()
