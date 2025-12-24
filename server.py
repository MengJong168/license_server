from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3, hashlib

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"

DB = "database.db"
SECRET = "NEXUS_PRO_2025"

def db():
    return sqlite3.connect(DB)

# INIT DB
with db() as con:
    con.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license TEXT UNIQUE,
        mac TEXT,
        expiry TEXT
    )
    """)

# ---------- ADMIN LOGIN ----------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["user"] == "admin" and request.form["pass"] == "admin123":
            session["admin"] = True
            return redirect("/dashboard")
    return render_template("login.html")

# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if not session.get("admin"):
        return redirect("/")
    con = db()
    rows = con.execute("SELECT * FROM licenses").fetchall()
    return render_template("dashboard.html", licenses=rows)

# ---------- ADD LICENSE ----------
@app.route("/add", methods=["POST"])
def add():
    lic = request.form["license"]
    exp = request.form["expiry"]
    con = db()
    con.execute("INSERT INTO licenses (license, expiry) VALUES (?,?)", (lic, exp))
    con.commit()
    return redirect("/dashboard")

# ---------- DELETE ----------
@app.route("/delete/<int:id>")
def delete(id):
    con = db()
    con.execute("DELETE FROM licenses WHERE id=?", (id,))
    con.commit()
    return redirect("/dashboard")

# ---------- ACTIVATE API ----------
@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    lic = data["license"]
    mac = data["mac"]

    con = db()
    cur = con.execute(
        "SELECT mac, expiry FROM licenses WHERE license=?",
        (lic,)
    )
    row = cur.fetchone()

    if not row:
        return jsonify({"status": "invalid"})

    saved_mac, expiry = row

    if saved_mac and saved_mac != mac:
        return jsonify({"status": "used"})

    # Optional expiry check
    # if expiry < today: return {"status":"expired"}

    # First-time bind
    if not saved_mac:
        con.execute("UPDATE licenses SET mac=? WHERE license=?", (mac, lic))
        con.commit()

    return jsonify({"status": "ok"})


app.run(host="0.0.0.0", port=5000)
