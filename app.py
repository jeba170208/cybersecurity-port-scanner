import os
from port_scanner import scan_ports, get_port_info
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret")

DATABASE = "port_scanner.db"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            target TEXT NOT NULL,
            open_ports TEXT,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()
init_db()


@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        connection = get_db()

        try:
            connection.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            connection.commit()
            connection.close()

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            connection.close()

            return render_template(
                "register.html",
                error="Username already exists"
            )

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        connection = get_db()

        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(user["password"], password):

            session["username"] = username

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")



@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    target = ""
    ip = None
    open_ports = []
    port_results = []
    error = None
    scanned = False

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if not target:
            error = "Please enter a hostname or IP address."
        else:
            ip, open_ports = scan_ports(target)

            if ip is None:
                error = "Could not resolve the target."
            else:
                scanned = True

                # ADD PORT SERVICE EXPLANATIONS HERE
                port_results = [
                    get_port_info(port)
                    for port in open_ports
                ]

    return render_template(
        "dashboard.html",
        username=session["username"],
        target=target,
        ip=ip,
        open_ports=open_ports,
        port_results=port_results,
        error=error,
        scanned=scanned
    )


@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect(url_for("login"))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)

