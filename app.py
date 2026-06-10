from flask import Flask, render_template, request, redirect, session
import sqlite3
import os
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# SECRET KEY (for sessions)
app.secret_key = "ocean_secret_key"

# =========================
# ENCRYPTION KEY (RENDER SAFE)
# =========================
key = os.getenv("FERNET_KEY")
fer = Fernet(key)

# =========================
# DATABASE SETUP (runs once)
# =========================
conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    website TEXT,
    password TEXT
)
""")

conn.commit()
conn.close()

# =========================
# ROUTES
# =========================

@app.route("/")
def home():
    return redirect("/login")


# SIGNUP
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users(username, password) VALUES(?, ?)",
                (username, hashed_password)
            )
            conn.commit()
            return redirect("/login")

        except:
            return "Username already exists"

    return render_template("signup.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect("/dashboard")

        else:
            return "Invalid username or password"

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# ADD PASSWORD
@app.route("/add_password", methods=["GET", "POST"])
def add_password():

    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":

        website = request.form["website"]
        password = request.form["password"]

        encrypted_password = fer.encrypt(
            password.encode()
        ).decode()

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO passwords(user_id, website, password)
            VALUES(?, ?, ?)
        """, (
            session["user_id"],
            website,
            encrypted_password
        ))

        conn.commit()

        return redirect("/view_passwords")

    return render_template("add_password.html")


# VIEW PASSWORDS
@app.route("/view_passwords")
def view_passwords():

    if "user_id" not in session:
        return redirect("/login")

    search = request.args.get("search", "")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    if search:
        cursor.execute("""
            SELECT id, website, password
            FROM passwords
            WHERE user_id=? AND website LIKE ?
        """, (
            session["user_id"],
            "%" + search + "%"
        ))
    else:
        cursor.execute("""
            SELECT id, website, password
            FROM passwords
            WHERE user_id=?
        """, (session["user_id"],))

    data = cursor.fetchall()

    passwords = []

    for password_id, website, encrypted_password in data:

        decrypted = fer.decrypt(
            encrypted_password.encode()
        ).decode()

        passwords.append((password_id, website, decrypted))

    return render_template(
        "view_passwords.html",
        passwords=passwords
    )


# DELETE PASSWORD
@app.route("/delete_password/<int:id>")
def delete_password(id):

    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM passwords
        WHERE id=? AND user_id=?
    """, (id, session["user_id"]))

    conn.commit()

    return redirect("/view_passwords")


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================
# RUN SERVER (RENDER FIXED)
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)