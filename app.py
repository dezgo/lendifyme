import sqlite3
import os
from flask import Flask, render_template, request, redirect


app = Flask(__name__)
DB_PATH = "loans.db"


@app.before_request
def redirect_www():
    if request.host.startswith("www."):
        new_url = request.url.replace("://www.", "://", 1)
        return redirect(new_url, code=301)


def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE loans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                borrower TEXT NOT NULL,
                amount REAL NOT NULL,
                note TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        borrower = request.form.get("borrower")
        amount = request.form.get("amount")
        note = request.form.get("note")

        if borrower and amount:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT INTO loans (borrower, amount, note) VALUES (?, ?, ?)",
                      (borrower, float(amount), note))
            conn.commit()
            conn.close()
        return redirect("/")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT borrower, amount, note, created_at FROM loans ORDER BY created_at DESC")
    loans = c.fetchall()
    conn.close()

    return render_template("index.html", loans=loans)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
