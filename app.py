import sqlite3
import os
from services import migrations
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect


# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Config
DB_PATH = 'lendifyme.db'


@app.before_request
def redirect_www():
    if request.host.startswith("www."):
        new_url = request.url.replace("://www.", "://", 1)
        return redirect(new_url, code=301)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    migrations.run_migrations(conn)
    conn.close()


init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        borrower = request.form.get("borrower")
        date_borrowed = request.form.get("date_borrowed")
        amount = request.form.get("amount")
        note = request.form.get("note")

        if borrower and amount:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO loans (borrower, amount, note, date_borrowed)
                VALUES (?, ?, ?, ?)
            """, (borrower, float(amount), note, date_borrowed))
            conn.commit()
            conn.close()
        return redirect("/")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT borrower, amount, note, date_borrowed, created_at
        FROM loans
        ORDER BY created_at DESC
    """)

    loans = c.fetchall()
    conn.close()

    return render_template("index.html", loans=loans)


if __name__ == "__main__":
    app.run(debug=True)
