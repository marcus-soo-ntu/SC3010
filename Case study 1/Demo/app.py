import logging
import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, g, redirect, render_template, request, url_for

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "sql_injection_demo.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "sql-injection-demo-only"
app.logger.setLevel(logging.INFO)


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    database = get_db()
    database.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            action TEXT NOT NULL,
            mode TEXT NOT NULL,
            sql_text TEXT NOT NULL,
            params_text TEXT NOT NULL,
            result_count INTEGER NOT NULL,
            note TEXT NOT NULL
        );
        """
    )

    if database.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        database.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            [
                ("alice", "wonderland", "student"),
                ("bob", "builder", "student"),
                ("admin", "admin123", "administrator"),
            ],
        )

    if database.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        database.executemany(
            "INSERT INTO products (name, category, price) VALUES (?, ?, ?)",
            [
                ("Laptop", "Electronics", 1299.00),
                ("Mouse", "Electronics", 25.90),
                ("Notebook", "Stationery", 4.50),
                ("Water Bottle", "Lifestyle", 12.00),
                ("Desk Lamp", "Home", 34.90),
            ],
        )

    database.commit()


with app.app_context():
    init_db()


def normalize_mode(value):
    return "vulnerable" if value == "vulnerable" else "secure"


def log_query(action, mode, sql_text, params, result_count, note):
    database = get_db()
    database.execute(
        """
        INSERT INTO query_logs (created_at, action, mode, sql_text, params_text, result_count, note)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            action,
            mode,
            sql_text,
            str(params),
            result_count,
            note,
        ),
    )
    database.commit()
    app.logger.info("[%s] %s | %s | params=%s | rows=%s", mode, action, sql_text, params, result_count)


def fetch_query_logs(limit=10):
    database = get_db()
    return database.execute(
        "SELECT created_at, action, mode, sql_text, params_text, result_count, note FROM query_logs ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()


@app.context_processor
def inject_globals():
    return {"current_year": datetime.now().year}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    mode = normalize_mode(request.values.get("mode", "secure"))
    result = None
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if mode == "vulnerable":
            # Intentionally unsafe: user input is concatenated directly into SQL.
            # This is vulnerable because an attacker can change the query logic.
            sql_text = (
                "SELECT id, username, role FROM users WHERE username = '"
                + username
                + "' AND password = '"
                + password
                + "'"
            )
            database = get_db()
            try:
                rows = database.execute(sql_text).fetchall()
                log_query("login", mode, sql_text, {"username": username, "password": password}, len(rows), "String concatenation makes the query injectable.")
            except sqlite3.OperationalError as e:
                error = f"SQL Error (expected with injection): {str(e)}"
                log_query("login", mode, sql_text, {"username": username, "password": password}, 0, f"Injection caused error: {str(e)}")
                rows = []
        else:
            sql_text = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
            database = get_db()
            rows = database.execute(sql_text, (username, password)).fetchall()
            log_query("login", mode, sql_text, {"username": username, "password": password}, len(rows), "Parameters keep the SQL structure separate from user input.")

        if rows:
            result = rows[0]
        elif not error:
            error = "No matching user was found."

    return render_template(
        "login.html",
        mode=mode,
        result=result,
        error=error,
        query_logs=fetch_query_logs(),
    )


@app.route("/clear-logs", methods=["POST"])
def clear_logs():
    database = get_db()
    database.execute("DELETE FROM query_logs")
    database.commit()
    app.logger.info("Query logs cleared")
    return redirect(request.referrer or url_for("index"))


@app.route("/search", methods=["GET"])
def search():
    mode = normalize_mode(request.args.get("mode", "secure"))
    query_text = request.args.get("q", "").strip()
    results = []

    if query_text:
        if mode == "vulnerable":
            # Intentionally unsafe: search text is inserted directly into the SQL string.
            sql_text = (
                "SELECT id, name, category, price FROM products WHERE name LIKE '%"
                + query_text
                + "%' OR category LIKE '%"
                + query_text
                + "%'"
            )
            database = get_db()
            try:
                results = database.execute(sql_text).fetchall()
                log_query("search", mode, sql_text, {"q": query_text}, len(results), "String concatenation allows the WHERE clause to be altered.")
            except sqlite3.OperationalError as e:
                results = []
                log_query("search", mode, sql_text, {"q": query_text}, 0, f"Injection caused error: {str(e)}")
        else:
            sql_text = "SELECT id, name, category, price FROM products WHERE name LIKE ? OR category LIKE ?"
            like_query = f"%{query_text}%"
            database = get_db()
            results = database.execute(sql_text, (like_query, like_query)).fetchall()
            log_query("search", mode, sql_text, {"q": query_text}, len(results), "Prepared statements treat the search term as data.")

    return render_template(
        "search.html",
        mode=mode,
        query_text=query_text,
        results=results,
        query_logs=fetch_query_logs(),
    )


if __name__ == "__main__":
    app.run(debug=True)
