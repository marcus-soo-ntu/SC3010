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
def search_vulnerable():
    # HTTP query params map directly to backend variables via request.args.
    query_text = request.args.get("q", "").strip()
    # Optional advanced demo: unsanitized custom header value used in SQL.
    header_input = request.headers.get("X-User-Input", "").strip()
    use_header = request.args.get("use_header", "0") == "1"
    results = []
    error = None
    header_demo_status = ""

    app.logger.info("Raw HTTP input for /search | q=%r | X-User-Input=%r | use_header=%s", query_text, header_input, use_header)

    if query_text:
        # FOR EDUCATIONAL PURPOSES ONLY (vulnerable):
        # User-controlled HTTP input is concatenated into SQL text.
        # Example malicious URL: /search?q=' OR '1'='1
        # This can change query logic and return extra rows.
        sql_text = (
            "SELECT id, name, category, price FROM products WHERE name LIKE '%"
            + query_text
            + "%' OR category LIKE '%"
            + query_text
            + "%'"
        )

        if use_header and header_input:
            sql_text += " OR category = '" + header_input + "'"
            header_demo_status = "Advanced demo ON: X-User-Input header was concatenated into vulnerable SQL."
        elif use_header:
            header_demo_status = "Advanced demo ON but no X-User-Input header received. Use a client script (not browser form) to send it."

        database = get_db()
        try:
            app.logger.info("Final SQL /search (vulnerable): %s", sql_text)
            results = database.execute(sql_text).fetchall()
            log_query(
                "http_search",
                "vulnerable",
                sql_text,
                {"q": query_text, "X-User-Input": header_input, "use_header": use_header},
                len(results),
                "Vulnerable HTTP Query Endpoint: query params and optional header are directly concatenated.",
            )
        except sqlite3.OperationalError as exc:
            error = f"SQL Error (expected with injection demos): {str(exc)}"
            log_query(
                "http_search",
                "vulnerable",
                sql_text,
                {"q": query_text, "X-User-Input": header_input, "use_header": use_header},
                0,
                f"Injection caused error: {str(exc)}",
            )

    return render_template(
        "search.html",
        mode="vulnerable",
        endpoint_label="Vulnerable HTTP Query Endpoint",
        submit_url=url_for("search_vulnerable"),
        switch_url=url_for("search_secure"),
        switch_label="Go To Secure HTTP Endpoint",
        query_text=query_text,
        use_header=use_header,
        header_input=header_input,
        header_demo_status=header_demo_status,
        error=error,
        results=results,
        query_logs=fetch_query_logs(),
    )


@app.route("/search_secure", methods=["GET"])
def search_secure():
    query_text = request.args.get("q", "").strip()
    header_input = request.headers.get("X-User-Input", "").strip()
    use_header = request.args.get("use_header", "0") == "1"
    results = []
    header_demo_status = ""

    app.logger.info("Raw HTTP input for /search_secure | q=%r | X-User-Input=%r | use_header=%s", query_text, header_input, use_header)

    if query_text:
        # Secure version: input is always bound as data using placeholders.
        sql_text = "SELECT id, name, category, price FROM products WHERE name LIKE ? OR category LIKE ?"
        like_query = f"%{query_text}%"
        params = [like_query, like_query]

        if use_header and header_input:
            sql_text += " OR category = ?"
            params.append(header_input)
            header_demo_status = "Advanced demo ON: X-User-Input header was bound as a parameter in secure SQL."
        elif use_header:
            header_demo_status = "Advanced demo ON but no X-User-Input header received. Use a client script (not browser form) to send it."

        database = get_db()
        app.logger.info("Final SQL /search_secure: %s | params=%s", sql_text, params)
        results = database.execute(sql_text, tuple(params)).fetchall()
        log_query(
            "http_search",
            "secure",
            sql_text,
            {"q": query_text, "X-User-Input": header_input, "use_header": use_header},
            len(results),
            "Secure HTTP endpoint uses parameterized queries; payload stays data.",
        )

    return render_template(
        "search.html",
        mode="secure",
        endpoint_label="Secure HTTP Query Endpoint",
        submit_url=url_for("search_secure"),
        switch_url=url_for("search_vulnerable"),
        switch_label="Go To Vulnerable HTTP Endpoint",
        query_text=query_text,
        use_header=use_header,
        header_input=header_input,
        header_demo_status=header_demo_status,
        error=None,
        results=results,
        query_logs=fetch_query_logs(),
    )


if __name__ == "__main__":
    app.run(debug=True)
