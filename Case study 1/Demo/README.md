# SQL Injection Demo

This is a local educational Flask application that demonstrates how SQL injection works and how parameterized queries prevent it.

## What it shows

- A login form using a vulnerable SQL query or a secure prepared statement
- A product search page with the same vulnerable/secure comparison
- Query logging so you can inspect the executed SQL statements
- Sample data seeded into SQLite on first run

## Run it locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Educational notes

- Vulnerable mode uses string concatenation to build SQL.
- Secure mode uses parameterized queries so input cannot change the SQL structure.
- The app is intended only for local classroom or lab use.

## Vulnerable SQL input:

Login Page: Username = `alice'--` Password = `--`

Search Page: `' OR 1=1`