# SQL Injection Demo

This is a local educational Flask application that demonstrates how SQL injection works and how parameterized queries prevent it.

## What it shows

- A login form using a vulnerable SQL query or a secure prepared statement
- A dedicated vulnerable HTTP query endpoint: `/search`
- A dedicated secure HTTP query endpoint: `/search_secure`
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

## Example Vulnerable SQL input:

Login Page: Username = `alice'--` Password = `--`

Search Page: `' OR 1=1`

## HTTP Request Injection Demo

The app demonstrates that SQL injection can come from HTTP query parameters (and optional headers), not only HTML forms.

- Vulnerable endpoint (educational only): `GET /search?q=...`
- Secure endpoint: `GET /search_secure?q=...`
- Optional advanced header demo: send `X-User-Input` and `use_header=1`

Example malicious payload in URL:

`/search?q=' OR '1'='1`

The vulnerable endpoint concatenates this directly into SQL, while the secure endpoint uses placeholders.

Attackers use headers because:

- Often overlooked by developers
- Not validated properly
- Still part of HTTP request

### Automated request simulation

Run this while Flask is running locally:

```bash
python http_injection_demo.py
```

This script compares normal and malicious requests against both endpoints and includes the optional header-based demonstration.

## Educational notes

- Vulnerable mode uses string concatenation to build SQL.
- Secure mode uses parameterized queries so input cannot change the SQL structure.
- The app is intended only for local classroom or lab use.
- Vulnerable code paths are for educational purposes only.