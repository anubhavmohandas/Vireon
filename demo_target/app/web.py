"""
Flask web app — vulnerable to CVE-2023-30861 (open redirect),
CVE-2024-22195 (Jinja2 XSS), CVE-2023-30608 (SQLAlchemy injection).
"""
from flask import Flask, request, redirect, render_template_string
from jinja2 import Template
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine("sqlite:///demo.db")


@app.route("/redirect")
def unsafe_redirect():
    """Open redirect — CVE-2023-30861."""
    # VULN: user-controlled redirect target
    target = request.args.get("url", "/")
    return redirect(target)


@app.route("/render")
def unsafe_render():
    """Server-side template injection via Jinja2 — CVE-2024-22195."""
    template_str = request.args.get("template", "Hello World")
    # VULN: user-controlled template string — SSTI / XSS
    t = Template(template_str)
    return t.render()


@app.route("/search")
def unsafe_search():
    """SQL injection via SQLAlchemy text() — CVE-2023-30608."""
    query = request.args.get("q", "")
    with engine.connect() as conn:
        # VULN: user input directly in SQL — SQLi
        result = conn.execute(text(f"SELECT * FROM users WHERE name = '{query}'"))
        return str(result.fetchall())


@app.route("/upload", methods=["POST"])
def unsafe_upload():
    """Path traversal via werkzeug — CVE-2023-46136."""
    filename = request.form.get("filename", "upload.txt")
    data = request.form.get("data", "")
    # VULN: no path sanitization — directory traversal
    with open(f"uploads/{filename}", "w") as f:
        f.write(data)
    return "uploaded"


if __name__ == "__main__":
    app.run(debug=True)
