"""Stdlib-only structural verification for the CyberShield project."""
from pathlib import Path
import re
import sqlite3
import ast

ROOT = Path(__file__).resolve().parent

required = [
    ROOT / "app.py",
    ROOT / "auth.py",
    ROOT / "config.py",
    ROOT / "database.py",
    ROOT / "detection.py",
    ROOT / "incident_response.py",
    ROOT / "logging_service.py",
    ROOT / "threat_intel.py",
    ROOT / "requirements.txt",
    ROOT / "templates" / "base.html",
    ROOT / "templates" / "login.html",
    ROOT / "templates" / "investigations.html",
    ROOT / "templates" / "vulnerable" / "home.html",
    ROOT / "templates" / "vulnerable" / "login.html",
    ROOT / "templates" / "vulnerable" / "search.html",
    ROOT / "templates" / "vulnerable" / "feedback.html",
]

for path in required:
    assert path.exists(), f"Missing required file: {path}"

for path in ROOT.glob("*.py"):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

app_text = (ROOT / "app.py").read_text(encoding="utf-8")
functions = set(re.findall(r"def\s+(\w+)\s*\(", app_text))
refs = set()
for template in (ROOT / "templates").rglob("*.html"):
    text = template.read_text(encoding="utf-8")
    refs.update(re.findall(r"url_for\(\s*['\"]([^'\"]+)['\"]", text))
    assert text.count("{%") == text.count("%}"), f"Jinja tag mismatch: {template}"
    assert text.count("{{") == text.count("}}"), f"Jinja expression mismatch: {template}"
    for form in re.findall(r"<form\b[\s\S]*?</form>", text, flags=re.I):
        if 'METHOD="POST"' in form.upper():
            assert "csrf_token" in form, f"POST form missing CSRF token: {template}"

missing = refs - functions - {"static"}
assert not missing, f"Template references missing Flask endpoints: {sorted(missing)}"

db_path = ROOT / "database.db"
if db_path.exists():
    con = sqlite3.connect(db_path)
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in {"users", "assets", "logs", "alerts", "incidents", "incident_actions", "blocked_ips", "iocs"}:
        assert table in tables, f"Missing database table: {table}"
    admin_count = con.execute("SELECT COUNT(*) FROM users WHERE role='ADMIN'").fetchone()[0]
    analyst_count = con.execute("SELECT COUNT(*) FROM users WHERE role='SOC_ANALYST'").fetchone()[0]
    employee_count = con.execute("SELECT COUNT(*) FROM users WHERE role='EMPLOYEE'").fetchone()[0]
    assert admin_count >= 1 and analyst_count >= 1 and employee_count >= 1
    con.close()
    print("Existing local SQLite schema and demo records: PASS")
else:
    print("Local SQLite database not committed (expected); the app creates and seeds it on first run.")

print("CyberShield structural verification: PASS")
print(f"Python modules checked: {len(list(ROOT.glob('*.py')))}")
print(f"Templates checked: {len(list((ROOT / 'templates').rglob('*.html')))}")
print("CSRF coverage for POST forms: PASS")
print("Template endpoint references: PASS")


def _extract_csrf(html_text):
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_text)
    assert match, "CSRF token not found in response HTML"
    return match.group(1)


def run_functional_tests():
    try:
        import flask  # noqa: F401
    except ImportError:
        print("Functional suite skipped (run inside venv for full Flask client tests).")
        return

    db_path = ROOT / "database.db"
    db_backup = db_path.read_bytes() if db_path.exists() else None
    try:
        import app as cybershield_app
        from detection import run_detection
        from database import get_alerts, get_incidents, is_ip_blocked, get_user

        client = cybershield_app.app.test_client()

        # 1. Verify employee cannot log into SOC console (no 403 redirect loop)
        resp = client.get("/login")
        assert resp.status_code == 200
        csrf_token = _extract_csrf(resp.get_data(as_text=True))
        emp_soc = client.post("/login", data={"username": "john", "password": "john123", "csrf_token": csrf_token})
        assert emp_soc.status_code == 200
        assert "restricted to SOC Analysts and Administrators" in emp_soc.get_data(as_text=True)

        # 2. Verify SOC Analyst gets styled 403 page on Admin-only /users
        csrf_token = _extract_csrf(emp_soc.get_data(as_text=True))
        analyst_login = client.post("/login", data={"username": "analyst", "password": "analyst123", "csrf_token": csrf_token}, follow_redirects=True)
        assert analyst_login.status_code == 200
        forbidden_resp = client.get("/users")
        assert forbidden_resp.status_code == 403
        assert "Error 403" in forbidden_resp.get_data(as_text=True)

        # Sign out analyst, sign in as admin
        dash_html = client.get("/dashboard").get_data(as_text=True)
        client.post("/logout", data={"csrf_token": _extract_csrf(dash_html)}, follow_redirects=True)
        login_html = client.get("/login").get_data(as_text=True)
        admin_login = client.post("/login", data={"username": "admin", "password": "admin123", "csrf_token": _extract_csrf(login_html)}, follow_redirects=True)
        assert admin_login.status_code == 200

        # Ensure clean state for john and 203.0.113.45 before lab simulation
        users_html = client.get("/users").get_data(as_text=True)
        client.post("/users/john/status", data={"status": "ACTIVE", "csrf_token": _extract_csrf(users_html)}, follow_redirects=True)
        if is_ip_blocked("203.0.113.45"):
            inc_html = client.get("/incidents").get_data(as_text=True)
            client.post("/blocked-ips/unblock", data={"ip_address": "203.0.113.45", "csrf_token": _extract_csrf(inc_html)}, follow_redirects=True)

        # 3. Portal SQLi (' OR '1'='1) and XSS simulation
        portal_login_html = client.get("/portal/login").get_data(as_text=True)
        p_login = client.post("/portal/login", data={"username": "john", "password": "john123", "csrf_token": _extract_csrf(portal_login_html)}, follow_redirects=True)
        assert p_login.status_code == 200

        # Normal search only returns EMPLOYEE accounts
        normal_search = client.get("/portal/search?q=admin").get_data(as_text=True)
        assert "No Employees Found" in normal_search

        # SQLi search with classic "' OR '1'='1" payload triggers detection and exposes all records
        sqli_search = client.get("/portal/search?q=' OR '1'='1").get_data(as_text=True)
        assert "SQL Injection Pattern Detected" in sqli_search
        assert "admin@cybershield.local" in sqli_search

        # XSS feedback simulation
        fb_html = client.get("/portal/feedback").get_data(as_text=True)
        xss_resp = client.post("/portal/feedback", data={
            "name": "John",
            "email": "john@cybershield.local",
            "feedback": "<script>alert('xss')</script>",
            "csrf_token": _extract_csrf(fb_html),
        })
        assert xss_resp.status_code == 200
        assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in xss_resp.get_data(as_text=True)

        # 4. Verify SQLi and XSS alerts exist, open SQLi incident, and verify evidence correlation + lifecycle
        alerts = get_alerts()
        sqli_alert = next((a for a in alerts if a["alert_type"] == "SQL_INJECTION"), None)
        assert sqli_alert is not None, "Expected SQL_INJECTION alert to be generated"

        alerts_html = client.get("/alerts").get_data(as_text=True)
        inv_resp = client.post(f"/alerts/{sqli_alert['id']}/investigate", data={"csrf_token": _extract_csrf(alerts_html)}, follow_redirects=True)
        assert inv_resp.status_code == 200
        inv_text = inv_resp.get_data(as_text=True)

        # Verify Save Investigation Findings button IS visible before CONTAINED, and Lock Target Account is NOT shown for /portal/search
        assert "Save Investigation Findings" in inv_text
        assert "Lock Target Account (/portal/search)" not in inv_text
        # Verify correlated evidence log and captured payload are displayed
        assert "SQL_INJECTION_ATTEMPT" in inv_text
        assert "CAPTURED PAYLOAD / REQUEST DATA" in inv_text

        incidents = get_incidents()
        sqli_incident = next(i for i in incidents if i["alert_id"] == sqli_alert["id"])
        inc_id = sqli_incident["id"]

        # Walk the incident through the full lifecycle: NEW -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED
        if sqli_incident["status"] == "NEW":
            inv_text = client.post(f"/incidents/{inc_id}/status", data={"status": "INVESTIGATING", "csrf_token": _extract_csrf(inv_text)}, follow_redirects=True).get_data(as_text=True)

        inv_text = client.post(f"/incidents/{inc_id}/findings", data={
            "findings": "Confirmed SQL injection attempt via directory search.",
            "root_cause": "Unsanitized search query simulation.",
            "csrf_token": _extract_csrf(inv_text),
        }, follow_redirects=True).get_data(as_text=True)

        # Apply IP block containment
        inv_text = client.post(f"/incidents/{inc_id}/block-ip", data={"csrf_token": _extract_csrf(inv_text)}, follow_redirects=True).get_data(as_text=True)
        assert is_ip_blocked("203.0.113.45"), "Expected 203.0.113.45 to be blocked in database"

        # Verify portal now enforces the IP block with HTTP 403
        blocked_search = client.get("/portal/search?q=john")
        assert blocked_search.status_code == 403
        assert "blocked by CyberShield SOC containment policy" in blocked_search.get_data(as_text=True)

        # Advance to CONTAINED
        inv_text = client.post(f"/incidents/{inc_id}/status", data={"status": "CONTAINED", "csrf_token": _extract_csrf(inv_text)}, follow_redirects=True).get_data(as_text=True)
        assert "Incident moved to CONTAINED." in inv_text

        # Record remediation and advance to RESOLVED
        inv_text = client.post(f"/incidents/{inc_id}/remediation", data={
            "remediation": "Enforced parameterized queries and strict input validation.",
            "csrf_token": _extract_csrf(inv_text),
        }, follow_redirects=True).get_data(as_text=True)
        inv_text = client.post(f"/incidents/{inc_id}/status", data={"status": "RESOLVED", "csrf_token": _extract_csrf(inv_text)}, follow_redirects=True).get_data(as_text=True)
        assert "Incident moved to RESOLVED." in inv_text

        # Verify run_detection() does NOT re-create a duplicate alert for the already-resolved SQLi log
        alert_count_before = len(get_alerts())
        run_detection()
        alert_count_after = len(get_alerts())
        assert alert_count_after == alert_count_before, "Resolved SQLi log should not re-trigger a duplicate alert"

        # Record verification and close incident
        inv_text = client.post(f"/incidents/{inc_id}/verify", data={
            "verification": "Retested from 203.0.113.45; request blocked with HTTP 403.",
            "csrf_token": _extract_csrf(inv_text),
        }, follow_redirects=True).get_data(as_text=True)
        inv_text = client.post(f"/incidents/{inc_id}/status", data={"status": "CLOSED", "csrf_token": _extract_csrf(inv_text)}, follow_redirects=True).get_data(as_text=True)
        assert "Incident moved to CLOSED." in inv_text

        # Unblock IP to leave lab ready for interactive demonstration
        client.post("/blocked-ips/unblock", data={
            "ip_address": "203.0.113.45",
            "return_to": "investigation",
            "incident_id": str(inc_id),
            "csrf_token": _extract_csrf(inv_text),
        }, follow_redirects=True)
        assert not is_ip_blocked("203.0.113.45")
        assert get_user("john")["status"] == "ACTIVE"

        print("End-to-end functional & lifecycle verification: PASS")
    finally:
        if db_backup is not None:
            db_path.write_bytes(db_backup)


if __name__ == "__main__":
    run_functional_tests()
