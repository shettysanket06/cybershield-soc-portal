import hashlib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r", encoding="utf-8") as _env_file:
        for _line in _env_file:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip().strip("'\""))

APP_NAME = "CyberShield"
ORGANIZATION_NAME = "CyberShield Technologies"
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

DB_BACKEND = os.environ.get("CYBERSHIELD_DB_BACKEND", "auto").strip().lower()
MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://127.0.0.1:27017/").strip()
MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "cybershield").strip() or "cybershield"

DEFAULT_USERS = (
    (
        os.environ.get("CYBERSHIELD_ADMIN_USER", "admin"),
        os.environ.get("CYBERSHIELD_ADMIN_PASSWORD", "admin123"),
        os.environ.get("CYBERSHIELD_ADMIN_EMAIL", "admin@cybershield.local"),
        "ADMIN",
    ),
    (
        os.environ.get("CYBERSHIELD_ANALYST_USER", "analyst"),
        os.environ.get("CYBERSHIELD_ANALYST_PASSWORD", "analyst123"),
        os.environ.get("CYBERSHIELD_ANALYST_EMAIL", "analyst@cybershield.local"),
        "SOC_ANALYST",
    ),
    (
        os.environ.get("CYBERSHIELD_EMPLOYEE_USER", "john"),
        os.environ.get("CYBERSHIELD_EMPLOYEE_PASSWORD", "john123"),
        os.environ.get("CYBERSHIELD_EMPLOYEE_EMAIL", "john@cybershield.local"),
        "EMPLOYEE",
    ),
    ("alice", "alice123", "alice@cybershield.local", "EMPLOYEE"),
    ("bob", "bob123", "bob@cybershield.local", "EMPLOYEE"),
)

SECRET_KEY = os.environ.get("CYBERSHIELD_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = hashlib.sha256(f"cybershield-local-secret:{BASE_DIR}".encode("utf-8")).hexdigest()

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = os.environ.get("CYBERSHIELD_HTTPS", "0").lower() in {"1", "true", "yes"}

CSRF_TIME_LIMIT = int(os.environ.get("CYBERSHIELD_CSRF_SECONDS", "3600"))

PLATFORM_LOGIN_MAX_FAILURES = 8
PLATFORM_LOGIN_WINDOW = 300

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60

SQLI_PATTERNS = (
    "' OR 1=1",
    '" OR 1=1',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 'a'='a",
    "UNION SELECT",
    "UNION ALL SELECT",
    "DROP TABLE",
    "DROP DATABASE",
    "ORDER BY ",
    "INFORMATION_SCHEMA",
    "SLEEP(",
    "--",
)

XSS_PATTERNS = (
    "<script",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onmouseover=",
    "onfocus=",
    "<img",
    "<svg",
    "<iframe",
    "<body",
)

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ALERT_STATUSES = ("NEW", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")
INCIDENT_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED")
USER_ROLES = ("ADMIN", "SOC_ANALYST", "EMPLOYEE")
USER_STATUSES = ("ACTIVE", "LOCKED", "DISABLED")

SIMULATED_HOSTS = {
    "attacker01": {"hostname": "attacker-01", "ip": "203.0.113.45", "type": "External Attacker"},
    "attacker02": {"hostname": "attacker-02", "ip": "198.51.100.27", "type": "External Attacker"},
    "workstation01": {"hostname": "workstation-01", "ip": "192.168.10.77", "type": "Employee Workstation"},
}

DEFAULT_ASSETS = (
    {"name": "Employee Web Portal", "type": "Web Application", "ip_address": "192.168.10.10", "description": "Controlled simulated employee-facing web application.", "status": "ONLINE"},
    {"name": "Web Server", "type": "Server", "ip_address": "192.168.10.20", "description": "Simulated application server.", "status": "ONLINE"},
    {"name": "Database Server", "type": "Database", "ip_address": "192.168.10.30", "description": "Simulated backend database server.", "status": "ONLINE"},
)

DEFAULT_IOCS = (
    {"type": "IP", "value": "203.0.113.45", "reputation": "SUSPICIOUS", "confidence": 85, "description": "Known simulated brute-force source.", "source": "CyberShield IOC Database"},
    {"type": "IP", "value": "198.51.100.27", "reputation": "MALICIOUS", "confidence": 92, "description": "Known simulated attack source.", "source": "CyberShield IOC Database"},
    {"type": "IP", "value": "192.168.10.77", "reputation": "INTERNAL", "confidence": 100, "description": "Simulated employee workstation.", "source": "CyberShield Asset Inventory"},
)
