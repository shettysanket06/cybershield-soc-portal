from html import unescape
from urllib.parse import unquote_plus
import re

from config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, SQLI_PATTERNS, XSS_PATTERNS
from database import get_recent_login_failures, get_logs, get_alerts, create_alert

SQLI_REGEXES = (
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I),
    re.compile(r"(?:'|\"|\b)\s*(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.I),
    re.compile(r"\bdrop\s+(?:table|database)\b", re.I),
    re.compile(r"\border\s+by\s+\d+\b", re.I),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.I),
    re.compile(r"(?:--|/\*|\*/)", re.I),
)
XSS_REGEXES = (
    re.compile(r"<\s*script\b", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"\bon(?:error|load|mouseover|focus|click|submit|toggle)\s*=", re.I),
    re.compile(r"<\s*(?:img|svg|iframe|body|object|embed|math)\b", re.I),
)

ACTIVE_ALERT_STATUSES = {"NEW", "ACKNOWLEDGED", "INVESTIGATING"}
_handled_log_ids = {}


def normalize_input(value):
    value = unquote_plus(str(value or ""))
    return unescape(value).lower()


def contains_pattern(value, patterns):
    normalized = normalize_input(value)
    if any(str(pattern).lower() in normalized for pattern in patterns):
        return True
    if patterns is SQLI_PATTERNS:
        return any(regex.search(normalized) for regex in SQLI_REGEXES)
    if patterns is XSS_PATTERNS:
        return any(regex.search(normalized) for regex in XSS_REGEXES)
    return False


def mark_logs_handled(alert_type, source_ip, target, max_log_id=None):
    if max_log_id is None:
        logs = get_logs(1)
        max_log_id = logs[0]["id"] if logs else 0
    key = (alert_type, source_ip, target)
    _handled_log_ids[key] = max(_handled_log_ids.get(key, 0), int(max_log_id))


def _is_log_unhandled(log, alert_type, source_ip, target, all_alerts):
    key = (alert_type, source_ip, target)
    log_id = log.get("id") or 0
    handled_id = _handled_log_ids.get(key, 0)
    if handled_id and log_id <= handled_id:
        return False
    matching_alerts = [
        a for a in all_alerts
        if a.get("alert_type") == alert_type
        and a.get("source_ip") == source_ip
        and a.get("target") == target
    ]
    if not matching_alerts:
        return True
    if any(a.get("status") in ACTIVE_ALERT_STATUSES for a in matching_alerts):
        return False
    if handled_id:
        return log_id > handled_id
    latest_alert_ts = max((a.get("timestamp") or "") for a in matching_alerts)
    return (log.get("timestamp") or "") > latest_alert_ts


def alert_exists(alert_type, source_ip, target):
    return any(
        a.get("alert_type") == alert_type
        and a.get("source_ip") == source_ip
        and a.get("target") == target
        and a.get("status") in ACTIVE_ALERT_STATUSES
        for a in get_alerts()
    )


def _create_alert(alert_type, severity, source_ip, target, asset_id, rule, description, max_log_id=None):
    if alert_exists(alert_type, source_ip, target):
        return None
    alert_id = create_alert(alert_type, severity, source_ip, target, asset_id, rule, description)
    if alert_id and max_log_id is not None:
        mark_logs_handled(alert_type, source_ip, target, max_log_id)
    return alert_id


def detect_brute_force():
    failures = get_recent_login_failures(BRUTE_FORCE_WINDOW)
    if not failures:
        return []
    all_alerts = get_alerts()
    groups = {}
    for log in failures:
        source_ip = log.get("source_ip")
        username = log.get("username")
        if _is_log_unhandled(log, "BRUTE_FORCE", source_ip, username, all_alerts):
            groups.setdefault((source_ip, username), []).append(log)
    generated = []
    for (source_ip, username), group in groups.items():
        if len(group) < BRUTE_FORCE_THRESHOLD:
            continue
        first = group[0]
        max_log_id = max(item.get("id") or 0 for item in group)
        alert_id = _create_alert(
            "BRUTE_FORCE", "HIGH", source_ip, username, first.get("asset_id"),
            f"{BRUTE_FORCE_THRESHOLD}+ failed logins within {BRUTE_FORCE_WINDOW} seconds",
            f"Multiple failed login attempts detected from {source_ip} against user {username}.",
            max_log_id=max_log_id,
        )
        if alert_id:
            generated.append(alert_id)
    return generated


def detect_sql_injection():
    generated = []
    all_alerts = get_alerts()
    # Process oldest to newest so the first unhandled attempt triggers and marks up to the latest
    logs = list(reversed(get_logs(1000)))
    for log in logs:
        if log.get("event_type") != "SQL_INJECTION_ATTEMPT":
            continue
        request_data = log.get("request_data") or ""
        if not contains_pattern(request_data, SQLI_PATTERNS):
            continue
        source_ip = log.get("source_ip")
        endpoint = log.get("endpoint")
        if not _is_log_unhandled(log, "SQL_INJECTION", source_ip, endpoint, all_alerts):
            continue
        alert_id = _create_alert(
            "SQL_INJECTION", "HIGH", source_ip, endpoint, log.get("asset_id"),
            "Suspicious SQL injection pattern detected",
            f"Potential SQL injection activity detected from {source_ip} against {endpoint}.",
            max_log_id=log.get("id"),
        )
        if alert_id:
            generated.append(alert_id)
            all_alerts = get_alerts()
    return generated


def detect_xss():
    generated = []
    all_alerts = get_alerts()
    logs = list(reversed(get_logs(1000)))
    for log in logs:
        if log.get("event_type") != "XSS_ATTEMPT":
            continue
        request_data = log.get("request_data") or ""
        if not contains_pattern(request_data, XSS_PATTERNS):
            continue
        source_ip = log.get("source_ip")
        endpoint = log.get("endpoint")
        if not _is_log_unhandled(log, "XSS", source_ip, endpoint, all_alerts):
            continue
        alert_id = _create_alert(
            "XSS", "HIGH", source_ip, endpoint, log.get("asset_id"),
            "Suspicious cross-site scripting pattern detected",
            f"Potential cross-site scripting activity detected from {source_ip} against {endpoint}.",
            max_log_id=log.get("id"),
        )
        if alert_id:
            generated.append(alert_id)
            all_alerts = get_alerts()
    return generated


def run_detection():
    return {
        "brute_force": detect_brute_force(),
        "sql_injection": detect_sql_injection(),
        "xss": detect_xss(),
    }
