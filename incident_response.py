from datetime import datetime, timezone

from config import INCIDENT_STATUSES, ALERT_STATUSES, USER_STATUSES
from database import (
    get_alert, get_incident, get_incidents, create_incident, update_incident,
    update_alert_status, update_user_status, get_user, create_incident_action,
    get_incident_actions, block_ip, unblock_ip, is_ip_blocked,
)
from detection import mark_logs_handled
from logging_service import (
    log_ip_blocked, log_ip_unblocked, log_account_locked, log_account_unlocked,
)

STATUS_ORDER = {status: index for index, status in enumerate(INCIDENT_STATUSES)}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def can_transition(current_status, new_status):
    return (
        current_status in STATUS_ORDER
        and new_status in STATUS_ORDER
        and STATUS_ORDER[new_status] == STATUS_ORDER[current_status] + 1
    )


def _record_action(incident_id, actor_user_id, action_type, description):
    create_incident_action(incident_id, actor_user_id, action_type, description)


def open_incident(alert_id, assigned_to=None):
    alert = get_alert(alert_id)
    if not alert:
        return None
    for incident in get_incidents():
        if incident.get("alert_id") == alert_id:
            return incident["id"]
    incident_id = create_incident(
        alert_id, f"{alert['alert_type']} Security Incident", alert["severity"], assigned_to
    )
    update_alert_status(alert_id, "INVESTIGATING")
    _record_action(incident_id, assigned_to, "INCIDENT_OPENED", f"Incident opened from alert #{alert_id}.")
    return incident_id


def advance_incident(incident_id, new_status, actor_user_id=None):
    incident = get_incident(incident_id)
    if not incident:
        return False, "Incident not found."
    current = incident["status"]
    if not can_transition(current, new_status):
        return False, f"Invalid transition: {current} → {new_status}."
    if new_status == "CONTAINED":
        if not (incident.get("findings") or "").strip():
            return False, "Record investigation findings before containment."
        if not (incident.get("response_action") or "").strip():
            return False, "Perform at least one containment action before containment."
    if new_status == "RESOLVED" and not (incident.get("remediation") or "").strip():
        return False, "Record remediation before resolving the incident."
    if new_status == "CLOSED" and not (incident.get("verification") or "").strip():
        return False, "Record verification before closing the incident."
    closed_at = now() if new_status == "CLOSED" else None
    update_incident(incident_id, status=new_status, closed_at=closed_at)
    if new_status == "RESOLVED":
        update_alert_status(incident["alert_id"], "RESOLVED")
        mark_logs_handled(incident.get("alert_type"), incident.get("source_ip"), incident.get("target"))
    _record_action(incident_id, actor_user_id, "STATUS_CHANGE", f"Incident status changed from {current} to {new_status}.")
    if new_status == "CLOSED":
        mark_logs_handled(incident.get("alert_type"), incident.get("source_ip"), incident.get("target"))
        _record_action(incident_id, actor_user_id, "INCIDENT_CLOSED", "Incident closed after successful verification.")
    return True, f"Incident moved to {new_status}."


def record_findings(incident_id, findings, root_cause=None, actor_user_id=None):
    incident = get_incident(incident_id)
    if not incident:
        return False, "Incident not found."
    if incident["status"] not in ("NEW", "INVESTIGATING"):
        return False, "Findings can only be updated before containment."
    if not findings or not findings.strip():
        return False, "Investigation findings are required."
    update_incident(incident_id, findings=findings.strip(), root_cause=(root_cause or "").strip() or None)
    _record_action(incident_id, actor_user_id, "FINDINGS_RECORDED", "Investigation findings and root cause recorded.")
    return True, "Investigation findings recorded."


def _append_response_action(incident, action):
    existing = (incident.get("response_action") or "").strip()
    timestamped = f"[{now()}] {action}"
    combined = f"{existing}\n{timestamped}" if existing else timestamped
    update_incident(incident["id"], response_action=combined)
    return combined


def block_source_ip(incident_id, actor_user_id=None):
    incident = get_incident(incident_id)
    if not incident:
        return False, "Incident not found."
    if incident["status"] != "INVESTIGATING":
        return False, "Start the investigation before applying containment."
    source_ip = incident.get("source_ip")
    if not source_ip:
        return False, "Incident has no source IP."
    existing_actions = incident.get("response_action") or ""
    if is_ip_blocked(source_ip):
        if source_ip in existing_actions:
            return False, f"Source IP {source_ip} is already blocked."
        action = f"Confirmed active IP block on {source_ip} for incident containment."
        _append_response_action(incident, action)
        _record_action(incident_id, actor_user_id, "IP_BLOCKED", action)
        return True, action
    action = f"Simulated IP block applied to {source_ip}."
    block_ip(source_ip, incident_id, actor_user_id, action)
    _append_response_action(incident, action)
    _record_action(incident_id, actor_user_id, "IP_BLOCKED", action)
    log_ip_blocked(source_ip, incident.get("asset_id"), incident.get("target"))
    return True, action


def unblock_source_ip(ip_address, actor_username=None):
    ip_address = (ip_address or "").strip()
    if not ip_address or not is_ip_blocked(ip_address):
        return False, "IP address is not currently blocked."
    unblock_ip(ip_address)
    log_ip_unblocked(ip_address, actor_username)
    return True, f"Source IP {ip_address} has been unblocked."


def lock_target_account(incident_id, actor_user_id=None):
    incident = get_incident(incident_id)
    if not incident:
        return False, "Incident not found."
    if incident["status"] != "INVESTIGATING":
        return False, "Start the investigation before applying containment."
    username = (incident.get("target") or "").strip()
    if not username or username.startswith("/"):
        return False, "Incident has no target user account."
    user = get_user(username)
    if not user:
        return False, "Target account not found."
    existing_actions = incident.get("response_action") or ""
    if user["status"] == "LOCKED":
        if f"Account {username}" in existing_actions:
            return False, f"Account {username} is already locked."
        action = f"Account {username} confirmed locked for incident containment."
        _append_response_action(incident, action)
        _record_action(incident_id, actor_user_id, "ACCOUNT_LOCKED", action)
        return True, action
    update_user_status(username, "LOCKED")
    action = f"Account {username} was locked as a simulated containment action."
    _append_response_action(incident, action)
    _record_action(incident_id, actor_user_id, "ACCOUNT_LOCKED", action)
    log_account_locked(username, incident.get("asset_id"), incident.get("source_ip"))
    return True, action


def set_user_account_status(username, status, actor_username=None):
    username = (username or "").strip()
    status = (status or "").strip().upper()
    if status not in USER_STATUSES:
        return False, "Invalid account status."
    user = get_user(username)
    if not user:
        return False, "User account not found."
    update_user_status(username, status)
    if status == "ACTIVE":
        log_account_unlocked(username, actor_username)
    elif status == "LOCKED":
        log_account_locked(username)
    return True, f"User {username} status updated to {status}."


def set_alert_status(alert_id, status):
    status = (status or "").strip().upper()
    if status not in ALERT_STATUSES:
        return False, "Invalid alert status."
    alert = get_alert(alert_id)
    if not alert:
        return False, "Alert not found."
    update_alert_status(alert_id, status)
    if status in ("RESOLVED", "FALSE_POSITIVE"):
        mark_logs_handled(alert.get("alert_type"), alert.get("source_ip"), alert.get("target"))
    return True, f"Alert #{alert_id} marked as {status}."


def record_remediation(incident_id, remediation, actor_user_id=None):
    incident = get_incident(incident_id)
    if not incident:
        return False, "Incident not found."
    if incident["status"] != "CONTAINED":
        return False, "Remediation can only be recorded after containment."
    if not remediation or not remediation.strip():
        return False, "Remediation details are required."
    update_incident(incident_id, remediation=remediation.strip())
    _record_action(incident_id, actor_user_id, "REMEDIATION_RECORDED", "Remediation details recorded.")
    return True, "Remediation recorded."


def record_verification(incident_id, verification, actor_user_id=None):
    incident = get_incident(incident_id)
    if not incident:
        return False, "Incident not found."
    if incident["status"] != "RESOLVED":
        return False, "Verification can only be recorded after remediation and resolution."
    if not verification or not verification.strip():
        return False, "Verification result is required."
    update_incident(incident_id, verification=verification.strip())
    _record_action(incident_id, actor_user_id, "VERIFICATION_RECORDED", "Security verification result recorded.")
    return True, "Verification result recorded."


def get_incident_details(incident_id):
    return get_incident(incident_id)


def get_all_incidents():
    return get_incidents()


def get_actions(incident_id):
    return get_incident_actions(incident_id)
