EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILURE = "LOGIN_FAILURE"
EVENT_WEB_REQUEST = "WEB_REQUEST"
EVENT_SQL_INJECTION = "SQL_INJECTION_ATTEMPT"
EVENT_XSS = "XSS_ATTEMPT"
EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
EVENT_IP_BLOCKED = "IP_BLOCKED"
EVENT_SYSTEM = "SYSTEM"

from database import create_log


def log_event(event_type, source_ip=None, username=None, asset_id=None, endpoint=None, method=None, status_code=None, request_data=None, message="", detect=True):
    log_id = create_log(
        source_ip=source_ip,
        username=username,
        asset_id=asset_id,
        endpoint=endpoint,
        method=method,
        event_type=event_type,
        status_code=status_code,
        request_data=request_data,
        message=message,
    )
    if detect:
        from detection import run_detection
        run_detection()
    return log_id


def log_login_success(source_ip, username, asset_id, endpoint="/portal/login"):
    return log_event(EVENT_LOGIN_SUCCESS, source_ip, username, asset_id, endpoint, "POST", 200, None, "Successful login.")


def log_login_failure(source_ip, username, asset_id, endpoint="/portal/login"):
    return log_event(EVENT_LOGIN_FAILURE, source_ip, username, asset_id, endpoint, "POST", 401, None, "Failed login attempt.")


def log_web_request(source_ip, username, asset_id, endpoint, method, status_code, request_data=None, message="Web request."):
    return log_event(EVENT_WEB_REQUEST, source_ip, username, asset_id, endpoint, method, status_code, request_data, message)


def log_sql_injection_attempt(source_ip, username, asset_id, endpoint, method, request_data):
    return log_event(EVENT_SQL_INJECTION, source_ip, username, asset_id, endpoint, method, 400, request_data, "Potential SQL injection input detected.")


def log_xss_attempt(source_ip, username, asset_id, endpoint, method, request_data):
    return log_event(EVENT_XSS, source_ip, username, asset_id, endpoint, method, 400, request_data, "Potential XSS input detected.")


def log_ip_blocked(source_ip, asset_id=None, username=None):
    return log_event(EVENT_IP_BLOCKED, source_ip, username, asset_id, None, None, None, None, "Source IP blocked by SOC response.", detect=False)


def log_ip_unblocked(source_ip, username=None):
    return log_event(EVENT_SYSTEM, source_ip, username, None, None, None, None, None, f"Source IP {source_ip} unblocked by SOC.", detect=False)


def log_account_locked(username, asset_id=None, source_ip=None):
    return log_event(EVENT_ACCOUNT_LOCKED, source_ip, username, asset_id, None, None, None, None, "Employee account locked by SOC response.", detect=False)


def log_account_unlocked(username, actor_username=None):
    actor_info = f" by {actor_username}" if actor_username else ""
    return log_event(EVENT_SYSTEM, None, username, None, None, None, None, None, f"Account {username} unlocked{actor_info}.", detect=False)


def log_blocked_request(source_ip, username, asset_id, endpoint, method):
    return log_event(EVENT_IP_BLOCKED, source_ip, username, asset_id, endpoint, method, 403, None, f"Request from blocked IP {source_ip} rejected by SOC containment policy.", detect=False)


def log_system_event(message, source_ip=None, username=None, asset_id=None):
    return log_event(EVENT_SYSTEM, source_ip, username, asset_id, None, None, None, None, message, detect=False)
