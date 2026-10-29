from functools import wraps
from time import monotonic

from flask import abort, redirect, session, url_for
from werkzeug.security import check_password_hash

from database import get_user
from config import PLATFORM_LOGIN_MAX_FAILURES, PLATFORM_LOGIN_WINDOW

SOC_ALLOWED_ROLES = {"ADMIN", "SOC_ANALYST"}
_platform_failures = {}


def _key(username, source_ip):
    return f"{source_ip}:{username.lower()}"


def _locked_out(username, source_ip):
    key = _key(username, source_ip)
    attempts = _platform_failures.get(key, [])
    cutoff = monotonic() - PLATFORM_LOGIN_WINDOW
    attempts = [timestamp for timestamp in attempts if timestamp >= cutoff]
    _platform_failures[key] = attempts
    return len(attempts) >= PLATFORM_LOGIN_MAX_FAILURES


def _record_failure(username, source_ip):
    key = _key(username, source_ip)
    attempts = _platform_failures.setdefault(key, [])
    cutoff = monotonic() - PLATFORM_LOGIN_WINDOW
    attempts[:] = [timestamp for timestamp in attempts if timestamp >= cutoff]
    attempts.append(monotonic())


def _verify_password(user, password):
    if not user or not password:
        return False
    try:
        return check_password_hash(user["password"], password)
    except (TypeError, ValueError):
        return False


def authenticate(username, password, source_ip="unknown"):
    username = (username or "").strip()
    if not username or not password:
        return None, "Invalid username or password."
    if _locked_out(username, source_ip):
        return None, "Too many failed login attempts. Try again later."
    user = get_user(username)
    if user and user.get("status") == "LOCKED":
        _record_failure(username, source_ip)
        return None, "Account is locked."
    valid = bool(user and user.get("status") == "ACTIVE" and _verify_password(user, password))
    if not valid:
        _record_failure(username, source_ip)
        return None, "Invalid username or password."
    if user.get("role") not in SOC_ALLOWED_ROLES:
        return None, "SOC console access is restricted to SOC Analysts and Administrators."
    _platform_failures.pop(_key(username, source_ip), None)
    return user, None


def authenticate_portal_user(username, password, source_ip="unknown"):
    username = (username or "").strip()
    if not username or not password:
        return None, "Invalid username or password."
    user = get_user(username)
    if user and user.get("status") == "LOCKED":
        return None, "Account is locked."
    if not user or user.get("status") != "ACTIVE" or not _verify_password(user, password):
        return None, "Invalid username or password."
    if user.get("role") != "EMPLOYEE":
        return None, "This account is not an employee portal account."
    return user, None


def login_user(user):
    if not user:
        return
    session["soc_user_id"] = user["id"]
    session["soc_username"] = user["username"]
    session["soc_role"] = user["role"]


def logout_user():
    session.pop("soc_user_id", None)
    session.pop("soc_username", None)
    session.pop("soc_role", None)


def portal_login_user(user):
    if not user:
        return
    session["portal_user_id"] = user["id"]
    session["portal_username"] = user["username"]
    session["portal_role"] = user["role"]


def portal_logout_user():
    session.pop("portal_user_id", None)
    session.pop("portal_username", None)
    session.pop("portal_role", None)


def is_authenticated():
    return bool(session.get("soc_user_id"))


def current_user():
    if not is_authenticated():
        return None
    user = get_user(session.get("soc_username"))
    if not user or user.get("status") != "ACTIVE" or user.get("role") not in SOC_ALLOWED_ROLES:
        return None
    return user


def current_role():
    user = current_user()
    return user.get("role") if user else None


def portal_user():
    user_id = session.get("portal_user_id")
    if not user_id:
        return None
    username = session.get("portal_username")
    user = get_user(username) if username else None
    if not user or user.get("status") != "ACTIVE" or user.get("role") != "EMPLOYEE":
        return None
    return user


def role_required(*allowed_roles):
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            user = current_user()
            if not user:
                logout_user()
                return redirect(url_for("login"))
            if user["role"] not in allowed_roles:
                abort(403)
            return view_function(*args, **kwargs)
        return wrapped_view
    return decorator


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user:
            logout_user()
            return redirect(url_for("login"))
        return view_function(*args, **kwargs)
    return wrapped_view


def portal_login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        user = portal_user()
        if not user:
            portal_logout_user()
            return redirect(url_for("portal_login"))
        return view_function(*args, **kwargs)
    return wrapped_view
