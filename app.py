from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect, CSRFError

from config import (
    SECRET_KEY, APP_NAME, ORGANIZATION_NAME, SIMULATED_HOSTS,
    SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE, SESSION_COOKIE_SECURE,
    CSRF_TIME_LIMIT, SQLI_PATTERNS, XSS_PATTERNS, INCIDENT_STATUSES,
)
from database import (
    init_db, get_asset, get_user, get_logs, get_logs_for_alert, get_alert,
    get_alerts, get_incidents, get_users, get_assets, get_iocs,
    get_incident_actions, get_blocked_ips, is_ip_blocked, create_ioc,
    count_logs, count_alerts, count_open_incidents,
)
from auth import (
    authenticate, authenticate_portal_user, login_user, logout_user,
    portal_login_user, portal_logout_user, current_user, current_role, portal_user,
    role_required, login_required, portal_login_required,
)
from logging_service import (
    log_event, log_login_success, log_login_failure, log_sql_injection_attempt,
    log_xss_attempt, log_web_request, log_blocked_request, log_system_event,
)
from detection import run_detection, contains_pattern
from threat_intel import enrich_alert, get_ioc_summary, lookup_indicator, get_all_iocs
from incident_response import (
    open_incident, advance_incident, record_findings, block_source_ip,
    unblock_source_ip, lock_target_account, set_user_account_status,
    set_alert_status, record_remediation, record_verification,
    get_incident_details, get_actions,
)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    APP_NAME=APP_NAME,
    ORGANIZATION_NAME=ORGANIZATION_NAME,
    SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    WTF_CSRF_TIME_LIMIT=CSRF_TIME_LIMIT,
    SEND_FILE_MAX_AGE_DEFAULT=0,
)
csrf = CSRFProtect(app)
init_db()


@app.context_processor
def inject_context():
    soc_user = current_user()
    p_user = portal_user()
    return {
        "app_name": APP_NAME,
        "organization_name": ORGANIZATION_NAME,
        "current_username": soc_user["username"] if soc_user else None,
        "current_role": current_role(),
        "portal_username": p_user["username"] if p_user else None,
        "active_endpoint": request.endpoint or "",
    }


def render_error(message, status_code):
    return render_template("error.html", message=message, status_code=status_code), status_code


def get_simulated_ip():
    host_key = session.get("simulated_host", "attacker01")
    return SIMULATED_HOSTS.get(host_key, SIMULATED_HOSTS["attacker01"])["ip"]


def get_portal_asset():
    return get_asset(1)


@app.route("/")
def index():
    return redirect(url_for("dashboard")) if current_user() else redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"
        user, error = authenticate(username, password, client_ip)
        if user:
            login_user(user)
            log_login_success(client_ip, user["username"], None, endpoint="/login")
            return redirect(url_for("dashboard"))
        if username:
            log_event(
                "LOGIN_FAILURE", client_ip, username, None, "/login", "POST",
                401, None, "Failed SOC console login attempt.", detect=False,
            )
        return render_template("login.html", error=error)
    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    user = current_user()
    if user:
        log_system_event(f"SOC user {user['username']} signed out.", request.remote_addr or "127.0.0.1", user["username"])
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@role_required("ADMIN", "SOC_ANALYST")
def dashboard():
    run_detection()
    logs = get_logs(200)
    alerts = get_alerts()
    incidents = get_incidents()
    blocked_ips = get_blocked_ips()
    high_alerts = [a for a in alerts if a.get("severity") in {"HIGH", "CRITICAL"} and a.get("status") not in {"RESOLVED", "FALSE_POSITIVE"}]
    stats = {
        "logs": count_logs(),
        "alerts": count_alerts(),
        "high_alerts": len(high_alerts),
        "incidents": count_open_incidents(),
        "closed_incidents": sum(1 for i in incidents if i.get("status") == "CLOSED"),
        "blocked_ips": len(blocked_ips),
    }
    return render_template(
        "dashboard.html",
        logs=logs,
        recent_logs=logs[:8],
        alerts=alerts,
        incidents=incidents,
        blocked_ips=blocked_ips,
        stats=stats,
    )


@app.route("/logs")
@role_required("ADMIN", "SOC_ANALYST")
def logs():
    event_type = request.args.get("event_type", "").strip()
    source_ip = request.args.get("source_ip", "").strip()
    search = request.args.get("q", "").strip()
    filtered_logs = get_logs(
        500,
        event_type=event_type or None,
        source_ip=source_ip or None,
        search=search or None,
    )
    return render_template(
        "logs.html",
        logs=filtered_logs,
        selected_event_type=event_type,
        selected_source_ip=source_ip,
        search_query=search,
    )


@app.route("/alerts")
@role_required("ADMIN", "SOC_ANALYST")
def alerts():
    run_detection()
    return render_template("alerts.html", alerts=get_alerts())


@app.post("/alerts/<int:alert_id>/investigate")
@role_required("ADMIN", "SOC_ANALYST")
def investigate_alert(alert_id):
    alert = get_alert(alert_id)
    if not alert:
        return render_error("Alert not found.", 404)
    incident_id = open_incident(alert_id, current_user()["id"])
    if not incident_id:
        return render_error("Unable to create incident.", 500)
    return redirect(url_for("investigation", incident_id=incident_id))


@app.post("/alerts/<int:alert_id>/status")
@role_required("ADMIN", "SOC_ANALYST")
def update_alert(alert_id):
    status = request.form.get("status", "").strip().upper()
    success, message = set_alert_status(alert_id, status)
    if not success:
        flash(message, "danger")
    else:
        flash(message, "success")
    return redirect(url_for("alerts"))


@app.route("/investigation/<int:incident_id>")
@role_required("ADMIN", "SOC_ANALYST")
def investigation(incident_id):
    incident = get_incident_details(incident_id)
    if not incident:
        return render_error("Incident not found.", 404)
    alert = get_alert(incident["alert_id"])
    if not alert:
        return render_error("Associated alert not found.", 404)
    target = (incident.get("target") or "").strip()
    if target.startswith("/"):
        related_logs = get_logs_for_alert(incident.get("source_ip"), endpoint=target)
        target_user = None
    else:
        related_logs = get_logs_for_alert(incident.get("source_ip"), username=target or None)
        target_user = get_user(target) if target else None
    enriched = enrich_alert(alert)
    return render_template(
        "investigations.html",
        incident=incident,
        alert=alert,
        related_logs=related_logs,
        ioc=get_ioc_summary(enriched),
        actions=get_actions(incident_id),
        is_source_blocked=bool(is_ip_blocked(incident.get("source_ip"))),
        target_user=target_user,
    )


@app.route("/incidents")
@role_required("ADMIN", "SOC_ANALYST")
def incidents():
    blocked = get_blocked_ips()
    blocked_set = {b["ip_address"] for b in blocked}
    return render_template(
        "incidents.html",
        incidents=get_incidents(),
        blocked_ips=blocked,
        blocked_ip_set=blocked_set,
    )


def _handle_incident_result(incident_id, success, message):
    if not success:
        if message == "Incident not found.":
            return render_error(message, 404)
        flash(message, "danger")
    else:
        flash(message, "success")
    if request.form.get("return_to") == "incidents":
        return redirect(url_for("incidents"))
    return redirect(url_for("investigation", incident_id=incident_id))


@app.post("/incidents/<int:incident_id>/status")
@role_required("ADMIN", "SOC_ANALYST")
def incident_status(incident_id):
    status = request.form.get("status", "").strip().upper()
    if status not in INCIDENT_STATUSES:
        return render_error("Invalid incident status.", 400)
    success, message = advance_incident(incident_id, status, current_user()["id"])
    return _handle_incident_result(incident_id, success, message)


@app.post("/incidents/<int:incident_id>/findings")
@role_required("ADMIN", "SOC_ANALYST")
def incident_findings(incident_id):
    success, message = record_findings(
        incident_id,
        request.form.get("findings", ""),
        request.form.get("root_cause", ""),
        current_user()["id"],
    )
    return _handle_incident_result(incident_id, success, message)


@app.post("/incidents/<int:incident_id>/block-ip")
@role_required("ADMIN", "SOC_ANALYST")
def block_ip(incident_id):
    success, message = block_source_ip(incident_id, current_user()["id"])
    return _handle_incident_result(incident_id, success, message)


@app.post("/blocked-ips/unblock")
@role_required("ADMIN", "SOC_ANALYST")
def unblock_ip_route():
    ip_address = request.form.get("ip_address", "").strip()
    success, message = unblock_source_ip(ip_address, current_user()["username"])
    flash(message, "success" if success else "danger")
    next_page = request.form.get("return_to", "")
    if next_page == "assets":
        return redirect(url_for("assets"))
    if next_page == "investigation" and request.form.get("incident_id", "").isdigit():
        return redirect(url_for("investigation", incident_id=int(request.form.get("incident_id"))))
    return redirect(url_for("incidents"))


@app.post("/incidents/<int:incident_id>/lock-account")
@role_required("ADMIN", "SOC_ANALYST")
def lock_account(incident_id):
    success, message = lock_target_account(incident_id, current_user()["id"])
    return _handle_incident_result(incident_id, success, message)


@app.post("/incidents/<int:incident_id>/remediation")
@role_required("ADMIN", "SOC_ANALYST")
def remediation(incident_id):
    success, message = record_remediation(
        incident_id,
        request.form.get("remediation", ""),
        current_user()["id"],
    )
    return _handle_incident_result(incident_id, success, message)


@app.post("/incidents/<int:incident_id>/verify")
@role_required("ADMIN", "SOC_ANALYST")
def verify_incident(incident_id):
    success, message = record_verification(
        incident_id,
        request.form.get("verification", ""),
        current_user()["id"],
    )
    return _handle_incident_result(incident_id, success, message)


@app.route("/threat-intel", methods=["GET", "POST"])
@role_required("ADMIN", "SOC_ANALYST")
def threat_intel():
    search_value = ""
    lookup_result = None
    if request.method == "POST":
        search_value = request.form.get("indicator", "").strip()
        if search_value:
            lookup_result = get_ioc_summary(lookup_indicator(search_value))
    return render_template("threat_intel.html", search_value=search_value, lookup_result=lookup_result, iocs=get_all_iocs())


@app.post("/threat-intel/add")
@role_required("ADMIN", "SOC_ANALYST")
def add_threat_intel():
    ioc_type = request.form.get("type", "IP").strip().upper()
    value = request.form.get("value", "").strip()
    reputation = request.form.get("reputation", "SUSPICIOUS").strip().upper()
    confidence = request.form.get("confidence", "80").strip()
    description = request.form.get("description", "").strip()
    source = request.form.get("source", "CyberShield Analyst").strip() or "CyberShield Analyst"
    try:
        create_ioc(ioc_type, value, reputation, int(confidence), description, source)
        flash(f"Indicator {value} saved to IOC database.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("threat_intel"))


@app.route("/users")
@role_required("ADMIN")
def users():
    return render_template("users.html", users=get_users())


@app.post("/users/<username>/status")
@role_required("ADMIN")
def update_user_status_route(username):
    status = request.form.get("status", "").strip().upper()
    actor = current_user()
    if actor and actor["username"] == username and status != "ACTIVE":
        flash("Cannot lock or disable your own active administrator account.", "danger")
        return redirect(url_for("users"))
    success, message = set_user_account_status(username, status, actor["username"] if actor else None)
    flash(message, "success" if success else "danger")
    if request.form.get("return_to") == "investigation" and request.form.get("incident_id", "").isdigit():
        return redirect(url_for("investigation", incident_id=int(request.form.get("incident_id"))))
    return redirect(url_for("users"))


@app.route("/assets")
@role_required("ADMIN", "SOC_ANALYST")
def assets():
    return render_template("assets.html", assets=get_assets(), blocked_ips=get_blocked_ips())


# ------------------------ portal --------------------------------

@app.route("/portal")
def portal_home():
    source_ip = get_simulated_ip()
    return render_template(
        "vulnerable/home.html",
        simulated_hosts=SIMULATED_HOSTS,
        selected_host=session.get("simulated_host", "attacker01"),
        source_ip=source_ip,
        is_source_blocked=bool(is_ip_blocked(source_ip)),
    )


@app.post("/portal/source")
def select_simulated_source():
    host_key = request.form.get("simulated_host", "")
    if host_key not in SIMULATED_HOSTS:
        return render_error("Invalid simulated host.", 400)
    session["simulated_host"] = host_key
    return redirect(url_for("portal_home"))


@app.route("/portal/login", methods=["GET", "POST"])
def portal_login():
    existing = portal_user()
    if existing and request.method == "GET":
        return redirect(url_for("portal_home"))
    error = None
    source_ip = get_simulated_ip()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        asset = get_portal_asset()
        if not asset:
            return render_error("Vulnerable portal asset is unavailable.", 500)
        if is_ip_blocked(source_ip):
            log_blocked_request(source_ip, username or None, asset["id"], "/portal/login", "POST")
            return render_template(
                "vulnerable/login.html",
                error=f"Connection refused: Source IP {source_ip} is blocked by CyberShield SOC containment policy.",
                username=username,
                is_source_blocked=True,
            ), 403
        user = get_user(username)
        if user and user.get("status") == "LOCKED":
            log_login_failure(source_ip, username, asset["id"])
            return render_template("vulnerable/login.html", error="Account is locked by SOC security policy.", username=username)
        user, error = authenticate_portal_user(username, password, source_ip)
        if user:
            portal_login_user(user)
            log_login_success(source_ip, username, asset["id"])
            return redirect(url_for("portal_home"))
        if error == "Invalid username or password.":
            log_login_failure(source_ip, username, asset["id"])
        return render_template("vulnerable/login.html", error=error, username=username)
    return render_template("vulnerable/login.html", is_source_blocked=bool(is_ip_blocked(source_ip)))


@app.post("/portal/logout")
def portal_logout():
    portal_logout_user()
    return redirect(url_for("portal_home"))


@app.route("/portal/search", methods=["GET", "POST"])
@portal_login_required
def portal_search():
    query = request.form.get("q", request.form.get("query", "")) if request.method == "POST" else request.args.get("q", request.args.get("query", ""))
    query = (query or "").strip()
    results = None
    injection_detected = False
    blocked_error = None
    source_ip = get_simulated_ip()
    if query:
        asset = get_portal_asset()
        if not asset:
            return render_error("Vulnerable portal asset is unavailable.", 500)
        method = request.method
        username = portal_user()["username"] if portal_user() else None
        if is_ip_blocked(source_ip):
            log_blocked_request(source_ip, username, asset["id"], "/portal/search", method)
            blocked_error = f"Access denied: Source IP {source_ip} is blocked by CyberShield SOC containment policy."
            return render_template(
                "vulnerable/search.html",
                results=None,
                query=query,
                injection_detected=False,
                blocked_error=blocked_error,
            ), 403
        injection_detected = contains_pattern(query, SQLI_PATTERNS)
        if injection_detected:
            log_sql_injection_attempt(source_ip, username, asset["id"], "/portal/search", method, query)
        else:
            log_web_request(source_ip, username, asset["id"], "/portal/search", method, 200, query, "Employee directory search.")
        all_users = get_users()
        if injection_detected:
            results = all_users
        else:
            q = query.lower()
            results = [
                u for u in all_users
                if u.get("role") == "EMPLOYEE"
                and (q in u["username"].lower() or q in u["email"].lower() or q in u["role"].lower())
            ]
    return render_template(
        "vulnerable/search.html",
        results=results,
        query=query,
        injection_detected=injection_detected,
        blocked_error=blocked_error,
    )


@app.route("/portal/feedback", methods=["GET", "POST"])
@portal_login_required
def portal_feedback():
    submitted_feedback = None
    name = email = feedback = ""
    detected = False
    source_ip = get_simulated_ip()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        feedback = request.form.get("feedback", "")
        asset = get_portal_asset()
        if not asset:
            return render_error("Vulnerable portal asset is unavailable.", 500)
        username = portal_user()["username"] if portal_user() else None
        if is_ip_blocked(source_ip):
            log_blocked_request(source_ip, username, asset["id"], "/portal/feedback", "POST")
            return render_template(
                "vulnerable/feedback.html",
                error=f"Access denied: Source IP {source_ip} is blocked by CyberShield SOC containment policy.",
                name=name,
                email=email,
                feedback=feedback,
            ), 403
        if not name or not email or not feedback:
            return render_template("vulnerable/feedback.html", error="All fields are required.", name=name, email=email, feedback=feedback)
        request_data = f"name={name}&email={email}&feedback={feedback}"
        detected = contains_pattern(request_data, XSS_PATTERNS)
        if detected:
            log_xss_attempt(source_ip, username, asset["id"], "/portal/feedback", "POST", request_data)
        else:
            log_web_request(source_ip, username, asset["id"], "/portal/feedback", "POST", 200, request_data, "Employee feedback submitted.")
        # Safe rendering: the lab simulates XSS detection without creating
        # an actual stored-XSS sink in the application.
        submitted_feedback = feedback
    return render_template("vulnerable/feedback.html", submitted_feedback=submitted_feedback, detected=detected, name=name, email=email, feedback=feedback)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return render_template("error.html", status_code=400, message="Security token expired or missing. Please refresh and try again."), 400


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", status_code=400, message="Bad request."), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", status_code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", status_code=404, message="Page not found."), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("error.html", status_code=500, message="Internal server error."), 500


if __name__ == "__main__":
    print(f"{APP_NAME} starting...")
    print("SOC platform: http://127.0.0.1:5000/login")
    print("Vulnerable portal: http://127.0.0.1:5000/portal")
    app.run(host="127.0.0.1", port=5000, debug=False)
