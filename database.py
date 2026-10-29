import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash
from config import (
    DATABASE_PATH,
    DB_BACKEND,
    MONGODB_URI,
    MONGODB_DB_NAME,
    DEFAULT_USERS,
    DEFAULT_ASSETS,
    DEFAULT_IOCS,
    ALERT_STATUSES,
    INCIDENT_STATUSES,
    USER_ROLES,
    USER_STATUSES,
    SEVERITIES,
)

try:
    from pymongo import MongoClient, ASCENDING, DESCENDING, ReturnDocument
except ImportError:
    MongoClient = None
    ASCENDING = 1
    DESCENDING = -1
    ReturnDocument = None

_mongo_client = None
_mongo_db = None
_active_backend = "sqlite"


def _utc_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _connect_mongodb():
    global _mongo_client, _mongo_db, _active_backend
    if DB_BACKEND == "sqlite":
        _active_backend = "sqlite"
        return None
    if _mongo_db is not None:
        return _mongo_db
    if MongoClient is None or not MONGODB_URI:
        if DB_BACKEND == "mongodb":
            raise RuntimeError("pymongo is required and MONGODB_URI must be set when CYBERSHIELD_DB_BACKEND=mongodb.")
        _active_backend = "sqlite"
        return None
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=2000, connectTimeoutMS=2000)
        client.admin.command("ping")
        _mongo_client = client
        _mongo_db = client[MONGODB_DB_NAME]
        _active_backend = "mongodb"
        return _mongo_db
    except Exception as exc:
        if DB_BACKEND == "mongodb":
            raise RuntimeError(f"Could not connect to the configured MongoDB instance ({type(exc).__name__}). Check the local connection settings; credentials are intentionally not displayed.") from exc
        _active_backend = "sqlite"
        return None


def get_active_db_backend():
    return _active_backend


def _next_seq(collection_name):
    doc = _mongo_db["_counters"].find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return int(doc["seq"])


def _clean_doc(doc):
    if not doc:
        return None
    result = dict(doc)
    result.pop("_id", None)
    return result


@contextmanager
def get_db():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _init_sqlite_schema():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (role IN ('ADMIN','SOC_ANALYST','EMPLOYEE')),
                CHECK (status IN ('ACTIVE','LOCKED','DISABLED'))
            );
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ONLINE',
                description TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                username TEXT,
                asset_id INTEGER,
                endpoint TEXT,
                method TEXT,
                event_type TEXT NOT NULL,
                status_code INTEGER,
                request_data TEXT,
                message TEXT,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                target TEXT,
                asset_id INTEGER,
                rule TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
                CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                CHECK (status IN ('NEW','ACKNOWLEDGED','INVESTIGATING','RESOLVED','FALSE_POSITIVE'))
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL UNIQUE,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                assigned_to INTEGER,
                status TEXT NOT NULL DEFAULT 'NEW',
                findings TEXT,
                root_cause TEXT,
                response_action TEXT,
                remediation TEXT,
                verification TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                closed_at TEXT,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
                CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
                CHECK (status IN ('NEW','INVESTIGATING','CONTAINED','RESOLVED','CLOSED'))
            );
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                actor_user_id INTEGER,
                action_type TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
                FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                incident_id INTEGER,
                blocked_by INTEGER,
                reason TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
                FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                reputation TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                description TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_username ON logs(username);
            CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_alert_id ON incidents(alert_id);
            CREATE INDEX IF NOT EXISTS idx_incident_actions_incident ON incident_actions(incident_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            """
        )


def _init_mongodb_collections(mdb):
    existing_collections = set(mdb.list_collection_names())
    for coll_name in ("users", "assets", "logs", "alerts", "incidents", "incident_actions", "blocked_ips", "iocs", "_counters"):
        if coll_name not in existing_collections:
            mdb.create_collection(coll_name)
    mdb["users"].create_index([("id", ASCENDING)], unique=True)
    mdb["users"].create_index([("username", ASCENDING)], unique=True)
    mdb["assets"].create_index([("id", ASCENDING)], unique=True)
    mdb["assets"].create_index([("name", ASCENDING)], unique=True)
    mdb["logs"].create_index([("id", DESCENDING)], unique=True)
    mdb["logs"].create_index([("source_ip", ASCENDING)])
    mdb["logs"].create_index([("event_type", ASCENDING)])
    mdb["alerts"].create_index([("id", DESCENDING)], unique=True)
    mdb["incidents"].create_index([("id", DESCENDING)], unique=True)
    mdb["incidents"].create_index([("alert_id", ASCENDING)], unique=True)
    mdb["incident_actions"].create_index([("id", ASCENDING)], unique=True)
    mdb["incident_actions"].create_index([("incident_id", ASCENDING)])
    mdb["blocked_ips"].create_index([("ip_address", ASCENDING)], unique=True)
    mdb["iocs"].create_index([("value", ASCENDING)], unique=True)


def init_db():
    _init_sqlite_schema()
    mdb = _connect_mongodb()
    if mdb is not None:
        _init_mongodb_collections(mdb)
    seed_database()


def execute(query, params=(), *, fetchone=False, fetchall=False):
    with get_db() as db:
        cursor = db.execute(query, params)
        if fetchone:
            row = cursor.fetchone()
            return dict(row) if row else None
        if fetchall:
            return [dict(row) for row in cursor.fetchall()]
        return cursor.lastrowid


def seed_database():
    # Always keep local SQLite seeded
    with get_db() as db:
        for username, plaintext, email, role in DEFAULT_USERS:
            existing = db.execute("SELECT id, password, status FROM users WHERE username = ?", (username,)).fetchone()
            if existing is None:
                password_hash = generate_password_hash(plaintext)
                db.execute(
                    """INSERT INTO users(username,password,email,role,status) VALUES(?,?,?,?, 'ACTIVE')""",
                    (username, password_hash, email, role),
                )
            elif not str(existing["password"] or "").startswith(("scrypt:", "pbkdf2:", "argon2:")):
                password_hash = generate_password_hash(plaintext)
                db.execute("UPDATE users SET password=? WHERE username=?", (password_hash, username))

        for asset in DEFAULT_ASSETS:
            db.execute(
                """INSERT OR IGNORE INTO assets(name,type,ip_address,status,description) VALUES(?,?,?,?,?)""",
                (asset["name"], asset["type"], asset["ip_address"], asset.get("status", "ONLINE"), asset["description"]),
            )

        for ioc in DEFAULT_IOCS:
            db.execute(
                """INSERT OR IGNORE INTO iocs(type,value,reputation,confidence,description,source) VALUES(?,?,?,?,?,?)""",
                (ioc["type"], ioc["value"], ioc["reputation"], ioc["confidence"], ioc["description"], ioc["source"]),
            )

    # If MongoDB is active, also seed MongoDB collections so the database & collections exist immediately
    if _active_backend == "mongodb" and _mongo_db is not None:
        now = _utc_timestamp()
        for username, plaintext, email, role in DEFAULT_USERS:
            existing = _mongo_db["users"].find_one({"username": username})
            if existing is None:
                _mongo_db["users"].insert_one({
                    "id": _next_seq("users"),
                    "username": username,
                    "password": generate_password_hash(plaintext),
                    "email": email,
                    "role": role,
                    "status": "ACTIVE",
                    "created_at": now,
                })
            elif not str(existing.get("password") or "").startswith(("scrypt:", "pbkdf2:", "argon2:")):
                _mongo_db["users"].update_one(
                    {"username": username},
                    {"$set": {"password": generate_password_hash(plaintext)}},
                )

        for asset in DEFAULT_ASSETS:
            if _mongo_db["assets"].find_one({"name": asset["name"]}) is None:
                _mongo_db["assets"].insert_one({
                    "id": _next_seq("assets"),
                    "name": asset["name"],
                    "type": asset["type"],
                    "ip_address": asset["ip_address"],
                    "status": asset.get("status", "ONLINE"),
                    "description": asset["description"],
                    "created_at": now,
                })

        for ioc in DEFAULT_IOCS:
            if _mongo_db["iocs"].find_one({"value": ioc["value"]}) is None:
                _mongo_db["iocs"].insert_one({
                    "id": _next_seq("iocs"),
                    "type": ioc["type"],
                    "value": ioc["value"],
                    "reputation": ioc["reputation"],
                    "confidence": int(ioc["confidence"]),
                    "description": ioc["description"],
                    "source": ioc["source"],
                    "created_at": now,
                })


def create_user(username, password, email, role, status="ACTIVE"):
    username = (username or "").strip()
    email = (email or "").strip()
    if not username or not password or not email:
        raise ValueError("Username, password and email are required.")
    if role not in USER_ROLES:
        raise ValueError("Invalid user role.")
    if status not in USER_STATUSES:
        raise ValueError("Invalid user status.")
    if _active_backend == "mongodb":
        if _mongo_db["users"].find_one({"username": username}):
            raise ValueError(f"User '{username}' already exists.")
        uid = _next_seq("users")
        _mongo_db["users"].insert_one({
            "id": uid,
            "username": username,
            "password": generate_password_hash(password),
            "email": email,
            "role": role,
            "status": status,
            "created_at": _utc_timestamp(),
        })
        return uid
    return execute(
        """INSERT INTO users(username,password,email,role,status) VALUES(?,?,?,?,?)""",
        (username, generate_password_hash(password), email, role, status),
    )


def get_user(username):
    username = (username or "").strip()
    if _active_backend == "mongodb":
        return _clean_doc(_mongo_db["users"].find_one({"username": username}))
    return execute("SELECT * FROM users WHERE username = ?", (username,), fetchone=True)


def get_user_by_id(user_id):
    if _active_backend == "mongodb":
        return _clean_doc(_mongo_db["users"].find_one({"id": int(user_id)}))
    return execute("SELECT * FROM users WHERE id = ?", (user_id,), fetchone=True)


def get_users():
    if _active_backend == "mongodb":
        docs = _mongo_db["users"].find({}, {"password": 0, "_id": 0}).sort("id", ASCENDING)
        return [dict(d) for d in docs]
    return execute("SELECT id,username,email,role,status,created_at FROM users ORDER BY id", fetchall=True)


def update_user_status(username, status):
    if status not in USER_STATUSES:
        raise ValueError("Invalid user status.")
    if _active_backend == "mongodb":
        _mongo_db["users"].update_one({"username": username}, {"$set": {"status": status}})
        return
    execute("UPDATE users SET status=? WHERE username=?", (status, username))


def create_asset(name, asset_type, ip_address, description="", status="ONLINE"):
    if _active_backend == "mongodb":
        aid = _next_seq("assets")
        _mongo_db["assets"].insert_one({
            "id": aid,
            "name": name,
            "type": asset_type,
            "ip_address": ip_address,
            "description": description,
            "status": status,
            "created_at": _utc_timestamp(),
        })
        return aid
    return execute(
        """INSERT INTO assets(name,type,ip_address,description,status) VALUES(?,?,?,?,?)""",
        (name, asset_type, ip_address, description, status),
    )


def get_asset(asset_id):
    if asset_id is None:
        return None
    if _active_backend == "mongodb":
        return _clean_doc(_mongo_db["assets"].find_one({"id": int(asset_id)}))
    return execute("SELECT * FROM assets WHERE id=?", (asset_id,), fetchone=True)


def get_assets():
    if _active_backend == "mongodb":
        return [_clean_doc(d) for d in _mongo_db["assets"].find().sort("id", ASCENDING)]
    return execute("SELECT * FROM assets ORDER BY id", fetchall=True)


def create_log(source_ip=None, username=None, asset_id=None, endpoint=None, method=None, event_type="SYSTEM", status_code=None, request_data=None, message=""):
    if not event_type:
        raise ValueError("event_type is required.")
    if _active_backend == "mongodb":
        lid = _next_seq("logs")
        _mongo_db["logs"].insert_one({
            "id": lid,
            "timestamp": _utc_timestamp(),
            "source_ip": source_ip,
            "username": username,
            "asset_id": asset_id,
            "endpoint": endpoint,
            "method": method,
            "event_type": event_type,
            "status_code": status_code,
            "request_data": request_data,
            "message": message,
        })
        return lid
    return execute(
        """INSERT INTO logs(source_ip,username,asset_id,endpoint,method,event_type,status_code,request_data,message)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (source_ip, username, asset_id, endpoint, method, event_type, status_code, request_data, message),
    )


def count_logs():
    if _active_backend == "mongodb":
        return _mongo_db["logs"].count_documents({})
    row = execute("SELECT COUNT(*) AS count FROM logs", fetchone=True)
    return row["count"] if row else 0


def count_alerts():
    if _active_backend == "mongodb":
        return _mongo_db["alerts"].count_documents({})
    row = execute("SELECT COUNT(*) AS count FROM alerts", fetchone=True)
    return row["count"] if row else 0


def count_incidents():
    if _active_backend == "mongodb":
        return _mongo_db["incidents"].count_documents({})
    row = execute("SELECT COUNT(*) AS count FROM incidents", fetchone=True)
    return row["count"] if row else 0


def count_open_incidents():
    if _active_backend == "mongodb":
        return _mongo_db["incidents"].count_documents({"status": {"$ne": "CLOSED"}})
    row = execute("SELECT COUNT(*) AS count FROM incidents WHERE status != 'CLOSED'", fetchone=True)
    return row["count"] if row else 0


def _enrich_logs_mongo(docs):
    assets_map = {a["id"]: a["name"] for a in get_assets()}
    results = []
    for d in docs:
        item = _clean_doc(d)
        item["asset_name"] = assets_map.get(item.get("asset_id"))
        results.append(item)
    return results


def get_logs(limit=200, event_type=None, source_ip=None, search=None):
    try:
        limit = max(1, min(int(limit), 5000))
    except (TypeError, ValueError):
        limit = 200
    if _active_backend == "mongodb":
        flt = {}
        if event_type:
            flt["event_type"] = event_type.strip()
        if source_ip:
            flt["source_ip"] = source_ip.strip()
        if search:
            regex = re.compile(re.escape(search.strip()), re.I)
            flt["$or"] = [
                {"username": regex},
                {"source_ip": regex},
                {"endpoint": regex},
                {"event_type": regex},
                {"message": regex},
                {"request_data": regex},
            ]
        docs = _mongo_db["logs"].find(flt).sort("id", DESCENDING).limit(limit)
        return _enrich_logs_mongo(docs)

    query = """SELECT logs.*, assets.name AS asset_name
               FROM logs LEFT JOIN assets ON logs.asset_id=assets.id
               WHERE 1=1"""
    params = []
    if event_type:
        query += " AND logs.event_type = ?"
        params.append(event_type.strip())
    if source_ip:
        query += " AND logs.source_ip = ?"
        params.append(source_ip.strip())
    if search:
        like_val = f"%{search.strip()}%"
        query += """ AND (
            COALESCE(logs.username, '') LIKE ?
            OR COALESCE(logs.source_ip, '') LIKE ?
            OR COALESCE(logs.endpoint, '') LIKE ?
            OR COALESCE(logs.event_type, '') LIKE ?
            OR COALESCE(logs.message, '') LIKE ?
            OR COALESCE(logs.request_data, '') LIKE ?
        )"""
        params.extend([like_val] * 6)
    query += " ORDER BY logs.id DESC LIMIT ?"
    params.append(limit)
    return execute(query, tuple(params), fetchall=True)


def get_recent_login_failures(window_seconds):
    if _active_backend == "mongodb":
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=int(window_seconds))).strftime("%Y-%m-%d %H:%M:%S")
        docs = _mongo_db["logs"].find({
            "event_type": "LOGIN_FAILURE",
            "source_ip": {"$ne": None},
            "username": {"$ne": None},
            "timestamp": {"$gte": cutoff},
        }).sort([("timestamp", ASCENDING), ("id", ASCENDING)])
        return [_clean_doc(d) for d in docs]
    return execute(
        """SELECT * FROM logs
           WHERE event_type='LOGIN_FAILURE'
             AND source_ip IS NOT NULL
             AND username IS NOT NULL
             AND timestamp >= datetime('now', ?)
           ORDER BY timestamp ASC, id ASC""",
        (f"-{int(window_seconds)} seconds",), fetchall=True,
    )


def get_logs_for_alert(source_ip, username=None, endpoint=None):
    if _active_backend == "mongodb":
        flt = {"source_ip": source_ip}
        if username and endpoint:
            flt["$or"] = [
                {"username": username},
                {"endpoint": endpoint},
                {"event_type": {"$in": ["IP_BLOCKED", "ACCOUNT_LOCKED"]}},
            ]
        elif username:
            flt["$or"] = [
                {"username": username},
                {"event_type": {"$in": ["IP_BLOCKED", "ACCOUNT_LOCKED"]}},
            ]
        elif endpoint:
            flt["$or"] = [
                {"endpoint": endpoint},
                {"event_type": "IP_BLOCKED"},
            ]
        docs = _mongo_db["logs"].find(flt).sort("id", ASCENDING)
        return _enrich_logs_mongo(docs)

    query = """SELECT logs.*, assets.name AS asset_name FROM logs
               LEFT JOIN assets ON logs.asset_id=assets.id
               WHERE logs.source_ip = ?"""
    params = [source_ip]
    if username and endpoint:
        query += " AND (logs.username = ? OR logs.endpoint = ? OR logs.event_type IN ('IP_BLOCKED', 'ACCOUNT_LOCKED'))"
        params.extend([username, endpoint])
    elif username:
        query += " AND (logs.username = ? OR logs.event_type IN ('IP_BLOCKED', 'ACCOUNT_LOCKED'))"
        params.append(username)
    elif endpoint:
        query += " AND (logs.endpoint = ? OR logs.event_type = 'IP_BLOCKED')"
        params.append(endpoint)
    query += " ORDER BY logs.id ASC"
    return execute(query, tuple(params), fetchall=True)


def create_alert(alert_type, severity, source_ip, target, asset_id, rule, description):
    if severity not in SEVERITIES:
        raise ValueError("Invalid alert severity.")
    if _active_backend == "mongodb":
        aid = _next_seq("alerts")
        _mongo_db["alerts"].insert_one({
            "id": aid,
            "timestamp": _utc_timestamp(),
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "target": target,
            "asset_id": asset_id,
            "rule": rule,
            "description": description,
            "status": "NEW",
        })
        return aid
    return execute(
        """INSERT INTO alerts(alert_type,severity,source_ip,target,asset_id,rule,description)
           VALUES(?,?,?,?,?,?,?)""",
        (alert_type, severity, source_ip, target, asset_id, rule, description),
    )


def _enrich_alert_mongo(doc):
    if not doc:
        return None
    item = _clean_doc(doc)
    asset = get_asset(item.get("asset_id"))
    inc = _mongo_db["incidents"].find_one({"alert_id": item["id"]})
    item["asset_name"] = asset["name"] if asset else None
    item["incident_id"] = inc["id"] if inc else None
    return item


def get_alert(alert_id):
    if _active_backend == "mongodb":
        return _enrich_alert_mongo(_mongo_db["alerts"].find_one({"id": int(alert_id)}))
    return execute(
        """SELECT alerts.*, assets.name AS asset_name,
                  incidents.id AS incident_id
           FROM alerts LEFT JOIN assets ON alerts.asset_id=assets.id
           LEFT JOIN incidents ON incidents.alert_id=alerts.id
           WHERE alerts.id=?""",
        (alert_id,), fetchone=True,
    )


def get_alerts():
    if _active_backend == "mongodb":
        return [_enrich_alert_mongo(d) for d in _mongo_db["alerts"].find().sort("id", DESCENDING)]
    return execute(
        """SELECT alerts.*, assets.name AS asset_name,
                  incidents.id AS incident_id
           FROM alerts LEFT JOIN assets ON alerts.asset_id=assets.id
           LEFT JOIN incidents ON incidents.alert_id=alerts.id
           ORDER BY alerts.id DESC""",
        fetchall=True,
    )


def update_alert_status(alert_id, status):
    if status not in ALERT_STATUSES:
        raise ValueError("Invalid alert status.")
    if _active_backend == "mongodb":
        _mongo_db["alerts"].update_one({"id": int(alert_id)}, {"$set": {"status": status}})
        return
    execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))


def create_incident(alert_id, title, severity, assigned_to=None):
    if severity not in SEVERITIES:
        raise ValueError("Invalid incident severity.")
    if _active_backend == "mongodb":
        iid = _next_seq("incidents")
        _mongo_db["incidents"].insert_one({
            "id": iid,
            "alert_id": int(alert_id),
            "title": title.strip(),
            "severity": severity,
            "assigned_to": assigned_to,
            "status": "NEW",
            "findings": None,
            "root_cause": None,
            "response_action": None,
            "remediation": None,
            "verification": None,
            "created_at": _utc_timestamp(),
            "closed_at": None,
        })
        return iid
    return execute(
        """INSERT INTO incidents(alert_id,title,severity,assigned_to) VALUES(?,?,?,?)""",
        (alert_id, title.strip(), severity, assigned_to),
    )


def _enrich_incident_mongo(doc):
    if not doc:
        return None
    item = _clean_doc(doc)
    alert = _mongo_db["alerts"].find_one({"id": item.get("alert_id")}) or {}
    asset = get_asset(alert.get("asset_id"))
    user = get_user_by_id(item.get("assigned_to")) if item.get("assigned_to") else None
    item["alert_type"] = alert.get("alert_type")
    item["source_ip"] = alert.get("source_ip")
    item["target"] = alert.get("target")
    item["asset_id"] = alert.get("asset_id")
    item["rule"] = alert.get("rule")
    item["description"] = alert.get("description")
    item["asset_name"] = asset["name"] if asset else None
    item["assigned_username"] = user["username"] if user else None
    return item


def get_incident(incident_id):
    if _active_backend == "mongodb":
        return _enrich_incident_mongo(_mongo_db["incidents"].find_one({"id": int(incident_id)}))
    return execute(
        """SELECT incidents.*, alerts.alert_type, alerts.source_ip, alerts.target, alerts.asset_id,
                  alerts.rule, alerts.description, assets.name AS asset_name,
                  users.username AS assigned_username
           FROM incidents JOIN alerts ON incidents.alert_id=alerts.id
           LEFT JOIN assets ON alerts.asset_id=assets.id
           LEFT JOIN users ON incidents.assigned_to=users.id
           WHERE incidents.id=?""",
        (incident_id,), fetchone=True,
    )


def get_incidents():
    if _active_backend == "mongodb":
        return [_enrich_incident_mongo(d) for d in _mongo_db["incidents"].find().sort("id", DESCENDING)]
    return execute(
        """SELECT incidents.*, alerts.alert_type, alerts.source_ip, alerts.target,
                  alerts.asset_id, alerts.rule, alerts.description,
                  assets.name AS asset_name, users.username AS assigned_username
           FROM incidents JOIN alerts ON incidents.alert_id=alerts.id
           LEFT JOIN assets ON alerts.asset_id=assets.id
           LEFT JOIN users ON incidents.assigned_to=users.id
           ORDER BY incidents.id DESC""",
        fetchall=True,
    )


def update_incident(incident_id, status=None, findings=None, root_cause=None, response_action=None, remediation=None, verification=None, closed_at=None):
    if status is not None and status not in INCIDENT_STATUSES:
        raise ValueError("Invalid incident status.")
    updates = {
        "status": status,
        "findings": findings,
        "root_cause": root_cause,
        "response_action": response_action,
        "remediation": remediation,
        "verification": verification,
        "closed_at": closed_at,
    }
    non_null = {k: v for k, v in updates.items() if v is not None}
    if not non_null:
        return False
    if _active_backend == "mongodb":
        _mongo_db["incidents"].update_one({"id": int(incident_id)}, {"$set": non_null})
        return True
    fields = [f"{k}=?" for k in non_null]
    values = list(non_null.values()) + [incident_id]
    execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id=?", tuple(values))
    return True


def create_incident_action(incident_id, actor_user_id, action_type, description):
    if _active_backend == "mongodb":
        aid = _next_seq("incident_actions")
        _mongo_db["incident_actions"].insert_one({
            "id": aid,
            "incident_id": int(incident_id),
            "actor_user_id": actor_user_id,
            "action_type": action_type,
            "description": description,
            "created_at": _utc_timestamp(),
        })
        return aid
    return execute(
        """INSERT INTO incident_actions(incident_id,actor_user_id,action_type,description) VALUES(?,?,?,?)""",
        (incident_id, actor_user_id, action_type, description),
    )


def get_incident_actions(incident_id):
    if _active_backend == "mongodb":
        docs = _mongo_db["incident_actions"].find({"incident_id": int(incident_id)}).sort("id", ASCENDING)
        results = []
        for d in docs:
            item = _clean_doc(d)
            user = get_user_by_id(item.get("actor_user_id")) if item.get("actor_user_id") else None
            item["actor_username"] = user["username"] if user else None
            results.append(item)
        return results
    return execute(
        """SELECT incident_actions.*, users.username AS actor_username
           FROM incident_actions LEFT JOIN users ON incident_actions.actor_user_id=users.id
           WHERE incident_actions.incident_id=? ORDER BY incident_actions.id ASC""",
        (incident_id,), fetchall=True,
    )


def block_ip(ip_address, incident_id, blocked_by, reason):
    if _active_backend == "mongodb":
        existing = _mongo_db["blocked_ips"].find_one({"ip_address": ip_address})
        if existing:
            return existing["id"]
        bid = _next_seq("blocked_ips")
        _mongo_db["blocked_ips"].insert_one({
            "id": bid,
            "ip_address": ip_address,
            "incident_id": incident_id,
            "blocked_by": blocked_by,
            "reason": reason,
            "created_at": _utc_timestamp(),
        })
        return bid
    return execute(
        """INSERT OR IGNORE INTO blocked_ips(ip_address,incident_id,blocked_by,reason) VALUES(?,?,?,?)""",
        (ip_address, incident_id, blocked_by, reason),
    )


def unblock_ip(ip_address):
    ip_address = (ip_address or "").strip()
    if _active_backend == "mongodb":
        _mongo_db["blocked_ips"].delete_many({"ip_address": ip_address})
        return
    execute("DELETE FROM blocked_ips WHERE ip_address=?", (ip_address,))


def is_ip_blocked(ip_address):
    if _active_backend == "mongodb":
        return _clean_doc(_mongo_db["blocked_ips"].find_one({"ip_address": ip_address}))
    return execute("SELECT * FROM blocked_ips WHERE ip_address=?", (ip_address,), fetchone=True)


def get_blocked_ips():
    if _active_backend == "mongodb":
        docs = _mongo_db["blocked_ips"].find().sort("id", DESCENDING)
        results = []
        for d in docs:
            item = _clean_doc(d)
            user = get_user_by_id(item.get("blocked_by")) if item.get("blocked_by") else None
            item["blocked_by_username"] = user["username"] if user else None
            results.append(item)
        return results
    return execute(
        """SELECT blocked_ips.*, users.username AS blocked_by_username
           FROM blocked_ips LEFT JOIN users ON blocked_ips.blocked_by=users.id
           ORDER BY blocked_ips.id DESC""",
        fetchall=True,
    )


def create_ioc(ioc_type, value, reputation, confidence, description, source):
    ioc_type = (ioc_type or "IP").strip().upper()
    value = (value or "").strip()
    reputation = (reputation or "SUSPICIOUS").strip().upper()
    description = (description or "").strip()
    source = (source or "CyberShield Analyst").strip()
    if not value or not description:
        raise ValueError("Indicator value and description are required.")
    confidence = max(0, min(int(confidence), 100))
    if _active_backend == "mongodb":
        existing = _mongo_db["iocs"].find_one({"value": value})
        if existing:
            _mongo_db["iocs"].update_one(
                {"value": value},
                {"$set": {
                    "type": ioc_type,
                    "reputation": reputation,
                    "confidence": confidence,
                    "description": description,
                    "source": source,
                }},
            )
            return existing["id"]
        iid = _next_seq("iocs")
        _mongo_db["iocs"].insert_one({
            "id": iid,
            "type": ioc_type,
            "value": value,
            "reputation": reputation,
            "confidence": confidence,
            "description": description,
            "source": source,
            "created_at": _utc_timestamp(),
        })
        return iid
    return execute(
        """INSERT OR REPLACE INTO iocs(type,value,reputation,confidence,description,source) VALUES(?,?,?,?,?,?)""",
        (ioc_type, value, reputation, confidence, description, source),
    )


def lookup_ioc(value):
    value = (value or "").strip()
    if _active_backend == "mongodb":
        return _clean_doc(_mongo_db["iocs"].find_one({"value": value}))
    return execute("SELECT * FROM iocs WHERE value=?", (value,), fetchone=True)


def get_iocs():
    if _active_backend == "mongodb":
        return [_clean_doc(d) for d in _mongo_db["iocs"].find().sort("id", ASCENDING)]
    return execute("SELECT * FROM iocs ORDER BY id", fetchall=True)
