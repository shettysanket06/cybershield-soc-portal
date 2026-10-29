import sys
from config import MONGODB_URI, MONGODB_DB_NAME
import database


def main():
    print("Connecting to the configured MongoDB instance (connection string hidden).")
    print(f"Target Database Name     : {MONGODB_DB_NAME}")
    try:
        from pymongo import MongoClient
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=4000, connectTimeoutMS=4000)
        client.admin.command("ping")
    except Exception as exc:
        print("\n[!] Could not connect to MongoDB.")
        print(f"    Reason: {exc}")
        print("\nHow to fix:")
        print("  1. If using Local MongoDB (Compass / Community Server), make sure the MongoDB server is running on 127.0.0.1:27017.")
        print("  2. If using MongoDB Atlas (Cloud), set MONGODB_URI locally in your .env file.")
        print("     Keep the connection string private; do not commit .env to source control.")
        print("  3. Note: While MongoDB is offline, CyberShield automatically falls back to SQLite (database.db) when CYBERSHIELD_DB_BACKEND=auto.")
        sys.exit(1)

    database.init_db()
    mdb = client[MONGODB_DB_NAME]
    print(f"\n[OK] Successfully initialized MongoDB database '{MONGODB_DB_NAME}'!")
    print("Created & seeded collections:")
    for coll in ("users", "assets", "iocs", "logs", "alerts", "incidents", "incident_actions", "blocked_ips"):
        print(f"  - {coll:18s}: {mdb[coll].count_documents({})} document(s)")


if __name__ == "__main__":
    main()
