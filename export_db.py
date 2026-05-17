"""
export_db.py - Export VPN database to JSON for the viewer
Run from your project root: python export_db.py
Creates: vpn_data_export.json
"""
import sqlite3, json, os, glob
from datetime import datetime

DB_PATH          = "database/users.db"
LOGS_PATH        = "logs/vpn_logs.txt"
FILES_PATH       = "received_files"
OUTPUT_PATH      = "vpn_data_export.json"

def get_db():
    if not os.path.exists(DB_PATH):
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Make sure you run this from D:\\VPN PROJECT SE\\")
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def export_users(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, role, created_at, last_login, is_active
        FROM users ORDER BY id
    """)
    return [dict(r) for r in cur.fetchall()]

def export_sessions(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, ip_address, created_at, expires_at, is_active
        FROM sessions ORDER BY id DESC LIMIT 100
    """)
    return [dict(r) for r in cur.fetchall()]

def export_connection_history(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, ip_address, connected_at, disconnected_at,
               bytes_sent, bytes_recv
        FROM connection_history ORDER BY id DESC LIMIT 200
    """)
    return [dict(r) for r in cur.fetchall()]

def export_login_attempts(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, ip_address, attempted_at, success
        FROM login_attempts ORDER BY id DESC LIMIT 200
    """)
    return [dict(r) for r in cur.fetchall()]

def export_logs():
    if not os.path.exists(LOGS_PATH):
        return []
    lines = []
    with open(LOGS_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f.readlines()[-500:]:
            line = line.strip()
            if not line:
                continue
            level = "INFO"
            if "[WARNING" in line:   level = "WARNING"
            elif "[ERROR"   in line: level = "ERROR"
            elif "[DEBUG"   in line: level = "DEBUG"
            lines.append({"raw": line, "level": level})
    return lines

def export_files():
    if not os.path.exists(FILES_PATH):
        return []
    result = []
    for path in glob.glob(os.path.join(FILES_PATH, "*")):
        name = os.path.basename(path)
        size = os.path.getsize(path)
        mtime = datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        parts = name.split("_", 1)
        sender = parts[0] if len(parts) > 1 else "unknown"
        filename = parts[1] if len(parts) > 1 else name
        ext = os.path.splitext(filename)[1].lower()
        result.append({
            "name": name,
            "filename": filename,
            "sender": sender,
            "size": size,
            "modified": mtime,
            "ext": ext,
            "path": os.path.abspath(path)
        })
    return sorted(result, key=lambda x: x["modified"], reverse=True)

def main():
    print("VPN Database Exporter")
    print("=" * 40)

    conn = get_db()
    if not conn:
        return

    data = {
        "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "users":              export_users(conn),
        "sessions":           export_sessions(conn),
        "connection_history": export_connection_history(conn),
        "login_attempts":     export_login_attempts(conn),
        "received_files":     export_files(),
        "logs":               export_logs(),
    }
    conn.close()

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Users:              {len(data['users'])}")
    print(f"Sessions:           {len(data['sessions'])}")
    print(f"Connection history: {len(data['connection_history'])}")
    print(f"Login attempts:     {len(data['login_attempts'])}")
    print(f"Received files:     {len(data['received_files'])}")
    print(f"Log lines:          {len(data['logs'])}")
    print(f"\nExported to: {os.path.abspath(OUTPUT_PATH)}")
    print("Now open vpn_database_viewer.html in your browser!")

if __name__ == "__main__":
    main()