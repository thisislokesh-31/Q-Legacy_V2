import sqlite3

DATABASE_NAME = "qlegacy.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                asset_type TEXT DEFAULT 'unknown',
                algorithms TEXT DEFAULT '[]',
                risk_level TEXT DEFAULT 'UNKNOWN',
                recommendation TEXT DEFAULT '',
                confidence TEXT DEFAULT 'MEDIUM',
                priority TEXT DEFAULT 'MEDIUM',
                manual_review_required INTEGER DEFAULT 0,
                evidence TEXT DEFAULT '[]',
                details TEXT DEFAULT '{}',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Ensure older tables get missing columns if table already existed
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(assets)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "confidence" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN confidence TEXT DEFAULT 'MEDIUM'")
        if "priority" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN priority TEXT DEFAULT 'MEDIUM'")
        if "manual_review_required" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN manual_review_required INTEGER DEFAULT 0")
        if "evidence" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN evidence TEXT DEFAULT '[]'")
        if "details" not in columns:
            conn.execute("ALTER TABLE assets ADD COLUMN details TEXT DEFAULT '{}'")