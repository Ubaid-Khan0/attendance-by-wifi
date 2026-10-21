
import os
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_NAME = os.environ.get("ATTENDANCE_DATABASE", str(BASE_DIR / "attendance.db"))


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _add_column(connection, table, definition):
    name = definition.split()[0]
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def create_tables():
    connection = get_connection()
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_code TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                department TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        for definition in (
            "password_hash TEXT", "role TEXT NOT NULL DEFAULT 'employee'",
            "is_active INTEGER NOT NULL DEFAULT 1",
            "must_change_password INTEGER NOT NULL DEFAULT 0",
            "failed_login_attempts INTEGER NOT NULL DEFAULT 0", "locked_until TEXT",
            "deactivated_at TEXT",
        ):
            _add_column(connection, "employees", definition)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                check_in TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                check_out TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id)
            )
        """)
        for definition in (
            "attendance_date TEXT", "schedule_id INTEGER",
            "is_valid INTEGER NOT NULL DEFAULT 1",
        ):
            _add_column(connection, "attendance", definition)
        connection.execute("UPDATE attendance SET attendance_date = DATE(check_in) WHERE attendance_date IS NULL")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_attendance_employee_date ON attendance(employee_id, attendance_date)")

        connection.execute("""
            CREATE TABLE IF NOT EXISTS work_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                effective_from TEXT UNIQUE NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                grace_minutes INTEGER NOT NULL DEFAULT 0,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES employees(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS holidays (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                holiday_date TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES employees(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_by INTEGER,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (updated_by) REFERENCES employees(id)
            )
        """)
        connection.execute("INSERT OR IGNORE INTO settings(key, value) VALUES ('allowed_networks', '127.0.0.0/8,::1/128')")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS attendance_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attendance_id INTEGER NOT NULL, admin_id INTEGER NOT NULL,
                action TEXT NOT NULL, reason TEXT NOT NULL,
                old_check_in TEXT, old_check_out TEXT, old_is_valid INTEGER,
                new_check_in TEXT, new_check_out TEXT, new_is_valid INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (attendance_id) REFERENCES attendance(id),
                FOREIGN KEY (admin_id) REFERENCES employees(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS leave_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                leave_type TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
                reviewer_note TEXT,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (employee_id) REFERENCES employees(id),
                FOREIGN KEY (reviewed_by) REFERENCES employees(id)
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_leave_employee_dates ON leave_requests(employee_id, start_date, end_date)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_leave_status ON leave_requests(status)")
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    create_tables()
    print(f"Database ready: {DATABASE_NAME}")
    print("Existing employee and attendance records preserved.")
