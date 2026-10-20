import os
import tempfile
import unittest
from datetime import timedelta

_database_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_database_file.close()
os.environ["ATTENDANCE_DATABASE"] = _database_file.name
os.environ["FLASK_SECRET_KEY"] = "test-secret"

from werkzeug.security import generate_password_hash

from app import app, now_pk, today_pk
from database import get_connection


class AttendanceAppTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        os.unlink(_database_file.name)

    def setUp(self):
        self.client = app.test_client()
        connection = get_connection()
        for table in ("attendance_audit", "attendance", "holidays", "work_schedules", "employees"):
            connection.execute(f"DELETE FROM {table}")
        connection.execute("""
            INSERT INTO employees(id, employee_code, full_name, password_hash, role)
            VALUES (1, 'ADMIN', 'Main Admin', ?, 'admin')
        """, (generate_password_hash("Admin123"),))
        connection.execute("""
            INSERT INTO employees(id, employee_code, full_name, department, password_hash)
            VALUES (2, 'EMP001', 'Test Employee', 'QA', ?)
        """, (generate_password_hash("Employee123"),))
        connection.execute("""
            INSERT INTO work_schedules(effective_from, start_time, end_time, grace_minutes, created_by)
            VALUES (?, '00:00', '23:59', 0, 1)
        """, ((today_pk() - timedelta(days=30)).isoformat(),))
        connection.commit()
        connection.close()

    def csrf(self):
        with self.client.session_transaction() as active_session:
            active_session["csrf_token"] = "test-csrf"
        return "test-csrf"

    def login(self, admin=False):
        return self.client.post(
            "/admin/login" if admin else "/login",
            data={"csrf_token": self.csrf(), "employee_code": "ADMIN" if admin else "EMP001", "password": "Admin123" if admin else "Employee123"},
            follow_redirects=True,
        )

    def test_pages_render_and_roles_are_separate(self):
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(self.login(admin=True).status_code, 200)
        for path in ("/admin", "/admin/employees", "/admin/settings", "/admin/reports", "/attendance"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_csrf_is_required(self):
        self.assertEqual(self.client.post("/login", data={}).status_code, 400)

    def test_check_in_is_unique_and_check_out_works(self):
        self.login()
        token = self.csrf()
        first = self.client.post("/attendance/check-in", data={"csrf_token": token}, follow_redirects=True)
        self.assertIn(b"Check-in recorded", first.data)
        second = self.client.post("/attendance/check-in", data={"csrf_token": token}, follow_redirects=True)
        self.assertIn(b"already have a check-in", second.data)
        checkout = self.client.post("/attendance/check-out", data={"csrf_token": token}, follow_redirects=True)
        self.assertIn(b"Check-out recorded", checkout.data)

    def test_excel_export(self):
        self.login(admin=True)
        response = self.client.get(f"/admin/reports/export?start={today_pk().isoformat()}&end={today_pk().isoformat()}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data[:2], b"PK")


if __name__ == "__main__":
    unittest.main()
