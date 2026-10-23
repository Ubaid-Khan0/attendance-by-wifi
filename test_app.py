import io
import os
import shutil
import tempfile
import unittest
from datetime import timedelta

_database_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_database_file.close()
_upload_folder = tempfile.mkdtemp()
os.environ["ATTENDANCE_DATABASE"] = _database_file.name
os.environ["LEAVE_UPLOAD_FOLDER"] = _upload_folder
os.environ["FLASK_SECRET_KEY"] = "test-secret"
os.environ["TRUSTED_IP_HEADER"] = "X-Real-IP"

from werkzeug.security import generate_password_hash

from app import app, now_pk, today_pk
from database import get_connection


class AttendanceAppTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        os.unlink(_database_file.name)
        shutil.rmtree(_upload_folder)

    def setUp(self):
        self.client = app.test_client()
        connection = get_connection()
        for table in ("attendance_audit", "leave_requests", "attendance", "holidays", "work_schedules", "employees"):
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
            INSERT INTO employees(id, employee_code, full_name, department, password_hash, role)
            VALUES (3, 'HR001', 'HR User', 'Human Resources', ?, 'hr')
        """, (generate_password_hash("Human123"),))
        connection.execute("""
            INSERT INTO work_schedules(effective_from, start_time, end_time, grace_minutes, created_by)
            VALUES (?, '00:00', '23:59', 0, 1)
        """, ((today_pk() - timedelta(days=30)).isoformat(),))
        connection.execute("UPDATE settings SET value='127.0.0.0/8,::1/128' WHERE key='allowed_networks'")
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

    def login_hr(self):
        return self.client.post(
            "/login",
            data={"csrf_token": self.csrf(), "employee_code": "HR001", "password": "Human123"},
            follow_redirects=True,
        )

    def test_pages_render_and_roles_are_separate(self):
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(self.login(admin=True).status_code, 200)
        for path in ("/admin", "/admin/settings", "/admin/reports", "/attendance"):
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.assertEqual(self.client.get("/hr/employees").status_code, 403)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(self.login_hr().status_code, 200)
        self.assertEqual(self.client.get("/hr").status_code, 200)
        self.assertEqual(self.client.get("/hr/employees").status_code, 200)
        self.assertEqual(self.client.get("/admin").status_code, 403)

    def test_admin_and_hr_dashboards_show_in_office_count(self):
        connection = get_connection()
        connection.execute(
            "INSERT INTO attendance(employee_id, check_in, attendance_date) VALUES(?, ?, ?)",
            (2, f"{today_pk().isoformat()} 09:00:00", today_pk().isoformat()),
        )
        connection.commit()
        connection.close()

        admin_response = self.login(admin=True)
        self.assertIn(b"In Office", admin_response.data)
        self.assertIn(b">1</h2>", admin_response.data)
        self.client.post("/logout", data={"csrf_token": self.csrf()})

        hr_response = self.login_hr()
        self.assertIn(b"HR Dashboard", hr_response.data)
        self.assertIn(b"In Office", hr_response.data)
        self.assertIn(b">1</h2>", hr_response.data)

    def test_csrf_is_required(self):
        self.assertEqual(self.client.post("/login", data={}).status_code, 400)

    def test_check_in_is_unique_and_check_out_works(self):
        self.login()
        token = self.csrf()
        first = self.client.post("/attendance/check-in", data={"csrf_token": token, "late_reason": "Heavy traffic congestion"}, headers={"X-Real-IP": "127.0.0.1"}, follow_redirects=True)
        self.assertIn(b"Check-in recorded", first.data)
        second = self.client.post("/attendance/check-in", data={"csrf_token": token}, headers={"X-Real-IP": "127.0.0.1"}, follow_redirects=True)
        self.assertIn(b"already have a check-in", second.data)
        checkout = self.client.post("/attendance/check-out", data={"csrf_token": token}, follow_redirects=True)
        self.assertIn(b"Check-out recorded", checkout.data)

    def test_deployed_check_in_uses_forwarded_public_ip(self):
        connection = get_connection()
        connection.execute("UPDATE settings SET value='198.51.100.10/32' WHERE key='allowed_networks'")
        connection.commit()
        connection.close()

        self.login()
        token = self.csrf()
        rejected = self.client.post(
            "/attendance/check-in",
            data={"csrf_token": token, "late_reason": "Heavy traffic congestion"},
            headers={"X-Real-IP": "203.0.113.20"},
            follow_redirects=True,
        )
        self.assertIn(b"only available on the configured office Wi-Fi", rejected.data)

        accepted = self.client.post(
            "/attendance/check-in",
            data={"csrf_token": token, "late_reason": "Heavy traffic congestion"},
            headers={"X-Real-IP": "198.51.100.10"},
            follow_redirects=True,
        )
        self.assertIn(b"Check-in recorded", accepted.data)

    def test_late_check_in_requires_reason_and_accepts_picture(self):
        self.login()
        token = self.csrf()
        missing_reason = self.client.post(
            "/attendance/check-in",
            data={"csrf_token": token},
            headers={"X-Real-IP": "127.0.0.1"},
            follow_redirects=True,
        )
        self.assertIn(b"reason for your late check-in", missing_reason.data)

        response = self.client.post(
            "/attendance/check-in",
            data={
                "csrf_token": token,
                "late_reason": "Public transport delay",
                "late_picture": (io.BytesIO(b"\x89PNG\r\n\x1a\nproof"), "proof.png"),
            },
            headers={"X-Real-IP": "127.0.0.1"},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertIn(b"Check-in recorded", response.data)
        connection = get_connection()
        record = connection.execute("SELECT late_reason, late_picture_name FROM attendance WHERE employee_id=2").fetchone()
        connection.close()
        self.assertEqual(record["late_reason"], "Public transport delay")
        self.assertTrue(record["late_picture_name"].endswith(".png"))

    def test_excel_export(self):
        self.login(admin=True)
        response = self.client.get(f"/admin/reports/export?start={today_pk().isoformat()}&end={today_pk().isoformat()}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data[:2], b"PK")

    def test_employee_requests_leave_and_admin_approves_it(self):
        self.login()
        start = (today_pk() + timedelta(days=1)).isoformat()
        response = self.client.post("/leave", data={
            "csrf_token": self.csrf(), "leave_type": "Annual",
            "start_date": start, "end_date": start, "reason": "Religious or family event",
        }, follow_redirects=True)
        self.assertIn(b"Leave request submitted", response.data)

        connection = get_connection()
        leave_id = connection.execute("SELECT id FROM leave_requests WHERE employee_id=2").fetchone()[0]
        connection.close()

        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login(admin=True)
        response = self.client.post(f"/admin/leaves/{leave_id}/review", data={
            "csrf_token": self.csrf(), "action": "approved", "reviewer_note": "Approved",
        }, follow_redirects=True)
        self.assertIn(b"Leave request approved", response.data)

        connection = get_connection()
        status = connection.execute("SELECT status FROM leave_requests WHERE id=?", (leave_id,)).fetchone()[0]
        connection.close()
        self.assertEqual(status, "approved")

    def test_sick_and_emergency_leave_require_picture(self):
        self.login()
        start = (today_pk() + timedelta(days=2)).isoformat()
        response = self.client.post("/leave", data={
            "csrf_token": self.csrf(), "leave_type": "Sick",
            "start_date": start, "end_date": start, "reason": "Other", "reason_other": "Medical rest",
        }, follow_redirects=True)
        self.assertIn(b"require a JPG, PNG, or WebP image", response.data)

        response = self.client.post("/leave", data={
            "csrf_token": self.csrf(), "leave_type": "Emergency",
            "start_date": start, "end_date": start, "reason": "Family emergency",
            "evidence": (io.BytesIO(b"\x89PNG\r\n\x1a\n" + b"test-image"), "evidence.png"),
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Leave request submitted", response.data)

        connection = get_connection()
        item = connection.execute("SELECT id, attachment_name FROM leave_requests WHERE leave_type='Emergency'").fetchone()
        connection.close()
        self.assertTrue(item["attachment_name"].endswith(".png"))
        evidence_response = self.client.get(f"/leave/{item['id']}/evidence")
        self.assertEqual(evidence_response.status_code, 200)
        evidence_response.close()

    def test_hr_assigns_role_and_edits_employee_without_changing_id(self):
        self.login_hr()
        response = self.client.post("/hr/employees/add", data={
            "csrf_token": self.csrf(), "employee_code": "MGR001",
            "full_name": "Team Manager", "department": "Operations",
            "role": "manager", "password": "Manager123",
        }, follow_redirects=True)
        self.assertIn(b"Employee added", response.data)

        connection = get_connection()
        manager = connection.execute("SELECT id, employee_code, role FROM employees WHERE employee_code='MGR001'").fetchone()
        connection.close()
        self.assertEqual(manager["role"], "manager")

        response = self.client.post(f"/hr/employees/{manager['id']}/edit", data={
            "csrf_token": self.csrf(), "employee_code": "CHANGED",
            "full_name": "Updated Manager", "department": "Sales",
            "role": "employee", "is_active": "on",
        }, follow_redirects=True)
        self.assertIn(b"Employee details updated", response.data)
        connection = get_connection()
        updated = connection.execute("SELECT employee_code, full_name, department, role FROM employees WHERE id=?", (manager["id"],)).fetchone()
        connection.close()
        self.assertEqual(updated["employee_code"], "MGR001")
        self.assertEqual((updated["full_name"], updated["department"], updated["role"]), ("Updated Manager", "Sales", "employee"))

    def test_hr_can_assign_intern_role(self):
        self.login_hr()
        response = self.client.post("/hr/employees/add", data={
            "csrf_token": self.csrf(), "employee_code": "INT001",
            "full_name": "Test Intern", "department": "Technology",
            "role": "intern", "password": "Intern123",
        }, follow_redirects=True)
        self.assertIn(b"Employee added", response.data)
        connection = get_connection()
        role = connection.execute("SELECT role FROM employees WHERE employee_code='INT001'").fetchone()[0]
        connection.close()
        self.assertEqual(role, "intern")

    def test_admin_can_create_first_hr_only(self):
        connection = get_connection()
        connection.execute("UPDATE employees SET role='employee' WHERE id=3")
        connection.commit()
        connection.close()

        self.login(admin=True)
        self.assertEqual(self.client.get("/hr/employees").status_code, 200)
        response = self.client.post("/hr/employees/add", data={
            "csrf_token": self.csrf(), "employee_code": "HR002",
            "full_name": "First HR", "department": "Human Resources",
            "role": "employee", "password": "Welcome123",
        }, follow_redirects=True)
        self.assertIn(b"Employee added", response.data)

        connection = get_connection()
        role = connection.execute("SELECT role FROM employees WHERE employee_code='HR002'").fetchone()[0]
        connection.close()
        self.assertEqual(role, "hr")
        self.assertEqual(self.client.get("/hr/employees").status_code, 403)


if __name__ == "__main__":
    unittest.main()
