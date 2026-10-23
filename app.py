import csv
import io
import ipaddress
import os
import secrets
import sqlite3
from datetime import date, datetime, time, timedelta
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

import click
from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from database import create_tables, get_connection

TZ = ZoneInfo("Asia/Karachi")
LEAVE_UPLOAD_FOLDER = Path(os.environ.get("LEAVE_UPLOAD_FOLDER", Path(__file__).resolve().parent / "leave_uploads"))
MAX_LEAVE_IMAGE_BYTES = 5 * 1024 * 1024
LEAVE_REASONS = (
    "Bereavement or funeral", "Hospital admission or medical emergency",
    "Illness or recovery", "Family emergency", "Personal appointment",
    "Religious or family event", "Travel disruption",
)
LATE_REASONS = (
    "Heavy traffic congestion", "Traffic challan or police stop",
    "Motorcycle or vehicle puncture", "Vehicle mechanical problem",
    "Public transport delay", "Medical emergency", "Family emergency",
    "Severe weather conditions",
)
app = Flask(__name__)
try:
    trusted_proxy_hops = int(os.environ.get("TRUSTED_PROXY_HOPS", "0"))
    if trusted_proxy_hops < 0:
        raise ValueError
except ValueError as error:
    raise RuntimeError("TRUSTED_PROXY_HOPS must be a non-negative integer.") from error

if trusted_proxy_hops:
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=trusted_proxy_hops,
        x_proto=trusted_proxy_hops,
    )

app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
    PERMANENT_SESSION_LIFETIME=timedelta(days=15),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
)
create_tables()


def now_pk():
    return datetime.now(TZ).replace(tzinfo=None)


def today_pk():
    return now_pk().date()


def valid_password(value):
    return len(value) >= 8 and any(c.isalpha() for c in value) and any(c.isdigit() for c in value)


def selected_reason(form, field, choices):
    choice = form.get(field, "").strip()
    if choice == "Other":
        return form.get(f"{field}_other", "").strip()
    return choice if choice in choices else ""


def leave_image_extension(upload):
    if not upload or not upload.filename:
        return None
    upload.stream.seek(0, 2)
    size = upload.stream.tell()
    upload.stream.seek(0)
    header = upload.stream.read(12)
    upload.stream.seek(0)
    if size <= 0 or size > MAX_LEAVE_IMAGE_BYTES:
        return None
    if header.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "webp"
    return None


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def security_checks():
    if request.method == "POST":
        expected = session.get("csrf_token")
        supplied = request.form.get("csrf_token")
        if not expected or not supplied or not secrets.compare_digest(supplied, expected):
            abort(400, "Invalid or missing security token.")
    allowed = {"logout", "change_password", "static"}
    if session.get("user_id") and session.get("must_change_password") and request.endpoint not in allowed:
        return redirect(url_for("change_password"))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "error")
            return redirect(url_for("employee_login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def hr_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "hr":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def employee_management_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") == "hr":
            return view(*args, **kwargs)
        if session.get("role") == "admin":
            connection = get_connection()
            try:
                hr_exists = connection.execute("SELECT 1 FROM employees WHERE role='hr' LIMIT 1").fetchone()
            finally:
                connection.close()
            if not hr_exists:
                return view(*args, **kwargs)
        abort(403)
    return wrapped


@app.context_processor
def employee_management_navigation():
    if session.get("role") != "admin":
        return {"needs_first_hr": False}
    connection = get_connection()
    try:
        needs_first_hr = connection.execute("SELECT 1 FROM employees WHERE role='hr' LIMIT 1").fetchone() is None
    finally:
        connection.close()
    return {"needs_first_hr": needs_first_hr}


def current_schedule(connection, day=None):
    day = day or today_pk().isoformat()
    return connection.execute("""
        SELECT * FROM work_schedules WHERE effective_from <= ?
        ORDER BY effective_from DESC LIMIT 1
    """, (day,)).fetchone()


def is_holiday(connection, day):
    return connection.execute("SELECT 1 FROM holidays WHERE holiday_date = ?", (day,)).fetchone() is not None


def labels_for(day, check_in, check_out, schedule, valid=True):
    if not valid:
        return ["Invalid"]
    target = date.fromisoformat(day)
    if target.weekday() >= 5 or not schedule:
        return ["Present"] if check_in else ["Not scheduled"]
    if not check_in:
        return ["Absent"] if now_pk() > datetime.combine(target, time.fromisoformat(schedule["end_time"])) else ["Not Yet Checked In"]
    start_limit = datetime.combine(target, time.fromisoformat(schedule["start_time"])) + timedelta(minutes=schedule["grace_minutes"])
    result = ["Late" if datetime.fromisoformat(check_in) > start_limit else "On Time"]
    if check_out and datetime.fromisoformat(check_out) < datetime.combine(target, time.fromisoformat(schedule["end_time"])):
        result.append("Left Early")
    return result


def client_on_allowed_network(connection):
    value = connection.execute("SELECT value FROM settings WHERE key='allowed_networks'").fetchone()["value"]
    try:
        header_name = os.environ.get("TRUSTED_IP_HEADER", "").strip()
        client_ip = request.headers.get(header_name, "") if header_name else request.remote_addr
        address = ipaddress.ip_address(client_ip)
        return any(address in ipaddress.ip_network(item.strip(), strict=False) for item in value.split(",") if item.strip())
    except (TypeError, ValueError):
        return False


def client_ip_address():
    header_name = os.environ.get("TRUSTED_IP_HEADER", "").strip()
    return request.headers.get(header_name, "Unknown") if header_name else request.remote_addr


def attempt_login(role):
    code = request.form.get("employee_code", "").strip()
    password = request.form.get("password", "")
    connection = get_connection()
    try:
        if role == "admin":
            user = connection.execute("SELECT * FROM employees WHERE employee_code=? AND role='admin'", (code,)).fetchone()
        else:
            user = connection.execute("SELECT * FROM employees WHERE employee_code=? AND role!='admin'", (code,)).fetchone()
        current = now_pk()
        if user and user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > current:
            flash("Account temporarily locked. Try again later.", "error")
            return None
        if user and user["is_active"] and user["password_hash"] and check_password_hash(user["password_hash"], password):
            connection.execute("UPDATE employees SET failed_login_attempts=0, locked_until=NULL WHERE id=?", (user["id"],))
            connection.commit()
            session.clear()
            session.permanent = True
            session.update(user_id=user["id"], employee_code=user["employee_code"], employee_name=user["full_name"], role=user["role"], must_change_password=bool(user["must_change_password"]))
            csrf_token()
            return user
        if user:
            failures = user["failed_login_attempts"] + 1
            locked = (current + timedelta(minutes=15)).isoformat(sep=" ", timespec="seconds") if failures >= 5 else None
            connection.execute("UPDATE employees SET failed_login_attempts=?, locked_until=? WHERE id=?", (failures, locked, user["id"]))
            connection.commit()
        flash("Invalid credentials or inactive account.", "error")
        return None
    finally:
        connection.close()


@app.route("/")
def home():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "hr":
        return redirect(url_for("hr_dashboard"))
    if session.get("user_id"):
        return redirect(url_for("my_attendance"))
    return redirect(url_for("employee_login"))


@app.route("/login", methods=["GET", "POST"])
def employee_login():
    if request.method == "POST":
        user = attempt_login("employee")
        if user:
            return redirect(url_for("hr_dashboard" if user["role"] == "hr" else "my_attendance"))
    return render_template("login.html", admin=False)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST" and attempt_login("admin"):
        return redirect(url_for("admin_dashboard"))
    return render_template("login.html", admin=True)


@app.post("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("employee_login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current, new, confirm = (request.form.get(k, "") for k in ("current_password", "new_password", "confirm_password"))
        connection = get_connection()
        try:
            user = connection.execute("SELECT password_hash FROM employees WHERE id=?", (session["user_id"],)).fetchone()
            if not check_password_hash(user["password_hash"], current):
                flash("Current password is incorrect.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            elif not valid_password(new):
                flash("Use at least 8 characters with a letter and a number.", "error")
            else:
                connection.execute("UPDATE employees SET password_hash=?, must_change_password=0 WHERE id=?", (generate_password_hash(new), session["user_id"]))
                connection.commit()
                session["must_change_password"] = False
                flash("Password changed.", "success")
                if session["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                if session["role"] == "hr":
                    return redirect(url_for("hr_dashboard"))
                return redirect(url_for("my_attendance"))
        finally:
            connection.close()
    return render_template("change_password.html")


@app.route("/attendance")
@login_required
def my_attendance():
    start = request.args.get("start", (today_pk() - timedelta(days=30)).isoformat())
    end = request.args.get("end", today_pk().isoformat())
    connection = get_connection()
    try:
        today_record = connection.execute("SELECT * FROM attendance WHERE employee_id=? AND attendance_date=? AND is_valid=1", (session["user_id"], today_pk().isoformat())).fetchone()
        schedule = current_schedule(connection)
        late_check_in = bool(schedule and now_pk() > datetime.combine(today_pk(), time.fromisoformat(schedule["start_time"])) + timedelta(minutes=schedule["grace_minutes"]))
        allowed = client_on_allowed_network(connection)
        rows = build_report(connection, start, end, str(session["user_id"]))
    finally:
        connection.close()
    return render_template("attendance.html", records=rows, today_record=today_record, schedule=schedule, late_check_in=late_check_in, late_reasons=LATE_REASONS, network_allowed=allowed, start=start, end=end)


@app.post("/attendance/check-in")
@login_required
def check_in():
    connection = get_connection()
    today = today_pk().isoformat()
    saved_picture = None
    try:
        connection.execute("BEGIN IMMEDIATE")
        schedule = current_schedule(connection, today)
        current_time = now_pk()
        is_late = bool(schedule and current_time > datetime.combine(today_pk(), time.fromisoformat(schedule["start_time"])) + timedelta(minutes=schedule["grace_minutes"]))
        late_reason = selected_reason(request.form, "late_reason", LATE_REASONS)
        picture = request.files.get("late_picture")
        picture_extension = leave_image_extension(picture)
        if not schedule:
            flash("The administrator must configure a work schedule first.", "error")
        elif is_holiday(connection, today) or today_pk().weekday() >= 5:
            flash("Today is not a scheduled working day.", "error")
        elif not client_on_allowed_network(connection):
            flash("Check-in is only available on the configured office Wi-Fi.", "error")
        elif connection.execute("SELECT 1 FROM attendance WHERE employee_id=? AND attendance_date=? AND is_valid=1", (session["user_id"], today)).fetchone():
            flash("You already have a check-in for today.", "error")
        elif is_late and not late_reason:
            flash("Please enter a reason for your late check-in.", "error")
        elif is_late and picture and picture.filename and not picture_extension:
            flash("Upload a JPG, PNG, or WEBP picture smaller than 5 MB.", "error")
        else:
            current = current_time.isoformat(sep=" ", timespec="seconds")
            cursor = connection.execute("INSERT INTO attendance(employee_id,check_in,attendance_date,schedule_id,late_reason) VALUES(?,?,?,?,?)", (session["user_id"], current, today, schedule["id"], late_reason if is_late else None))
            if is_late and picture_extension:
                LEAVE_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
                saved_picture = f"late-{cursor.lastrowid}-{secrets.token_hex(8)}.{picture_extension}"
                picture.save(LEAVE_UPLOAD_FOLDER / saved_picture)
                connection.execute("UPDATE attendance SET late_picture_name=? WHERE id=?", (saved_picture, cursor.lastrowid))
            connection.commit()
            flash("Check-in recorded.", "success")
    except (OSError, sqlite3.Error):
        connection.rollback(); app.logger.exception("Check-in failed"); flash("Could not record check-in.", "error")
        if saved_picture:
            (LEAVE_UPLOAD_FOLDER / saved_picture).unlink(missing_ok=True)
    finally:
        connection.close()
    return redirect(url_for("my_attendance"))


@app.post("/attendance/check-out")
@login_required
def check_out():
    connection = get_connection()
    try:
        record = connection.execute("SELECT id FROM attendance WHERE employee_id=? AND attendance_date=? AND is_valid=1 AND check_out IS NULL", (session["user_id"], today_pk().isoformat())).fetchone()
        if not record:
            flash("No open check-in was found for today.", "error")
        else:
            connection.execute("UPDATE attendance SET check_out=? WHERE id=?", (now_pk().isoformat(sep=" ", timespec="seconds"), record["id"]))
            connection.commit(); flash("Check-out recorded.", "success")
    finally:
        connection.close()
    return redirect(url_for("my_attendance"))


def build_report(connection, start, end, employee_id="", department="", label=""):
    employees = connection.execute("SELECT * FROM employees WHERE (?='' OR id=?) AND (?='' OR department=?) ORDER BY full_name", (employee_id, employee_id, department, department)).fetchall()
    records = connection.execute("SELECT * FROM attendance WHERE attendance_date BETWEEN ? AND ?", (start, end)).fetchall()
    by_key = {(r["employee_id"], r["attendance_date"]): r for r in records}
    holidays = {r[0] for r in connection.execute("SELECT holiday_date FROM holidays WHERE holiday_date BETWEEN ? AND ?", (start, end))}
    approved_leave = connection.execute("""
        SELECT employee_id, start_date, end_date FROM leave_requests
        WHERE status='approved' AND start_date <= ? AND end_date >= ?
    """, (end, start)).fetchall()
    rows, day = [], date.fromisoformat(start)
    while day <= date.fromisoformat(end):
        day_text = day.isoformat()
        if day.weekday() < 5 and day_text not in holidays:
            schedule = current_schedule(connection, day_text)
            for employee in employees:
                created = str(employee["created_at"])[:10]
                if day_text < created or (employee["deactivated_at"] and day_text > employee["deactivated_at"][:10]):
                    continue
                record = by_key.get((employee["id"], day_text))
                on_leave = any(item["employee_id"] == employee["id"] and item["start_date"] <= day_text <= item["end_date"] for item in approved_leave)
                labels = ["On Leave"] if on_leave and not record else labels_for(day_text, record["check_in"] if record else None, record["check_out"] if record else None, schedule, record["is_valid"] if record else True)
                row = {"record_id": record["id"] if record else None, "employee_code": employee["employee_code"], "full_name": employee["full_name"], "department": employee["department"] or "", "date": day_text, "check_in": record["check_in"] if record else None, "check_out": record["check_out"] if record else None, "late_reason": record["late_reason"] if record else None, "late_picture_name": record["late_picture_name"] if record else None, "labels": labels}
                if not label or label in labels:
                    rows.append(row)
        day += timedelta(days=1)
    return sorted(rows, key=lambda r: (r["date"], r["full_name"]), reverse=True)


@app.route("/admin")
@admin_required
def admin_dashboard():
    return attendance_dashboard("Admin")


@app.route("/hr")
@hr_required
def hr_dashboard():
    return attendance_dashboard("HR")


def attendance_dashboard(title):
    connection = get_connection()
    try:
        today = today_pk().isoformat()
        rows = build_report(connection, today, today)
        counts = {key: sum(key in r["labels"] for r in rows) for key in ("On Time", "Late", "Absent", "Not Yet Checked In", "Left Early", "On Leave")}
        in_office = connection.execute("""
            SELECT COUNT(DISTINCT a.employee_id)
            FROM attendance a
            JOIN employees e ON e.id = a.employee_id
            WHERE a.attendance_date=? AND a.is_valid=1
              AND a.check_in IS NOT NULL AND a.check_out IS NULL
              AND e.is_active=1
        """, (today,)).fetchone()[0]
        total = connection.execute("SELECT COUNT(*) FROM employees WHERE is_active=1").fetchone()[0]
        pending_leave = connection.execute("SELECT COUNT(*) FROM leave_requests WHERE status='pending'").fetchone()[0]
    finally:
        connection.close()
    return render_template("admin_dashboard.html", dashboard_title=title, rows=rows, counts=counts, in_office=in_office, total=total, pending_leave=pending_leave)


@app.route("/leave", methods=["GET", "POST"])
@login_required
def leave_requests():
    connection = get_connection()
    try:
        if request.method == "POST":
            leave_type = request.form.get("leave_type", "").strip()
            start_text = request.form.get("start_date", "").strip()
            end_text = request.form.get("end_date", "").strip()
            reason = selected_reason(request.form, "reason", LEAVE_REASONS)
            evidence = request.files.get("evidence")
            evidence_extension = leave_image_extension(evidence)
            try:
                start_date = date.fromisoformat(start_text)
                end_date = date.fromisoformat(end_text)
            except ValueError:
                start_date = end_date = None
            overlap = None
            if start_date and end_date:
                overlap = connection.execute("""
                    SELECT 1 FROM leave_requests
                    WHERE employee_id=? AND status IN ('pending', 'approved')
                      AND start_date <= ? AND end_date >= ?
                """, (session["user_id"], end_text, start_text)).fetchone()
            if leave_type not in {"Annual", "Sick", "Emergency", "Casual", "Unpaid"}:
                flash("Select a valid leave type.", "error")
            elif not start_date or not end_date or end_date < start_date:
                flash("Enter a valid leave date range.", "error")
            elif not reason:
                flash("Please provide a reason for your leave.", "error")
            elif leave_type in {"Sick", "Emergency"} and not evidence_extension:
                flash("Sick and emergency leave require a JPG, PNG, or WebP image up to 5 MB.", "error")
            elif evidence and evidence.filename and not evidence_extension:
                flash("Upload a valid JPG, PNG, or WebP image up to 5 MB.", "error")
            elif overlap:
                flash("You already have a pending or approved request for these dates.", "error")
            else:
                cursor = connection.execute("""
                    INSERT INTO leave_requests(employee_id, leave_type, start_date, end_date, reason)
                    VALUES (?, ?, ?, ?, ?)
                """, (session["user_id"], leave_type, start_text, end_text, reason))
                if evidence_extension:
                    LEAVE_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
                    attachment_name = f"leave-{cursor.lastrowid}-{secrets.token_hex(8)}.{evidence_extension}"
                    evidence.save(LEAVE_UPLOAD_FOLDER / attachment_name)
                    connection.execute("UPDATE leave_requests SET attachment_name=? WHERE id=?", (attachment_name, cursor.lastrowid))
                connection.commit()
                flash("Leave request submitted.", "success")
                return redirect(url_for("leave_requests"))
        requests = connection.execute("""
            SELECT * FROM leave_requests WHERE employee_id=? ORDER BY created_at DESC, id DESC
        """, (session["user_id"],)).fetchall()
    finally:
        connection.close()
    return render_template("leave.html", requests=requests, today=today_pk().isoformat(), leave_reasons=LEAVE_REASONS)


@app.get("/leave/<int:leave_id>/evidence")
@login_required
def leave_evidence(leave_id):
    connection = get_connection()
    try:
        item = connection.execute("SELECT employee_id, attachment_name FROM leave_requests WHERE id=?", (leave_id,)).fetchone()
    finally:
        connection.close()
    if not item or not item["attachment_name"]:
        abort(404)
    if session.get("role") != "admin" and item["employee_id"] != session["user_id"]:
        abort(403)
    return send_from_directory(LEAVE_UPLOAD_FOLDER, item["attachment_name"], as_attachment=True)


@app.get("/attendance/<int:record_id>/late-picture")
@login_required
def late_check_in_picture(record_id):
    connection = get_connection()
    try:
        item = connection.execute("SELECT employee_id, late_picture_name FROM attendance WHERE id=?", (record_id,)).fetchone()
    finally:
        connection.close()
    if not item or not item["late_picture_name"]:
        abort(404)
    if session.get("role") not in {"admin", "hr"} and item["employee_id"] != session["user_id"]:
        abort(403)
    return send_from_directory(LEAVE_UPLOAD_FOLDER, item["late_picture_name"], as_attachment=True)


@app.get("/admin/leaves")
@admin_required
def admin_leaves():
    status = request.args.get("status", "pending")
    if status not in {"pending", "approved", "rejected", "all"}:
        status = "pending"
    connection = get_connection()
    try:
        requests = connection.execute("""
            SELECT l.*, e.full_name, e.employee_code, e.department,
                   reviewer.full_name AS reviewer_name
            FROM leave_requests l
            JOIN employees e ON e.id=l.employee_id
            LEFT JOIN employees reviewer ON reviewer.id=l.reviewed_by
            WHERE (?='all' OR l.status=?)
            ORDER BY CASE l.status WHEN 'pending' THEN 0 ELSE 1 END, l.created_at DESC
        """, (status, status)).fetchall()
    finally:
        connection.close()
    return render_template("admin_leaves.html", requests=requests, status=status)


@app.post("/admin/leaves/<int:leave_id>/review")
@admin_required
def review_leave(leave_id):
    action = request.form.get("action", "")
    note = request.form.get("reviewer_note", "").strip()
    if action not in {"approved", "rejected"}:
        abort(400, "Invalid leave decision.")
    connection = get_connection()
    try:
        leave = connection.execute("SELECT status FROM leave_requests WHERE id=?", (leave_id,)).fetchone()
        if not leave:
            abort(404)
        if leave["status"] != "pending":
            flash("This leave request has already been reviewed.", "error")
        else:
            connection.execute("""
                UPDATE leave_requests
                SET status=?, reviewer_note=?, reviewed_by=?, reviewed_at=?
                WHERE id=?
            """, (action, note or None, session["user_id"], now_pk().isoformat(sep=" ", timespec="seconds"), leave_id))
            connection.commit()
            flash(f"Leave request {action}.", "success")
    finally:
        connection.close()
    return redirect(url_for("admin_leaves"))


@app.route("/hr/employees")
@employee_management_required
def employees():
    connection = get_connection()
    try: people = connection.execute("SELECT * FROM employees WHERE role!='admin' ORDER BY id DESC").fetchall()
    finally: connection.close()
    return render_template("employees.html", employees=people, bootstrap_hr=session.get("role") == "admin")


@app.post("/hr/employees/add")
@employee_management_required
def add_employee():
    code, name, department, password, role = (request.form.get(k, "").strip() for k in ("employee_code", "full_name", "department", "password", "role"))
    bootstrap_hr = session.get("role") == "admin"
    if bootstrap_hr:
        role = "hr"
    if role not in {"employee", "intern", "manager", "hr"}:
        flash("Select a valid employee role.", "error"); return redirect(url_for("employees"))
    if not code or not name or not valid_password(password):
        flash("Code, name, and a valid password are required.", "error"); return redirect(url_for("employees"))
    connection = get_connection()
    try:
        connection.execute("INSERT INTO employees(employee_code,full_name,department,password_hash,must_change_password,role) VALUES(?,?,?,?,1,?)", (code, name, department or None, generate_password_hash(password), role))
        connection.commit(); flash("Employee added.", "success")
        if bootstrap_hr:
            return redirect(url_for("admin_dashboard"))
    except sqlite3.IntegrityError: flash("That employee code already exists.", "error")
    finally: connection.close()
    return redirect(url_for("employees"))


def verify_admin_password(connection):
    row = connection.execute("SELECT password_hash FROM employees WHERE id=?", (session["user_id"],)).fetchone()
    return check_password_hash(row["password_hash"], request.form.get("admin_password", ""))


@app.route("/hr/employees/<int:employee_id>/edit", methods=["GET", "POST"])
@hr_required
def edit_employee(employee_id):
    connection = get_connection()
    try:
        employee = connection.execute("SELECT * FROM employees WHERE id=? AND role!='admin'", (employee_id,)).fetchone()
        if not employee:
            abort(404)
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            department = request.form.get("department", "").strip()
            role = request.form.get("role", "").strip()
            active = 1 if request.form.get("is_active") else 0
            if not name:
                flash("Full name is required.", "error")
            elif role not in {"employee", "intern", "manager", "hr"}:
                flash("Select a valid employee role.", "error")
            elif employee_id == session["user_id"] and (role != "hr" or not active):
                flash("You cannot remove your own HR access or deactivate your account.", "error")
            else:
                deactivated = None if active else now_pk().isoformat(sep=" ", timespec="seconds")
                connection.execute("""
                    UPDATE employees SET full_name=?, department=?, role=?, is_active=?, deactivated_at=?
                    WHERE id=?
                """, (name, department or None, role, active, deactivated, employee_id))
                connection.commit()
                if employee_id == session["user_id"]:
                    session["employee_name"] = name
                flash("Employee details updated.", "success")
                return redirect(url_for("employees"))
    finally:
        connection.close()
    return render_template("edit_employee.html", employee=employee)


@app.post("/hr/employees/<int:employee_id>/toggle")
@hr_required
def toggle_employee(employee_id):
    connection = get_connection()
    try:
        if employee_id == session["user_id"]: flash("You cannot deactivate your own HR account.", "error")
        elif not verify_admin_password(connection): flash("Your password is incorrect.", "error")
        else:
            employee = connection.execute("SELECT is_active FROM employees WHERE id=? AND role!='admin'", (employee_id,)).fetchone()
            if not employee: abort(404)
            active = 0 if employee["is_active"] else 1
            deactivated = now_pk().isoformat(sep=" ", timespec="seconds") if not active else None
            connection.execute("UPDATE employees SET is_active=?, deactivated_at=? WHERE id=?", (active, deactivated, employee_id)); connection.commit(); flash("Employee status updated.", "success")
    finally: connection.close()
    return redirect(url_for("employees"))


@app.post("/hr/employees/<int:employee_id>/reset-password")
@hr_required
def reset_password(employee_id):
    password = request.form.get("password", "")
    connection = get_connection()
    try:
        employee = connection.execute("SELECT 1 FROM employees WHERE id=? AND role!='admin'", (employee_id,)).fetchone()
        if not employee: abort(404)
        if not verify_admin_password(connection): flash("Your password is incorrect.", "error")
        elif not valid_password(password): flash("Temporary password must have 8 characters, a letter, and a number.", "error")
        else:
            connection.execute("UPDATE employees SET password_hash=?, must_change_password=1 WHERE id=?", (generate_password_hash(password), employee_id)); connection.commit(); flash("Temporary password set.", "success")
    finally: connection.close()
    return redirect(url_for("employees"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    connection = get_connection()
    try:
        if request.method == "POST":
            action = request.form.get("action")
            if action == "schedule":
                effective, start, end, grace = (request.form.get(k, "").strip() for k in ("effective_from", "start_time", "end_time", "grace_minutes"))
                try:
                    date.fromisoformat(effective); time.fromisoformat(start); time.fromisoformat(end); grace = int(grace)
                    if end <= start or grace < 0: raise ValueError
                    connection.execute("INSERT INTO work_schedules(effective_from,start_time,end_time,grace_minutes,created_by) VALUES(?,?,?,?,?) ON CONFLICT(effective_from) DO UPDATE SET start_time=excluded.start_time,end_time=excluded.end_time,grace_minutes=excluded.grace_minutes,created_by=excluded.created_by", (effective, start, end, grace, session["user_id"]))
                    flash("Schedule saved.", "success")
                except ValueError: flash("Enter a valid schedule.", "error")
            elif action == "holiday":
                connection.execute("INSERT OR IGNORE INTO holidays(holiday_date,name,created_by) VALUES(?,?,?)", (request.form.get("holiday_date"), request.form.get("name", "").strip(), session["user_id"])); flash("Holiday saved.", "success")
            elif action == "network":
                networks = request.form.get("allowed_networks", "")
                try:
                    [ipaddress.ip_network(x.strip(), strict=False) for x in networks.split(",") if x.strip()]
                    connection.execute("UPDATE settings SET value=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE key='allowed_networks'", (networks, session["user_id"])); flash("Allowed networks saved.", "success")
                except ValueError: flash("Enter valid comma-separated IP networks.", "error")
            connection.commit()
        schedules = connection.execute("SELECT * FROM work_schedules ORDER BY effective_from DESC").fetchall()
        holidays = connection.execute("SELECT * FROM holidays ORDER BY holiday_date DESC").fetchall()
        networks = connection.execute("SELECT value FROM settings WHERE key='allowed_networks'").fetchone()["value"]
    finally: connection.close()
    return render_template("settings.html", schedules=schedules, holidays=holidays, networks=networks, client_ip=client_ip_address())


@app.post("/admin/holidays/<int:holiday_id>/delete")
@admin_required
def delete_holiday(holiday_id):
    connection = get_connection(); connection.execute("DELETE FROM holidays WHERE id=?", (holiday_id,)); connection.commit(); connection.close()
    flash("Holiday removed.", "success"); return redirect(url_for("admin_settings"))


@app.route("/admin/reports")
@admin_required
def reports():
    start, end = request.args.get("start", (today_pk()-timedelta(days=30)).isoformat()), request.args.get("end", today_pk().isoformat())
    if end > today_pk().isoformat(): end = today_pk().isoformat()
    if (date.fromisoformat(end)-date.fromisoformat(start)).days > 366: start=(date.fromisoformat(end)-timedelta(days=366)).isoformat()
    connection=get_connection()
    try:
        rows=build_report(connection,start,end,request.args.get("employee_id",""),request.args.get("department",""),request.args.get("label",""))
        people=connection.execute("SELECT id,full_name FROM employees ORDER BY full_name").fetchall(); departments=connection.execute("SELECT DISTINCT department FROM employees WHERE department IS NOT NULL ORDER BY department").fetchall()
    finally: connection.close()
    return render_template("reports.html",rows=rows,people=people,departments=departments,start=start,end=end)


@app.get("/admin/reports/export")
@admin_required
def export_report():
    try: from openpyxl import Workbook
    except ImportError:
        flash("Install project requirements to enable Excel export.", "error"); return redirect(url_for("reports", **request.args))
    start,end=request.args.get("start",today_pk().isoformat()),request.args.get("end",today_pk().isoformat())
    connection=get_connection()
    try: rows=build_report(connection,start,end,request.args.get("employee_id",""),request.args.get("department",""),request.args.get("label",""))
    finally: connection.close()
    book=Workbook(); sheet=book.active; sheet.title="Attendance"; sheet.append(["Employee Code","Name","Department","Date","Check In","Check Out","Status"])
    for row in rows: sheet.append([row["employee_code"],row["full_name"],row["department"],row["date"],row["check_in"],row["check_out"],", ".join(row["labels"])])
    output=io.BytesIO(); book.save(output); output.seek(0)
    return send_file(output,as_attachment=True,download_name=f"attendance-{start}-to-{end}.xlsx",mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/admin/attendance/<int:record_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_attendance(record_id):
    connection=get_connection()
    try:
        record=connection.execute("SELECT a.*,e.full_name FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.id=?",(record_id,)).fetchone()
        if not record: abort(404)
        if request.method=="POST":
            reason=request.form.get("reason","").strip(); new_in=request.form.get("check_in") or None; new_out=request.form.get("check_out") or None; valid=0 if request.form.get("is_invalid") else 1
            if not verify_admin_password(connection): flash("Admin password is incorrect.","error")
            elif not reason: flash("A correction reason is required.","error")
            elif new_in and new_out and new_out < new_in: flash("Check-out cannot be before check-in.","error")
            else:
                connection.execute("INSERT INTO attendance_audit(attendance_id,admin_id,action,reason,old_check_in,old_check_out,old_is_valid,new_check_in,new_check_out,new_is_valid) VALUES(?,?,?,?,?,?,?,?,?,?)",(record_id,session["user_id"],"invalidate" if not valid else "edit",reason,record["check_in"],record["check_out"],record["is_valid"],new_in,new_out,valid))
                connection.execute("UPDATE attendance SET check_in=?,check_out=?,is_valid=? WHERE id=?",(new_in,new_out,valid,record_id)); connection.commit(); flash("Attendance corrected and audited.","success"); return redirect(url_for("reports"))
    finally: connection.close()
    return render_template("edit_attendance.html",record=record)


@app.route("/admin/attendance/add", methods=["GET", "POST"])
@admin_required
def add_attendance():
    connection = get_connection()
    try:
        people = connection.execute("SELECT id, employee_code, full_name FROM employees ORDER BY full_name").fetchall()
        if request.method == "POST":
            employee_id = request.form.get("employee_id", "")
            check_in_value = request.form.get("check_in", "")
            check_out_value = request.form.get("check_out") or None
            reason = request.form.get("reason", "").strip()
            try:
                attendance_day = datetime.fromisoformat(check_in_value).date().isoformat()
            except ValueError:
                attendance_day = None
            if not verify_admin_password(connection):
                flash("Admin password is incorrect.", "error")
            elif not attendance_day or not reason:
                flash("Valid times and a correction reason are required.", "error")
            elif check_out_value and check_out_value < check_in_value:
                flash("Check-out cannot be before check-in.", "error")
            elif connection.execute("SELECT 1 FROM attendance WHERE employee_id=? AND attendance_date=? AND is_valid=1", (employee_id, attendance_day)).fetchone():
                flash("That employee already has a valid record for this date.", "error")
            else:
                schedule = current_schedule(connection, attendance_day)
                cursor = connection.execute("INSERT INTO attendance(employee_id,check_in,check_out,attendance_date,schedule_id) VALUES(?,?,?,?,?)", (employee_id, check_in_value, check_out_value, attendance_day, schedule["id"] if schedule else None))
                connection.execute("INSERT INTO attendance_audit(attendance_id,admin_id,action,reason,new_check_in,new_check_out,new_is_valid) VALUES(?,?,?,?,?,?,1)", (cursor.lastrowid, session["user_id"], "create", reason, check_in_value, check_out_value))
                connection.commit()
                flash("Missing attendance added and audited.", "success")
                return redirect(url_for("reports"))
    finally:
        connection.close()
    return render_template("add_attendance.html", people=people)


@app.cli.command("create-admin")
@click.option("--code", prompt="Admin ID")
@click.option("--name", prompt="Full name")
@click.password_option(confirmation_prompt=True)
def create_admin(code, name, password):
    """Create the first administrator account."""
    if not valid_password(password): raise click.ClickException("Password needs 8 characters, a letter, and a number.")
    connection=get_connection()
    try:
        if connection.execute("SELECT 1 FROM employees WHERE role='admin'").fetchone(): raise click.ClickException("An admin already exists.")
        connection.execute("INSERT INTO employees(employee_code,full_name,password_hash,role) VALUES(?,?,?,'admin')",(code.strip(),name.strip(),generate_password_hash(password))); connection.commit()
    finally: connection.close()
    click.echo("Administrator created.")


@app.cli.command("assign-hr")
@click.option("--code", required=True, help="Employee ID to promote to HR.")
def assign_hr(code):
    """Assign the HR role to an existing employee."""
    connection = get_connection()
    try:
        employee = connection.execute("SELECT id, role FROM employees WHERE employee_code=?", (code.strip(),)).fetchone()
        if not employee:
            raise click.ClickException("Employee ID was not found.")
        if employee["role"] == "admin":
            raise click.ClickException("An admin account cannot be changed to HR.")
        connection.execute("UPDATE employees SET role='hr' WHERE id=?", (employee["id"],))
        connection.commit()
    finally:
        connection.close()
    click.echo(f"{code.strip()} now has the HR role.")


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
