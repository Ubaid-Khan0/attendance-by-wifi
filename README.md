# Wi-Fi-Based Employee Attendance System

A Flask and SQLite web application for managing employee attendance on
an office network. Employees sign in with their employee code and
password, check in and check out, and administrators manage employees,
work schedules, holidays, network settings, and attendance reports.

> **Current network-check approach:** The application checks whether the
> request's IP address belongs to the configured allowed network ranges.
> It does not independently detect every device connected to a Wi-Fi
> router. Configure and test the office network ranges for your
> environment.

## Features

-   Employee login using employee code and password
-   Separate employee and administrator access
-   Attendance check-in and check-out
-   Attendance status based on configured work schedules and grace
    periods
-   Late arrival and early-leaving indicators
-   Employee management
-   Work schedule configuration with effective dates
-   Holiday management
-   Allowed-network configuration for attendance access
-   Attendance reports and export functionality
-   SQLite database with employee, attendance, schedule, holiday,
    settings, and audit records
-   Password hashing, session handling, CSRF checks, and protections
    against repeated failed login attempts
-   Automated tests for key application flows

## Technology Stack

-   **Backend:** Python, Flask
-   **Database:** SQLite
-   **Frontend:** HTML templates, CSS
-   **Security:** Werkzeug password hashing and Flask sessions
-   **Testing:** Python `unittest`

## Project Structure

``` text
attendance-by-wifi/
├── app.py              # Flask routes, authentication, attendance logic
├── database.py         # SQLite connection and database initialization
├── attendance.db       # Local database file (runtime data)
├── requirements.txt    # Python dependencies
├── test_app.py         # Automated application tests
├── AGENTS.md           # Instructions for AI coding assistants
├── templates/          # HTML/Jinja templates
└── static/
    └── css/            # Stylesheets
```

## Requirements

-   Python 3.10 or newer recommended
-   Git (optional, for cloning and version control)

## Installation on Windows

### 1. Clone the repository

``` powershell
git clone https://github.com/Ubaid-Khan0/attendance-by-wifi.git
cd attendance-by-wifi
```

If you already have the project, open its folder in VS Code and use the
terminal in that folder.

### 2. Create a virtual environment

``` powershell
python -m venv .venv
```

Activate it in PowerShell:

``` powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can use the environment's Python
directly:

``` powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 3. Install dependencies

``` powershell
python -m pip install -r requirements.txt
```

## Configuration

Set a stable secret key before running the application. In PowerShell,
for the current terminal session:

``` powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-secret"
```

Do not commit real secrets to GitHub.

The database path can be overridden using `ATTENDANCE_DATABASE`. If it
is not set, the application uses `attendance.db` in the project
directory.

The application uses Pakistan Standard Time (`Asia/Karachi`) for
attendance timestamps.

### Allowed network ranges

The app's `allowed_networks` setting controls which client IP ranges are
permitted for network-restricted attendance actions. Configure it in the
administrator settings to match your actual office network, for example
a private subnet such as `192.168.1.0/24` only if that is the subnet
used by your office.

The example above is illustrative. Check the router's actual LAN subnet
first. A network-range check is not, by itself, proof of a person's
identity or a guarantee that a particular physical Wi-Fi access point
was used.

## Run the Application

From the project root, with the virtual environment activated:

``` powershell
python app.py
```

Open the local address printed by Flask in your terminal, usually:

``` text
http://127.0.0.1:5000
```

For use from other devices on the office network, configure the Flask
server binding, firewall, and router/network settings appropriately. Do
not expose the development server directly to the public internet.

## Production Deployment

The included `Procfile` starts the application with Gunicorn on a Linux
hosting service. Configure these environment variables on the host:

``` text
FLASK_SECRET_KEY=<a long, stable, random value>
FLASK_ENV=production
TRUSTED_PROXY_HOPS=1
ATTENDANCE_DATABASE=<a path on persistent storage>/attendance.db
```

`TRUSTED_PROXY_HOPS=1` is appropriate only when the application is directly
behind one trusted hosting proxy. Change it to match the documented proxy
chain of the selected host; never enable it when clients can connect directly
to Gunicorn.

After deployment, set `allowed_networks` in Admin Settings to the office
public IPv4 address with a `/32` suffix. Keep `192.168.111.0/24` only for the
local-network version. SQLite must be stored on a persistent disk, otherwise
accounts and attendance records will be lost when the host restarts.

### PythonAnywhere

PythonAnywhere provides the verified visitor address in `X-Real-IP`. In the
PythonAnywhere WSGI configuration, set these values before importing `app`:

``` python
import os
import sys

project_path = "/home/YOUR_USERNAME/attendance-by-wifi"
if project_path not in sys.path:
    sys.path.insert(0, project_path)

os.environ["FLASK_SECRET_KEY"] = "REPLACE_WITH_A_LONG_RANDOM_SECRET"
os.environ["FLASK_ENV"] = "production"
os.environ["TRUSTED_IP_HEADER"] = "X-Real-IP"
os.environ["ATTENDANCE_DATABASE"] = f"{project_path}/attendance.db"

from app import app as application
```

Do not set `TRUSTED_PROXY_HOPS` on PythonAnywhere. After reloading the web app,
open Admin Settings and set the office public IPv4 address with a `/32` suffix.

## Run Tests

Run the automated tests with:

``` powershell
python -m unittest test_app.py
```

Tests use a temporary database so they can exercise application behavior
without intentionally using the main database.

## Basic Workflow

1.  An administrator signs in to the admin area.
2.  The administrator manages employee accounts, work schedules,
    holidays, and network settings.
3.  Employees sign in using their assigned employee code and password.
4.  Employees check in when they arrive and check out when they leave.
5.  The application records attendance and determines statuses using the
    configured schedule.
6.  Administrators review attendance reports and export records when
    needed.

## Database and Data Safety

-   Back up `attendance.db` before upgrades or database changes.
-   Never delete the database to resolve an ordinary application error.
-   Keep real employee information and production database files out of
    public repositories.
-   Use strong passwords and a stable, private `FLASK_SECRET_KEY`.
-   Use HTTPS and a production-ready WSGI server before deploying beyond
    local development.
-   Review access controls and network restrictions before using the
    application with real employee data.

## Current Scope and Future Improvements

Possible future enhancements include stronger router integration,
automated detection of device presence, improved report filters,
deployment configuration, and additional tests. These are not claimed as
completed features unless implemented and verified in the code.

## Contributing

1.  Create a branch for your change.
2.  Make a focused change.
3.  Run the test suite.
4.  Review the diff and ensure secrets and private data are not
    included.
5.  Submit a pull request with a clear description.

## License

No license is specified in this repository at the time this README was
prepared. Add a `LICENSE` file before granting others permission to
reuse or redistribute the project.

## Author

**Ubaid Khan**

Repository: https://github.com/Ubaid-Khan0/attendance-by-wifi
