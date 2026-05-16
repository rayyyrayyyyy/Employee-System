# ACT-10 Improved ACT-1: Secure Employee Web System

This project is an updated secure version of the ACT-1 Employee Web System using Python, FastAPI, Jinja2, SQLAlchemy ORM, SQLite, Passlib password hashing, and Bootstrap.

## Features

- Register employee user accounts with linked employee profiles
- Secure login and logout with signed session cookies
- Admin dashboard for viewing, adding, and editing employees
- Employee dashboard limited to the logged-in employee profile
- Password hashing with Passlib Argon2
- Server-side validation and duplicate username handling
- CSRF protection for POST forms
- Role-based access control
- HTTP security headers
- Audit logging for security-relevant actions

## Quick Start

```powershell
cd secure_employee_system
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/login` in a browser.

## Test Accounts

Create employee accounts through `/register`. Admin accounts are not created through public registration. Passwords must have at least 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.

## Database

The SQLite file is created automatically as `employee_system.db` when the application starts.
You can override the local database path with the `DATABASE_URL` environment variable.

Main tables:

- `users`
- `employees`
- `audit_logs`

## Security Summary

Input security is handled by `validators.py`, authentication/session security by `security.py`, and output protection by Jinja2 autoescaping, safe templates, and security headers in `main.py`.
