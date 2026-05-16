import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from database import create_database, get_db
from models import Employee, User
from security import (
    add_audit_log,
    clear_login_failures,
    get_client_ip,
    get_csrf_token,
    hash_password,
    is_locked_out,
    login_user,
    logout_user,
    record_login_failure,
    redirect_for_user,
    require_admin,
    require_employee,
    validate_csrf_token,
    verify_password,
)
from validators import ValidationError, normalize_username, validate_employee, validate_registration, validate_username


BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="ACT-10 Secure Employee Web System", debug=False)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", secrets.token_urlsafe(32)),
    https_only=False,
    same_site="lax",
    max_age=60 * 60,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates", autoescape=True)


@app.on_event("startup")
def on_startup() -> None:
    create_database()


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def render(request: Request, template_name: str, context: dict | None = None, status_code: int = 200) -> HTMLResponse:
    data = {"request": request, "csrf_token": get_csrf_token(request)}
    if context:
        data.update(context)
    return templates.TemplateResponse(template_name, data, status_code=status_code)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return render(
        request,
        "error.html",
        {"message": exc.detail or "The request could not be completed.", "status_code": exc.status_code},
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path == "/login":
        return render(request, "login.html", {"error": "Please enter your username and password."}, status_code=400)
    if request.url.path == "/register":
        return render(request, "register.html", {"error": "Please complete all required fields."}, status_code=400)
    return render(
        request,
        "error.html",
        {"message": "Please complete all required fields.", "status_code": 400},
        status_code=400,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return render(
        request,
        "error.html",
        {"message": "A system error occurred. Please try again later.", "status_code": 500},
        status_code=500,
    )


@app.get("/", response_class=HTMLResponse)
def index() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render(request, "register.html")


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    full_name: str = Form(""),
    position: str = Form(""),
    salary: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    try:
        validate_csrf_token(request, csrf_token)
        data = validate_registration(username, password, full_name, position, salary)
        password_hash = hash_password(data.password)

        user = User(username=data.username, password_hash=password_hash, role=data.role)
        employee = Employee(full_name=data.full_name, position=data.position, salary=data.salary, user=user)
        db.add(user)
        db.add(employee)
        db.flush()
        add_audit_log(db, user.id, "employee created", get_client_ip(request), "success")
        db.commit()
        return render(request, "login.html", {"success": "Registration successful. You can now log in."})
    except ValidationError as exc:
        db.rollback()
        return render(request, "register.html", {"error": str(exc)}, status_code=400)
    except IntegrityError:
        db.rollback()
        return render(request, "register.html", {"error": "Username is already registered."}, status_code=400)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    ip_address = get_client_ip(request)
    normalized_username = normalize_username(username)
    try:
        validate_csrf_token(request, csrf_token)
        normalized_username = validate_username(username)
    except (ValidationError, HTTPException):
        add_audit_log(db, None, "login failure", ip_address, "invalid input")
        db.commit()
        return render(request, "login.html", {"error": "Invalid username or password."}, status_code=400)

    if is_locked_out(normalized_username):
        add_audit_log(db, None, "login failure", ip_address, "locked out")
        db.commit()
        return render(request, "login.html", {"error": "Too many failed attempts. Please try again later."}, status_code=429)

    user = db.query(User).filter(User.username == normalized_username).first()
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        record_login_failure(normalized_username)
        add_audit_log(db, user.id if user else None, "login failure", ip_address, "failed")
        db.commit()
        return render(request, "login.html", {"error": "Invalid username or password."}, status_code=400)

    clear_login_failures(normalized_username)
    login_user(request, user)
    add_audit_log(db, user.id, "login success", ip_address, "success")
    db.commit()
    return redirect_for_user(user)


@app.post("/logout")
def logout(
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    user_id = request.session.get("user_id")
    validate_csrf_token(request, csrf_token)
    add_audit_log(db, user_id, "logout", get_client_ip(request), "success")
    db.commit()
    logout_user(request)
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    employees = db.query(Employee).order_by(Employee.id.desc()).all()
    users = db.query(User).order_by(User.id.desc()).all()
    audit_logs = db.query(User).count()
    return render(
        request,
        "admin_dashboard.html",
        {"current_user": current_user, "employees": employees, "users": users, "user_count": audit_logs},
    )


@app.post("/admin/employees", response_class=HTMLResponse)
def add_employee(
    request: Request,
    full_name: str = Form(""),
    position: str = Form(""),
    salary: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        validate_csrf_token(request, csrf_token)
        data = validate_employee(full_name, position, salary)
        employee = Employee(full_name=data.full_name, position=data.position, salary=data.salary)
        db.add(employee)
        db.flush()
        add_audit_log(db, current_user.id, "employee created", get_client_ip(request), "success")
        db.commit()
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    except ValidationError as exc:
        db.rollback()
        employees = db.query(Employee).order_by(Employee.id.desc()).all()
        users = db.query(User).order_by(User.id.desc()).all()
        return render(
            request,
            "admin_dashboard.html",
            {"current_user": current_user, "employees": employees, "users": users, "error": str(exc), "user_count": len(users)},
            status_code=400,
        )


@app.get("/admin/employees/{employee_id}/edit", response_class=HTMLResponse)
def edit_employee_page(
    request: Request,
    employee_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    employee = db.get(Employee, employee_id)
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found.")
    return render(request, "edit_employee.html", {"current_user": current_user, "employee": employee})


@app.post("/admin/employees/{employee_id}/edit", response_class=HTMLResponse)
def edit_employee(
    request: Request,
    employee_id: int,
    full_name: str = Form(""),
    position: str = Form(""),
    salary: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    employee = db.get(Employee, employee_id)
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found.")

    try:
        validate_csrf_token(request, csrf_token)
        data = validate_employee(full_name, position, salary)
        employee.full_name = data.full_name
        employee.position = data.position
        employee.salary = data.salary
        add_audit_log(db, current_user.id, "employee updated", get_client_ip(request), "success")
        db.commit()
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    except ValidationError as exc:
        db.rollback()
        return render(
            request,
            "edit_employee.html",
            {"current_user": current_user, "employee": employee, "error": str(exc)},
            status_code=400,
        )


@app.get("/employee/dashboard", response_class=HTMLResponse)
def employee_dashboard(request: Request, current_user: User = Depends(require_employee)):
    return render(request, "employee_dashboard.html", {"current_user": current_user, "employee": current_user.employee})
