import re
from dataclasses import dataclass


USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,30}$")
UPPER_RE = re.compile(r"[A-Z]")
LOWER_RE = re.compile(r"[a-z]")
DIGIT_RE = re.compile(r"\d")
SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")
TAG_RE = re.compile(r"<[^>]*>")
SUSPICIOUS_RE = re.compile(
    r"(<\s*script|javascript:|onerror\s*=|onload\s*=|data:text/html|select\s+.+\s+from|drop\s+table|--|/\*)",
    re.IGNORECASE,
)
SAFE_TEXT_RE = re.compile(r"^[A-Za-z0-9 .,'&()/-]+$")
REGISTERED_USER_ROLE = "employee"


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class RegistrationData:
    username: str
    password: str
    role: str
    full_name: str
    position: str
    salary: float


@dataclass(frozen=True)
class EmployeeData:
    full_name: str
    position: str
    salary: float


def normalize_username(username: str) -> str:
    return (username or "").strip().lower()


def validate_username(username: str) -> str:
    normalized = normalize_username(username)
    if not USERNAME_RE.fullmatch(normalized):
        raise ValidationError("Username must be 3-30 characters and use only letters, numbers, dots, underscores, or hyphens.")
    return normalized


def validate_password(password: str) -> str:
    password = password or ""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not UPPER_RE.search(password):
        raise ValidationError("Password must include at least one uppercase letter.")
    if not LOWER_RE.search(password):
        raise ValidationError("Password must include at least one lowercase letter.")
    if not DIGIT_RE.search(password):
        raise ValidationError("Password must include at least one number.")
    if not SPECIAL_RE.search(password):
        raise ValidationError("Password must include at least one special character.")
    return password


def validate_safe_text(value: str, field_name: str, min_length: int = 2, max_length: int = 100) -> str:
    clean_value = " ".join((value or "").strip().split())
    if not clean_value:
        raise ValidationError(f"{field_name} is required.")
    if len(clean_value) < min_length:
        raise ValidationError(f"{field_name} must be at least {min_length} characters.")
    if len(clean_value) > max_length:
        raise ValidationError(f"{field_name} must be {max_length} characters or fewer.")
    if TAG_RE.search(clean_value) or SUSPICIOUS_RE.search(clean_value) or not SAFE_TEXT_RE.fullmatch(clean_value):
        raise ValidationError(f"{field_name} contains unsafe or unsupported characters.")
    return clean_value


def validate_salary(salary: str) -> float:
    try:
        amount = float((salary or "").strip())
    except ValueError as exc:
        raise ValidationError("Salary must be a numeric value.") from exc
    if amount < 0:
        raise ValidationError("Salary cannot be negative.")
    if amount > 100000000:
        raise ValidationError("Salary value is too large.")
    return round(amount, 2)


def validate_registration(username: str, password: str, full_name: str, position: str, salary: str) -> RegistrationData:
    return RegistrationData(
        username=validate_username(username),
        password=validate_password(password),
        role=REGISTERED_USER_ROLE,
        full_name=validate_safe_text(full_name, "Full name", min_length=2, max_length=100),
        position=validate_safe_text(position, "Position", min_length=1, max_length=80),
        salary=validate_salary(salary),
    )


def validate_employee(full_name: str, position: str, salary: str) -> EmployeeData:
    return EmployeeData(
        full_name=validate_safe_text(full_name, "Full name", min_length=2, max_length=100),
        position=validate_safe_text(position, "Position", min_length=1, max_length=80),
        salary=validate_salary(salary),
    )
