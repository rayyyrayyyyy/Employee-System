import argparse
from getpass import getpass

from database import SessionLocal, create_database
from models import User
from security import hash_password
from validators import validate_password, validate_username


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or update the local admin account.")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password")
    args = parser.parse_args()

    username = validate_username(args.username)
    password = args.password or getpass("Admin password: ")
    validate_password(password)

    create_database()
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == username).first()
        if admin:
            admin.password_hash = hash_password(password)
            admin.role = "admin"
            admin.is_active = True
            action = "updated"
        else:
            admin = User(
                username=username,
                password_hash=hash_password(password),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            action = "created"

        db.commit()
        print(f"Admin account {action}: {username}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
