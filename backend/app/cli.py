import argparse
from getpass import getpass

from sqlalchemy import func, select

from app.core.security import hash_password
from app.db.session import SessionLocal
from app.domain.enums import UserRole
from app.models import User


def create_user(role: UserRole) -> None:
    email = input("Email: ").strip().casefold()
    display_name = input("Display name: ").strip()
    password = getpass("Password (12+ characters): ")
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Password must be between 12 and 128 characters")
    if not display_name or len(display_name) > 120:
        raise ValueError("Display name must be between 1 and 120 characters")

    with SessionLocal() as session:
        exists = session.scalar(select(User.id).where(func.lower(User.email) == email))
        if exists is not None:
            raise ValueError("An account with this email already exists")
        user = User(
            email=email,
            display_name=display_name,
            password_hash=hash_password(password),
            role=role.value,
        )
        session.add(user)
        session.commit()
        print(f"Created {role.value} user {user.email} (id: {user.id})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a SOCForge user account.")
    parser.add_argument("--role", choices=[role.value for role in UserRole], required=True)
    arguments = parser.parse_args()
    create_user(UserRole(arguments.role))


if __name__ == "__main__":
    main()
