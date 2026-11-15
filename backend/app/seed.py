import sys
from .db import SessionLocal
from .models import Organization, Role, User
from .security import hash_password

def seed_default_admin(
    email: str = "admin@pentagen.com",
    password: str = "Password123!Secure",
    org_name: str = "PentaGen Security",
) -> None:
    db = SessionLocal()
    try:
        if db.query(User.id).first() is not None:
            print("[INFO] Database already contains users. Seeding skipped.")
            return

        org = Organization(name=org_name, slug="pentagen-security")
        db.add(org)
        db.flush()

        user = User(
            organization_id=org.id,
            email=email.lower().strip(),
            full_name="PentaGen Administrator",
            password_hash=hash_password(password),
            role=Role.owner,
            is_active=True,
        )
        db.add(user)
        db.commit()
        print(f"[SUCCESS] Admin created: {email} / {password}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_default_admin()

