"""Baseline demo organisation. Devices created here are SIMULATED inventory (source='simulated')."""
from __future__ import annotations

from sqlalchemy import select

from .db import Base, SessionLocal, engine
from .demo import scenario
from .models import Device, Organization, User, utcnow
import os
import pathlib
import secrets

from .services.auth import hash_password
from .services.store import audit

USERS = [
    ("aisha.admin", "Aisha Al Hammadi", "aisha.alhammadi@alnoorlogistics.ae", "admin"),
    ("omar.analyst", "Omar Al Suwaidi", "omar.alsuwaidi@alnoorlogistics.ae", "analyst"),
    ("layla.analyst", "Layla Haddad", "layla.haddad@alnoorlogistics.ae", "analyst"),
    ("sara.ahmed", "Sara Ahmed", scenario.VICTIM["email"], "employee"),
]

DEVICES = [
    (scenario.VICTIM["device"], "Windows 11 Enterprise 24H2", scenario.VICTIM["email"], "10.20.4.37"),
    ("ALN-HR-LT02", "Windows 11 Enterprise 24H2", "mariam.khoury@alnoorlogistics.ae", "10.20.4.52"),
    ("ALN-IT-WS01", "Windows Server 2022", "omar.alsuwaidi@alnoorlogistics.ae", "10.20.1.10"),
    ("ALN-OPS-LT11", "macOS 15 Sequoia", "yousef.rahman@alnoorlogistics.ae", "10.20.6.21"),
]


CRED_FILE = pathlib.Path(os.getenv("WOLVE_CREDENTIALS_FILE", str(pathlib.Path(__file__).resolve().parent.parent / "demo-credentials.txt")))


def _migrate() -> None:
    """Add columns introduced after the first release (SQLite create_all does not alter existing tables)."""
    with engine.begin() as conn:
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)").fetchall()] if engine.dialect.name == "sqlite" else []
        if cols and "password_hash" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN password_hash VARCHAR(200)")


def ensure_passwords() -> None:
    """Give every user without a password a random one, written to backend/demo-credentials.txt (git-ignored)."""
    with SessionLocal() as db:
        missing = db.scalars(select(User).where(User.password_hash.is_(None))).all()
        if not missing:
            return
        lines = []
        for u in missing:
            pw = secrets.token_urlsafe(9)
            u.password_hash = hash_password(pw)
            lines.append(f"{u.username}\t{u.role}\t{pw}")
        db.commit()
    with CRED_FILE.open("a", encoding="utf-8") as fh:
        fh.write(f"# WOLVE sign-in passwords (generated {utcnow().isoformat()}). Change them in Settings.\n" + "\n".join(lines) + "\n")


def seed(reset_by: str = "system") -> None:
    Base.metadata.create_all(engine)
    _migrate()
    with SessionLocal() as db:
        if db.scalars(select(Organization)).first():
            db.close()
            ensure_passwords()
            return
        org = Organization(name=scenario.ORG_NAME, domain=scenario.ORG_DOMAIN)
        db.add(org)
        db.flush()
        for u, n, e, r in USERS:
            db.add(User(username=u, full_name=n, email=e, role=r, organization_id=org.id))
        for h, os_, owner, ip in DEVICES:
            db.add(Device(hostname=h, os=os_, owner_email=owner, ip_address=ip, source="simulated", agent_version="sim-0.1",
                          last_seen=utcnow(), system_info={"note": "Simulated inventory device for the demo"}))
        audit(db, reset_by, "system.seed", org.name)
        db.commit()
    ensure_passwords()


if __name__ == "__main__":
    seed()
    print("Seeded.")
