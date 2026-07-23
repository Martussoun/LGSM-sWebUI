from __future__ import annotations
import os
import secrets
import getpass
import subprocess
import tempfile
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.sql.schema import Index
from sqlmodel import Field, Session, SQLModel, create_engine, select, update
from argon2 import PasswordHasher
from argon2.low_level import Type

class Admin(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    username: str = Field(index=True, unique=True)
    pw_hash: str

    is_locked: bool = Field(default=False)
    locked_until: Optional[datetime] = None
    failed_attempts: int = Field(default=0)
    revoked_access: bool = Field(default=False, index=True)


class AdminSession(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)

    token_hash: str = Field(index=True, unique=True)
    admin_id: int = Field(foreign_key="admin.id", index=True)

    revoked: bool = Field(default=False, index=True)
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    __table_args__ = (
        Index("idx_admin_id_created_at", "admin_id", "created_at"),
    )

class APIKey(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    key_hash: str = Field(unique=True, index=True)
    description: str | None = None

    revoked: bool = Field(default=False, index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

def revoke_all_sessions():
    with Session(engine) as session:
        result = session.exec(
            update(AdminSession)
            .where(AdminSession.revoked == False)
            .values(revoked=True)
        )
        session.commit()

def argon2id_setup():
    print("\n--- Argon2id Setup ---\n")

    time_cost = int(input("Time cost (iterations) [3]: ") or 3)
    memory_mb = int(input("Memory cost (MB) [64]: ") or 64)
    parallelism = int(input("Parallelism (threads) [2]: ") or 2)
    hash_length = int(input("Hash length (bytes) [32]: ") or 32)
    salt_length = int(input("Salt length (bytes) [16]: ") or 16)

    memory_kib = memory_mb * 1024

    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_length,
        salt_len=salt_length,
        type=Type.ID,
    )


# DB SETUP
script_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(script_dir, "admin.db")
sqlite_url = f"sqlite:///{db_path}"

engine = create_engine(
    sqlite_url,
    echo=True,
    connect_args={"check_same_thread": False}
)

def create_db_and_tables():
    """
    Checks if the database file exists.
    If it does not exist, creates the DB and tables.
    If it exists, skips creation to avoid errors or redundant work.
    """
    # Check if the database file already exists on disk
    if os.path.exists(db_path):
        print(f"Database '{db_path}' already exists. Skipping table creation.")
        return

    print(f"Database '{db_path}' does not exist. Creating tables...")

    try:
        SQLModel.metadata.create_all(engine)
        print("Tables created successfully.")
    except Exception as e:
        print(f"Error creating tables: {e}")


# ADMIN MANAGEMENT
def create_admin():
    username = input("Enter admin username: ").strip()
    if not username:
        print("Username cannot be empty")
        return

    password = getpass.getpass("Enter admin password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match")
        return

    if len(password) < 10:
        print("Password too short (minimum 10 chars)")
        return

    ph = argon2id_setup()
    pw_hash = ph.hash(password)

    with Session(engine) as session:
        existing = session.exec(
            select(Admin).where(Admin.username == username)
        ).first()

        if existing:
            print(f"Admin {username} already exists, updating password...")
            existing.pw_hash = pw_hash
            existing.failed_attempts = 0
            existing.is_locked = False
            existing.locked_until = None
            existing.revoked_access = False
            session.add(existing)
        else:
            admin = Admin(username=username, pw_hash=pw_hash, revoked_access=False)
            session.add(admin)

        session.commit()
        print(f"Admin {username} created/updated successfully.")


def revoke_admin():
    with Session(engine) as session:
        # Fetch all admins to show the list
        admins = session.exec(select(Admin)).all()

        if not admins:
            print("No admins found in the database.")
            return

        print("\n--- Current Admins ---")
        for a in admins:
            status = "REVOKED" if a.revoked_access else "ACTIVE"
            print(f"ID: {a.id} | Username: {a.username} | Status: {status}")

        username_to_revoke = input("\nEnter the username to REVOKE (or 'cancel'): ").strip()

        if username_to_revoke.lower() == 'cancel':
            return

        admin = session.exec(select(Admin).where(Admin.username == username_to_revoke)).first()

        if admin:
            if admin.revoked_access:
                print(f"Admin '{admin.username}' is already revoked.")
            else:
                # 1. Revoke the Admin account access
                session.exec(
                    update(Admin)
                    .where(Admin.username == username_to_revoke)
                    .values(revoked_access=True)
                )

                # 2. Revoke all active sessions for this specific admin ID
                session.exec(
                    update(AdminSession)
                    .where(AdminSession.admin_id == admin.id)
                    .where(AdminSession.revoked == False)
                    .values(revoked=True)
                )

                session.commit()
                print(f"Admin '{username_to_revoke}' has been revoked and all their active sessions killed.")
        else:
            print(f"Admin '{username_to_revoke}' not found.")


# API KEY MANAGEMENT
def create_api_key():
    description = input("API Key description (optional): ").strip()

    raw_key = secrets.token_urlsafe(40)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = APIKey(
        key_hash=key_hash,
        description=description
    )

    with Session(engine) as session:
        session.add(api_key)
        session.commit()
        session.refresh(api_key)

    print("\nAPI Key created (COPY OR STORE THIS NOW, IT WILL NOT BE SHOWN AGAIN):\n")
    print(raw_key)

    choice = input("Encrypt and save to .gpg file? [y/N]: ").strip().lower()

    if choice in {"y","Y"}:
        password = input("Enter encryption password: ")

        filename = f"api_key_{api_key.id}.gpg"

        # write raw key to temp file
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(raw_key)
            tmp_path = tmp.name

        try:
            subprocess.run(
                [
                    "gpg",
                    "--batch",
                    "--yes",
                    "--symmetric",
                    "--cipher-algo", "AES256",
                    "--passphrase", password,
                    "--output", filename,
                    tmp_path
                ],
                check=True
            )

            print(f"\nEncrypted API key saved to: {filename}")

        finally:
            os.remove(tmp_path)
    print()


def revoke_api_key():
    with Session(engine) as session:
        keys = session.exec(select(APIKey)).all()
        if not keys:
            print("No API keys found.")
            return

        print("\nAvailable API Keys:")
        for k in keys:
            status = "REVOKED" if k.revoked else "ACTIVE"
            print(f"ID: {k.id} | Description: {k.description} | Status: {status}")

        key_id_input = input("\nEnter the ID of the key to REVOKE (or 'cancel'): ").strip()
        if key_id_input.lower() == 'cancel':
            return

        try:
            key_id = int(key_id_input)
            # Update the revoked status to True instead of deleting the row
            session.exec(
                update(APIKey)
                .where(APIKey.id == key_id)
                .values(revoked=True)
            )
            session.commit()
            print(f"API Key ID {key_id} has been successfully revoked.")
        except ValueError:
            print("Invalid input. Please enter a numeric ID.")

def main():
    try:
        create_db_and_tables()
        while True:
            print("\n--- Database Management Menu ---")
            print("1. Add Admin or restore access to existing Admin account")
            print("2. Create API Key")
            print("3. Revoke ALL Admin Sessions")
            print("4. Revoke Admin Access")
            print("5. Revoke API Key")
            print(f"Type 'exit' to quit")

            user_input = input("Enter your choice (1/2/3/4/5 or exit): ").strip()

            if user_input.lower() in {"exit","e","quit","q"}:
                print("\nExiting...")
                break

            try:
                choice = int(user_input)

                if choice == 1:
                    create_admin()
                elif choice == 2:
                    create_api_key()
                elif choice == 3:
                    revoke_all_sessions()
                    print("Sessions revoked.")
                elif choice == 4:
                    revoke_admin()
                elif choice == 5:
                    revoke_api_key()
                else:
                    print("Invalid option. Please enter 1, 2, 3, 4, or 5.")

            except ValueError:
                print("Invalid input. Please enter a number or 'exit'.")

    except KeyboardInterrupt:
        print("\nExiting...")

if __name__ == "__main__":
    main()