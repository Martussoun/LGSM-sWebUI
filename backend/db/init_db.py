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
        raise SystemExit("Username cannot be empty")

    password = getpass.getpass("Enter admin password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        raise SystemExit("Passwords do not match")

    if len(password) < 10:
        raise SystemExit("Password too short (minimum 10 chars)")

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
            session.add(existing)
        else:
            admin = Admin(username=username, pw_hash=pw_hash)
            session.add(admin)

        session.commit()
        print(f"Admin {username} created/updated successfully.")


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


def main():
    try:
        create_db_and_tables()
        while True:
            print("\n--- Database Setup Menu ---")
            print("1. Add Admin")
            print("2. Create API Key")
            print("3. Revoke ALL Admin Sessions")
            print(f"Type 'exit' to quit")

            user_input = input("Enter your choice (1/2/3 or exit): ").strip()

            # Check for exit command
            if user_input.lower() == "exit":
                print("\nExiting...")
                break

            try:
                choice = int(user_input)

                if choice == 1:
                    create_admin()
                    print("Admin added successfully.")
                elif choice == 2:
                    create_api_key()
                    print("API Key created successfully.")
                elif choice == 3:
                    revoke_all_sessions()
                    print("Sessions revoked.")
                else:
                    print("Invalid option. Please enter 1, 2 or 3.")

            except ValueError:
                print("Invalid input. Please enter a number (1/2/3) or 'exit'.")

    except KeyboardInterrupt:
        print("\nExiting...")


if __name__ == "__main__":
    main()
