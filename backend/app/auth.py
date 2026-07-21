import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from fastapi import Request, HTTPException
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlmodel import Session, select, update
from backend.db.init_db import Admin, APIKey, engine, AdminSession

# Configuration
# ─────────────────────────────────────────────────────────────
SESSION_COOKIE = "sWUI_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours

ph = PasswordHasher()
DUMMY_HASH = ph.hash("ahdfAdfaeiGFDFhh--.12fbkxfpsdfn54nnqw//ew8zuoui")

def get_db_session():
    """Yields a database session. Automatically handles commit/rollback/close."""
    with Session(engine) as session:
        yield session


def require_auth(request: Request):
    """Dependency to enforce authentication via API key or session cookie."""
    authorization = request.headers.get("authorization")
    with Session(engine) as db:

        # 1. Validate API Key
        if authorization:
            if not authorization.lower().startswith("bearer "):
                raise HTTPException(status_code=401, detail="Invalid authorization header format")

            token = authorization[7:].strip()
            api_key = db.exec(
                select(APIKey).where(APIKey.key_hash == _hash_token(token), ~APIKey.revoked)
            ).first()

            if api_key:
                request.state.is_api_key = True
                request.state.admin_id = None  # API keys may not map to an admin user
                return
            raise HTTPException(status_code=401, detail="Invalid or revoked API key")

        # 2. Validate Session Cookie
        session_token = request.cookies.get(SESSION_COOKIE)
        if not session_token:
            raise HTTPException(status_code=401, detail="Unauthorized")

        session_record = db.exec(
            select(AdminSession).where(AdminSession.token_hash == _hash_token(session_token))
        ).first()

        if not session_record or session_record.revoked:
            raise HTTPException(status_code=401, detail="Invalid or revoked session")

        # Check expiration
        if datetime.now(timezone.utc).replace(tzinfo=None) > session_record.expires_at:
            db.delete(session_record)
            raise HTTPException(status_code=401, detail="Session expired")

        # Verify admin still exists
        admin = db.exec(select(Admin).where(Admin.id == session_record.admin_id)).first()
        if not admin:
            db.delete(session_record)
            raise HTTPException(status_code=401, detail="Invalid session")

        request.state.is_api_key = False
        request.state.admin_id = session_record.admin_id


# Auth Helpers
# ─────────────────────────────────────────────────────────────
def verify_password(adminhash: str, password: str) -> bool:
    """Verifies admin credentials."""
    hash_to_check = adminhash if adminhash is not None else DUMMY_HASH
    try:
        verified=ph.verify(hash_to_check, password)
        return verified
    except VerifyMismatchError:
        return False
    except Exception:
        return False

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def create_session(admin_id: int) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    with Session(engine) as db:
        # REVOKE EXISTING SESSIONS
        db.exec(
            update(AdminSession)
            .where(
                AdminSession.admin_id == admin_id,
                AdminSession.revoked == False
            )
            .values(revoked=True)
        )

        # CREATE NEW SESSION
        session_obj = AdminSession(
            token_hash=token_hash,
            admin_id=admin_id,
            revoked=False,
            expires_at=datetime.utcnow() + timedelta(hours=8),
        )

        db.add(session_obj)
        db.commit()

    return raw_token

def revoke_session(token: str) -> bool:
    """
    Revoke a session using raw token from cookie.
    Returns True if session existed, False otherwise.
    """
    token_hash = _hash_token(token)

    with Session(engine) as db:
        session = db.exec(
            select(AdminSession).where(
                AdminSession.token_hash == token_hash
            )
        ).first()

        if not session:
            return False

        session.revoked = True
        db.add(session)
        db.commit()
        return True

