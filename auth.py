"""
auth.py - Secure login with RBAC and TOTP two-factor authentication.
Author: Safal Sapkota

GUI-independent: the Tkinter dialog (tk_login.py) and any other front end
call into this module. Teammates protect their functions with
@require_permission("encrypt") etc.

Security properties
  - Passwords hashed with Argon2id (argon2-cffi defaults), never stored or logged
  - 2FA via TOTP (RFC 6238), works offline with Google/Microsoft Authenticator
  - TOTP replay protection: a code can only be used once
  - Account lockout after MAX_FAILED attempts (fail-secure)
  - Generic error messages + dummy hash so usernames can't be enumerated
  - Deny-by-default RBAC with ownership checks (least privilege)
  - Session expiry
  - Security events go to the "securevault.auth" logger (Person 5 attaches handlers)
"""

import hmac
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from functools import wraps

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

log = logging.getLogger("securevault.auth")

# ---------------------------------------------------------------- settings
ISSUER = "SecureVault"
MIN_PASSWORD_LEN = 10
MAX_FAILED = 5            # failed attempts before lockout
LOCKOUT_SECONDS = 300     # 5 minutes
PENDING_TTL = 120         # seconds allowed between password step and 2FA step
SESSION_TTL = 900         # 15-minute sessions
TOTP_STEP = 30

GENERIC_ERROR = "Invalid credentials."

# ---------------------------------------------------------------- RBAC
ROLE_PERMISSIONS = {
    "admin":   {"encrypt", "decrypt", "delete", "view_logs", "manage_users"},
    "user":    {"encrypt", "decrypt", "delete"},
    "auditor": {"view_logs"},
}
# Permissions a role may only use on files it owns
OWN_FILES_ONLY = {
    "user": {"decrypt", "delete"},
}


class AuthError(Exception):
    """Login failed. Message is always generic."""


class PermissionDenied(Exception):
    """Session lacks the permission for an action."""


@dataclass
class Session:
    username: str
    role: str
    expires: float

    def is_active(self) -> bool:
        return time.time() < self.expires

    def can(self, permission: str, owner: str | None = None) -> bool:
        """Deny by default: expired session, unknown role or unknown permission -> False."""
        if not self.is_active():
            return False
        if permission not in ROLE_PERMISSIONS.get(self.role, set()):
            return False
        if permission in OWN_FILES_ONLY.get(self.role, set()):
            # fail-secure: if the owner isn't known, refuse
            return owner is not None and owner == self.username
        return True


def check_permission(session: Session | None, permission: str, owner: str | None = None) -> None:
    """Raise PermissionDenied unless the session may perform the action."""
    if session is None or not session.can(permission, owner):
        who = session.username if session else "<no session>"
        log.warning("ACCESS DENIED user=%s permission=%s owner=%s", who, permission, owner)
        raise PermissionDenied(f"Not allowed: {permission}")
    log.info("ACCESS GRANTED user=%s permission=%s owner=%s", session.username, permission, owner)


def require_permission(permission: str):
    """
    Decorator for teammates' functions. The first argument must be the Session;
    pass owner=<username> as a keyword when the action targets a specific file.

        @require_permission("decrypt")
        def decrypt_file(session, path, owner=None): ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(session, *args, **kwargs):
            check_permission(session, permission, kwargs.get("owner"))
            return fn(session, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------- manager
class AuthManager:
    """Stores users in a JSON file and runs the two-step login."""

    def __init__(self, db_path: str = "users.json"):
        self.db_path = db_path
        self._ph = PasswordHasher()          # Argon2id
        self._lock = threading.RLock()
        self._users = self._load()
        self._pending: dict[str, float] = {}  # username -> expiry of password step
        # Used when the username doesn't exist so timing looks the same
        self._dummy_hash = self._ph.hash("dummy-password-for-timing")

    # ---------- storage
    def _load(self) -> dict:
        if not os.path.exists(self.db_path):
            return {}
        with open(self.db_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self) -> None:
        """Atomic write so a crash can't leave a half-written user file."""
        folder = os.path.dirname(os.path.abspath(self.db_path))
        fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._users, f, indent=2)
            os.replace(tmp, self.db_path)
            try:
                os.chmod(self.db_path, 0o600)  # owner-only (no effect on Windows)
            except OSError:
                pass
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    # ---------- user management
    def create_user(self, username: str, password: str, role: str = "user") -> str:
        """Create a user and return the otpauth:// URI to show as a QR code."""
        username = username.strip().lower()
        if not username:
            raise ValueError("Username required.")
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role}")
        if len(password) < MIN_PASSWORD_LEN:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        with self._lock:
            if username in self._users:
                raise ValueError("User already exists.")
            secret = pyotp.random_base32()
            self._users[username] = {
                "pw_hash": self._ph.hash(password),
                "totp_secret": secret,
                "role": role,
                "failed": 0,
                "locked_until": 0,
                "last_totp_step": -1,
            }
            self._save()
        log.info("USER CREATED user=%s role=%s", username, role)
        return self.provisioning_uri(username)

    def provisioning_uri(self, username: str) -> str:
        secret = self._users[username.strip().lower()]["totp_secret"]
        return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)

    def set_role(self, admin: Session, username: str, role: str) -> None:
        check_permission(admin, "manage_users")
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role}")
        with self._lock:
            self._users[username]["role"] = role
            self._save()
        log.info("ROLE CHANGED by=%s user=%s role=%s", admin.username, username, role)

    def unlock_user(self, admin: Session, username: str) -> None:
        check_permission(admin, "manage_users")
        with self._lock:
            self._users[username].update(failed=0, locked_until=0)
            self._save()
        log.info("USER UNLOCKED by=%s user=%s", admin.username, username)

    def delete_user(self, admin: Session, username: str) -> None:
        check_permission(admin, "manage_users")
        with self._lock:
            self._users.pop(username, None)
            self._save()
        log.info("USER DELETED by=%s user=%s", admin.username, username)

    def list_users(self, admin: Session) -> dict[str, str]:
        check_permission(admin, "manage_users")
        return {u: r["role"] for u, r in self._users.items()}

    # ---------- login helpers
    def _is_locked(self, rec: dict) -> bool:
        return time.time() < rec.get("locked_until", 0)

    def _register_failure(self, username: str) -> None:
        rec = self._users[username]
        rec["failed"] = rec.get("failed", 0) + 1
        if rec["failed"] >= MAX_FAILED:
            rec["locked_until"] = time.time() + LOCKOUT_SECONDS
            rec["failed"] = 0
            log.warning("ACCOUNT LOCKED user=%s for %ss", username, LOCKOUT_SECONDS)
        self._save()

    # ---------- step 1: password
    def verify_password(self, username: str, password: str) -> bool:
        """Returns True if the password is right and 2FA is now expected."""
        username = username.strip().lower()
        with self._lock:
            rec = self._users.get(username)
            if rec is None:
                try:
                    self._ph.verify(self._dummy_hash, password)  # equalise timing
                except VerificationError:
                    pass
                log.warning("LOGIN FAILED (password) user=%s", username)
                return False
            if self._is_locked(rec):
                log.warning("LOGIN BLOCKED (locked) user=%s", username)
                return False
            try:
                self._ph.verify(rec["pw_hash"], password)
            except (VerificationError, InvalidHashError):
                self._register_failure(username)
                log.warning("LOGIN FAILED (password) user=%s", username)
                return False
            if self._ph.check_needs_rehash(rec["pw_hash"]):
                rec["pw_hash"] = self._ph.hash(password)
                self._save()
            self._pending[username] = time.time() + PENDING_TTL
            log.info("PASSWORD OK, awaiting 2FA user=%s", username)
            return True

    # ---------- step 2: TOTP
    def verify_2fa(self, username: str, code: str) -> Session:
        """Returns a Session on success, raises AuthError otherwise.
        A wrong code cancels the attempt; the user must re-enter the password."""
        username = username.strip().lower()
        code = (code or "").replace(" ", "").strip()
        with self._lock:
            expiry = self._pending.pop(username, None)
            rec = self._users.get(username)
            if rec is None or expiry is None or time.time() > expiry or self._is_locked(rec):
                log.warning("2FA FAILED (no valid pending login) user=%s", username)
                raise AuthError(GENERIC_ERROR)

            totp = pyotp.TOTP(rec["totp_secret"], interval=TOTP_STEP)
            now_step = int(time.time() // TOTP_STEP)
            matched = None
            for step in (now_step - 1, now_step, now_step + 1):  # tolerate clock drift
                if hmac.compare_digest(totp.at(step * TOTP_STEP), code):
                    matched = step
                    break

            if matched is None or matched <= rec.get("last_totp_step", -1):
                self._register_failure(username)
                reason = "replayed" if matched is not None else "wrong code"
                log.warning("2FA FAILED (%s) user=%s", reason, username)
                raise AuthError(GENERIC_ERROR)

            rec.update(failed=0, last_totp_step=matched)
            self._save()
            log.info("LOGIN SUCCESS user=%s role=%s", username, rec["role"])
            return Session(username, rec["role"], time.time() + SESSION_TTL)

    def login(self, username: str, password: str, code: str) -> Session:
        """One-call version (CLI/tests)."""
        if not self.verify_password(username, password):
            raise AuthError(GENERIC_ERROR)
        return self.verify_2fa(username, code)

    def logout(self, session: Session) -> None:
        session.expires = 0
        log.info("LOGOUT user=%s", session.username)
