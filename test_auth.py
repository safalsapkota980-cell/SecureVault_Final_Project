"""Run with:  pytest -q test_auth.py"""
import time

import pyotp
import pytest

import auth as A
from auth import AuthError, AuthManager, PermissionDenied, require_permission

PW = "CorrectHorse99"


@pytest.fixture
def mgr(tmp_path):
    m = AuthManager(str(tmp_path / "users.json"))
    m.create_user("alice", PW, "user")
    m.create_user("root", PW, "admin")
    m.create_user("audit", PW, "auditor")
    return m


def code_for(m, user, offset=0):
    return pyotp.TOTP(m._users[user]["totp_secret"]).at(time.time() + offset)


def test_password_not_stored_in_plaintext(mgr):
    assert PW not in open(mgr.db_path).read()


def test_successful_login(mgr):
    s = mgr.login("alice", PW, code_for(mgr, "alice"))
    assert s.username == "alice" and s.role == "user"


def test_wrong_password(mgr):
    assert not mgr.verify_password("alice", "wrong-password")


def test_unknown_user_same_result(mgr):
    assert not mgr.verify_password("nobody", PW)


def test_wrong_code_rejected_and_cancels_pending(mgr):
    assert mgr.verify_password("alice", PW)
    with pytest.raises(AuthError):
        mgr.verify_2fa("alice", "000000")
    with pytest.raises(AuthError):  # pending login is gone
        mgr.verify_2fa("alice", code_for(mgr, "alice"))


def test_2fa_without_password_step(mgr):
    with pytest.raises(AuthError):
        mgr.verify_2fa("alice", code_for(mgr, "alice"))


def test_totp_replay_blocked(mgr):
    c = code_for(mgr, "alice")
    mgr.login("alice", PW, c)
    with pytest.raises(AuthError):
        mgr.login("alice", PW, c)


def test_lockout(mgr):
    for _ in range(A.MAX_FAILED):
        mgr.verify_password("alice", "bad-password")
    assert not mgr.verify_password("alice", PW)  # correct password still refused


def test_rbac_matrix(mgr):
    u = mgr.login("alice", PW, code_for(mgr, "alice"))
    a = mgr.login("root", PW, code_for(mgr, "root"))
    au = mgr.login("audit", PW, code_for(mgr, "audit"))
    assert u.can("encrypt") and u.can("decrypt", owner="alice")
    assert not u.can("decrypt", owner="root")       # not own file
    assert not u.can("decrypt")                      # owner unknown -> deny
    assert not u.can("view_logs")
    assert a.can("decrypt", owner="alice") and a.can("manage_users")
    assert au.can("view_logs") and not au.can("encrypt")
    assert not u.can("does_not_exist")               # deny by default


def test_expired_session_denied(mgr):
    s = mgr.login("alice", PW, code_for(mgr, "alice"))
    s.expires = 0
    assert not s.can("encrypt")


def test_decorator(mgr):
    @require_permission("delete")
    def delete_file(session, path, owner=None):
        return f"deleted {path}"

    u = mgr.login("alice", PW, code_for(mgr, "alice"))
    assert delete_file(u, "a.enc", owner="alice") == "deleted a.enc"
    with pytest.raises(PermissionDenied):
        delete_file(u, "b.enc", owner="root")
    with pytest.raises(PermissionDenied):
        delete_file(None, "a.enc", owner="alice")


def test_only_admin_manages_users(mgr):
    u = mgr.login("alice", PW, code_for(mgr, "alice"))
    with pytest.raises(PermissionDenied):
        mgr.set_role(u, "alice", "admin")
