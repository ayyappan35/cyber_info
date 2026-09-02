"""backend/auth.py - password hashing and the username-enumeration
timing fix (DUMMY_PASSWORD_HASH). backend/ is on sys.path via
tests/conftest.py."""
import bcrypt

import auth


def test_hash_and_verify_password_roundtrip():
    hashed = auth.hash_password("correct-horse-battery-staple")
    assert auth.verify_password("correct-horse-battery-staple", hashed) is True
    assert auth.verify_password("wrong-password", hashed) is False


def test_dummy_password_hash_is_a_real_bcrypt_hash():
    # Must be a genuine bcrypt hash (not a placeholder string) so
    # verify_password() against it does real, equivalent-cost work -
    # a fake/short string would make the timing fix a no-op.
    assert auth.DUMMY_PASSWORD_HASH.startswith(("$2a$", "$2b$", "$2y$"))
    # bcrypt.checkpw must accept it without raising - confirms it's
    # well-formed, not just a string that happens to start right.
    bcrypt.checkpw(b"anything", auth.DUMMY_PASSWORD_HASH.encode("utf-8"))


def test_verify_password_against_dummy_hash_never_matches():
    # Real, observed requirement: auth_router.py calls this for a
    # nonexistent username specifically to burn bcrypt work, never
    # expecting (or needing) it to succeed - DUMMY_PASSWORD_HASH is a
    # random value nobody will ever type.
    for candidate in ("password123", "", "correct-horse-battery-staple", "admin"):
        assert auth.verify_password(candidate, auth.DUMMY_PASSWORD_HASH) is False


def test_dummy_password_hash_uses_the_same_cost_factor_as_real_hashes():
    # The whole point is equivalent CPU cost - a mismatched bcrypt work
    # factor (the "$2b$NN$" cost field) would make the timing fix
    # incomplete even though it "looks" like a real hash.
    real_hash = auth.hash_password("some-real-user-password")
    real_cost = real_hash.split("$")[2]
    dummy_cost = auth.DUMMY_PASSWORD_HASH.split("$")[2]
    assert dummy_cost == real_cost
