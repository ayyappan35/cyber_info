"""backend/routers/auth_router.py's _mask_email() - the partial email
mask shown on the "Verify it's you" screen when mfa_required is True, so
the account owner knows where to look without exposing the full address
to anyone who only knows the username. backend/ is on sys.path via
tests/conftest.py."""
from routers.auth_router import _mask_email


def test_mask_email_keeps_first_two_and_last_char_of_local_part():
    assert _mask_email("v.ayyappann@gmail.com") == "v.********n@gmail.com"


def test_mask_email_short_local_part():
    assert _mask_email("ab@example.com") == "a*@example.com"


def test_mask_email_single_char_local_part():
    assert _mask_email("a@example.com") == "a*@example.com"


def test_mask_email_three_char_local_part():
    assert _mask_email("bob@example.com") == "b**@example.com"


def test_mask_email_never_reveals_full_local_part():
    for email in ("test@example.com", "ayyappan@gmail.com", "x.y.z@corp.io"):
        masked = _mask_email(email)
        assert masked != email
        assert "*" in masked
        assert masked.endswith("@" + email.split("@")[1])
