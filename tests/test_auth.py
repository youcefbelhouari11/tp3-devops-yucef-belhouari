import pytest

from app import auth


def test_valid_authentication():
    result = auth.authenticate("alice", "Alice123!Secure")
    assert result == {
        "success": True,
        "message": "Connexion reussie",
    }


def test_wrong_password_is_rejected():
    result = auth.authenticate("alice", "WrongPassword123!")
    assert result["success"] is False
    assert result["message"] == auth.GENERIC_ERROR


def test_unknown_user_is_rejected_with_same_message():
    known_user_response = auth.authenticate("alice", "WrongPassword123!")
    unknown_user_response = auth.authenticate("unknown", "WrongPassword123!")

    assert known_user_response["success"] is False
    assert unknown_user_response["success"] is False
    assert known_user_response["message"] == unknown_user_response["message"]


def test_account_is_locked_after_three_failures(monkeypatch):
    fake_time = {"now": 1_000_000.0}
    monkeypatch.setattr(auth.time, "time", lambda: fake_time["now"])

    for _ in range(auth.MAX_ATTEMPTS):
        auth.authenticate("alice", "WrongPassword123!")

    # Even the correct password is rejected while the account is locked.
    result = auth.authenticate("alice", "Alice123!Secure")
    assert result["success"] is False

    # After the lockout period, the correct password works again.
    fake_time["now"] += auth.LOCKOUT_SECONDS + 1
    result_after_lockout = auth.authenticate("alice", "Alice123!Secure")
    assert result_after_lockout["success"] is True


def test_password_is_not_stored_in_plain_text():
    password = "NewPassword123!"
    assert auth.register_user("charlie", password) is True
    assert auth.users["charlie"] != password
    assert auth.users["charlie"].startswith("pbkdf2_sha256$")


def test_duplicate_username_is_rejected():
    assert auth.register_user("alice", "AnotherPassword123!") is False


@pytest.mark.parametrize(
    ("username", "password"),
    [
        ("", "ValidPassword123!"),
        ("   ", "ValidPassword123!"),
        (None, "ValidPassword123!"),
        (123, "ValidPassword123!"),
        ("alice", ""),
        ("alice", None),
        ("alice", 123),
        ("ab", "ValidPassword123!"),
        ("a" * 33, "ValidPassword123!"),
        ("alice", "short"),
    ],
)
def test_invalid_inputs_are_rejected_without_exception(username, password):
    result = auth.authenticate(username, password)
    assert result["success"] is False
    assert result["message"] == auth.GENERIC_ERROR


def test_registration_rejects_weak_password():
    assert auth.register_user("charlie", "short") is False
    assert "charlie" not in auth.users


def test_successful_login_clears_previous_failed_attempts():
    auth.authenticate("alice", "WrongPassword123!")
    assert auth.attempts["alice"] == 1

    result = auth.authenticate("alice", "Alice123!Secure")
    assert result["success"] is True
    assert "alice" not in auth.attempts
