import pytest

from app import auth


@pytest.fixture(autouse=True)
def clean_auth_state():
    """Give every test a clean in-memory database and lockout state."""
    auth.reset_state()
    auth.register_user("alice", "Alice123!Secure")
    auth.register_user("bob", "Bob123456!Secure")
    yield
    auth.reset_state()
