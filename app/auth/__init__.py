"""Challenge-response device authentication."""

from .auth import DEFAULT_CHALLENGE_TTL, AuthenticationError, AuthManager
from .challenge import (
    CHALLENGE_LENGTH,
    challenge_message,
    new_challenge,
    sign_challenge,
    verify_challenge_signature,
)

__all__ = [
    "CHALLENGE_LENGTH",
    "DEFAULT_CHALLENGE_TTL",
    "AuthenticationError",
    "AuthManager",
    "challenge_message",
    "new_challenge",
    "sign_challenge",
    "verify_challenge_signature",
]
