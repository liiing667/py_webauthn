from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Hashable, Optional

from .generate_challenge import generate_challenge


class ChallengeLedgerError(Exception):
    """Base class for challenge ledger failures."""


class UnknownChallengeError(ChallengeLedgerError):
    """The challenge was not issued by this ledger or has expired."""


class ChallengeReplayedError(ChallengeLedgerError):
    """The challenge was already consumed."""


class ChallengeScopeMismatchError(ChallengeLedgerError):
    """The challenge was issued for a different ceremony/account scope."""


def _scope_digest(scope: Optional[Hashable]) -> Optional[bytes]:
    if scope is None:
        return None

    if isinstance(scope, bytes):
        scope_bytes = scope
    elif isinstance(scope, str):
        scope_bytes = scope.encode("utf-8")
    else:
        scope_bytes = repr(scope).encode("utf-8")

    return hashlib.sha256(b"webauthn-challenge-scope/v1\0" + scope_bytes).digest()


def _challenge_key(challenge: bytes) -> bytes:
    return hashlib.sha256(b"webauthn-challenge/v1\0" + bytes(challenge)).digest()


@dataclass
class _ChallengeEntry:
    scope_digest: Optional[bytes]
    expires_at: Optional[float]
    consumed: bool = False


class ChallengeLedger:
    """A small thread-safe, single-use challenge registry.

    ``py_webauthn`` intentionally remains stateless: an application can compare the
    response challenge against the challenge stored in the user's session without using
    this class.  This helper is useful when an application wants defense-in-depth against
    concurrent or repeated submissions and wants challenges bound to an account/session
    scope.  Production deployments with multiple processes should implement the same
    consume operation atomically in their database/cache.
    """

    def __init__(self, *, default_ttl_seconds: Optional[float] = 300.0) -> None:
        self._entries: dict[bytes, _ChallengeEntry] = {}
        self._lock = threading.RLock()
        self.default_ttl_seconds = default_ttl_seconds

    def issue(
        self,
        challenge: Optional[bytes] = None,
        *,
        scope: Optional[Hashable] = None,
        ttl_seconds: Optional[float] = None,
    ) -> bytes:
        """Register and return a new random challenge or a caller-generated challenge."""
        if challenge is None:
            challenge = generate_challenge()

        challenge = bytes(challenge)
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        expires_at = None if ttl is None else time.monotonic() + ttl

        with self._lock:
            self._purge_expired_locked()
            self._entries[_challenge_key(challenge)] = _ChallengeEntry(
                scope_digest=_scope_digest(scope),
                expires_at=expires_at,
            )

        return challenge

    # A few descriptive aliases make the storage contract easy to discover.
    register = issue
    add = issue

    def consume(
        self,
        challenge: bytes,
        *,
        scope: Optional[Hashable] = None,
    ) -> None:
        """Atomically validate, scope-check, and consume a challenge.

        Raises a :class:`ChallengeLedgerError` subclass when the challenge is unknown,
        expired, assigned to another scope, or has already been consumed.
        """
        key = _challenge_key(bytes(challenge))
        expected_scope = _scope_digest(scope)

        with self._lock:
            self._purge_expired_locked()
            entry = self._entries.get(key)

            if entry is None:
                raise UnknownChallengeError("Challenge was not issued by this ledger")

            if entry.scope_digest != expected_scope:
                raise ChallengeScopeMismatchError(
                    "Challenge was issued for a different account or ceremony scope"
                )

            if entry.consumed:
                raise ChallengeReplayedError("Challenge has already been used")

            entry.consumed = True

    def check_and_consume(
        self,
        challenge: bytes,
        *,
        scope: Optional[Hashable] = None,
    ) -> bool:
        """Return ``True`` when the challenge was valid and consumed, otherwise ``False``."""
        try:
            self.consume(challenge, scope=scope)
        except ChallengeLedgerError:
            return False
        return True

    def is_consumed(self, challenge: bytes) -> bool:
        with self._lock:
            entry = self._entries.get(_challenge_key(bytes(challenge)))
            return bool(entry and entry.consumed)

    def discard(self, challenge: bytes) -> None:
        with self._lock:
            self._entries.pop(_challenge_key(bytes(challenge)), None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def _purge_expired_locked(self) -> None:
        now = time.monotonic()
        expired = [
            key
            for key, entry in self._entries.items()
            if entry.expires_at is not None and entry.expires_at <= now
        ]
        for key in expired:
            self._entries.pop(key, None)


def consume_challenge(
    ledger: Any,
    challenge: bytes,
    *,
    scope: Optional[Hashable] = None,
) -> None:
    """Consume a challenge from either a :class:`ChallengeLedger` or a compatible store.

    Compatible stores may expose ``consume``, ``consume_challenge``,
    ``check_and_consume``, or a boolean-returning ``use_challenge`` method.
    """
    if ledger is None:
        return

    # Convenience for tests or tiny applications that pass a plain in-memory set.
    # Such a set cannot enforce scope; use ChallengeLedger for account binding.
    if isinstance(ledger, set):
        if challenge in ledger:
            raise ChallengeReplayedError("Challenge has already been used")
        ledger.add(challenge)
        return

    consume = getattr(ledger, "consume", None)
    if callable(consume):
        consume(challenge, scope=scope)
        return

    consume_challenge_method = getattr(ledger, "consume_challenge", None)
    if callable(consume_challenge_method):
        consume_challenge_method(challenge, scope=scope)
        return

    check_and_consume = getattr(ledger, "check_and_consume", None)
    if callable(check_and_consume):
        if not check_and_consume(challenge, scope=scope):
            raise ChallengeReplayedError("Challenge could not be consumed")
        return

    use_challenge = getattr(ledger, "use_challenge", None)
    if callable(use_challenge):
        if use_challenge(challenge, scope=scope) is False:
            raise ChallengeReplayedError("Challenge could not be consumed")
        return

    raise TypeError("challenge_ledger does not expose a supported consume method")
