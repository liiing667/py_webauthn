from typing import List, Optional, Type
from urllib.parse import urlsplit

from .exceptions import InvalidCrossOriginCeremony
from .structs import CollectedClientData

_DEFAULT_PORTS = {"https": 443, "http": 80}


def normalize_origin(origin: str) -> str:
    """Normalize an origin to `scheme://host[:port]` for comparison

    Lowercases the scheme and host, and drops the port when it is the default
    for the scheme. Raises `ValueError` when the value is not a valid origin.
    """
    parts = urlsplit(origin.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        raise ValueError(f'"{origin}" is not a valid origin')

    try:
        port = parts.port
    except ValueError:
        raise ValueError(f'"{origin}" is not a valid origin')

    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def verify_top_origin(
    *,
    client_data: CollectedClientData,
    expected_top_origins: Optional[List[str]],
    exception: Type[InvalidCrossOriginCeremony],
) -> None:
    """Enforce the cross-origin ceremony policy on parsed client data

    Cross-origin ceremonies are rejected by default. They are only allowed when
    the ceremony's `topOrigin`, after normalization, matches an entry in
    `expected_top_origins`. Raises the provided exception type on rejection so
    callers can distinguish this failure from other verification errors.
    """
    if not client_data.cross_origin:
        return

    if not expected_top_origins:
        raise exception(
            "Cross-origin ceremony detected but no expected top origins were provided"
        )

    if not client_data.top_origin:
        raise exception("Cross-origin ceremony did not include a top origin")

    try:
        normalized_top_origin = normalize_origin(client_data.top_origin)
    except ValueError:
        raise exception(
            f'Client data top origin "{client_data.top_origin}" was not a valid origin'
        )

    normalized_expected = set()
    for origin in expected_top_origins:
        try:
            normalized_expected.add(normalize_origin(origin))
        except ValueError:
            # An unparseable allowlist entry can never match
            continue

    if normalized_top_origin not in normalized_expected:
        raise exception(
            f'Unexpected client data top origin "{client_data.top_origin}", expected one of {expected_top_origins}'
        )
