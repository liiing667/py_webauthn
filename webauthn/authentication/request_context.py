"""Request-scoped authentication correlation helpers."""

from typing import Any, Optional

from webauthn.helpers.structs import (
    AuthRequest,
    AuthenticationCeremony,
    AuthenticationRequest,
    AuthenticationRequestRegistry,
    AuthenticationResult,
    AuthenticationResultStatus,
    AuthenticationStage,
    ChallengeStep,
    ChallengeStepStatus,
    Ceremony,
    FailureStage,
    FailureStageName,
    RequestContext,
    RequestRegistry,
    RequestStatus,
    ResponseField,
)
from .verify_authentication_response import (
    verify_authentication_request,
    verify_authentication_response,
    verify_authentication_result,
)

__all__ = [
    "AuthRequest",
    "AuthenticationCeremony",
    "AuthenticationRequest",
    "AuthenticationRequestRegistry",
    "AuthenticationResult",
    "AuthenticationResultStatus",
    "AuthenticationStage",
    "ChallengeStep",
    "ChallengeStepStatus",
    "Ceremony",
    "FailureStage",
    "FailureStageName",
    "RequestContext",
    "RequestRegistry",
    "RequestStatus",
    "ResponseField",
    "RequestScopedAuthenticator",
    "AuthenticationVerifier",
    "AuthenticationService",
    "verify_authentication_response",
    "verify_authentication_result",
    "verify_authentication_request",
]


class RequestScopedAuthenticator(AuthenticationRequestRegistry):
    """Registry plus convenience verification methods.

    Every call is bound to an :class:`AuthenticationRequest`.  If no ID is
    supplied, one is created and returned on both the report and exception.
    """

    def verify(
        self,
        *,
        request: Optional[AuthenticationRequest] = None,
        request_id: Optional[str] = None,
        **kwargs: Any,
    ):
        request = self._prepare(request=request, request_id=request_id, **kwargs)
        return verify_authentication_response(request=request, **kwargs)

    def verify_result(
        self,
        *,
        request: Optional[AuthenticationRequest] = None,
        request_id: Optional[str] = None,
        **kwargs: Any,
    ) -> AuthenticationResult:
        request = self._prepare(request=request, request_id=request_id, **kwargs)
        return verify_authentication_result(request=request, **kwargs)

    authenticate = verify_result
    safe_verify = verify_result

    def _prepare(
        self,
        *,
        request: Optional[AuthenticationRequest],
        request_id: Optional[str],
        expected_challenge: Optional[bytes] = None,
        **kwargs: Any,
    ) -> AuthenticationRequest:
        if request is None:
            request = self.create(request_id=request_id, challenge=expected_challenge)
        else:
            self.register(request)
        return request


AuthenticationVerifier = RequestScopedAuthenticator
AuthenticationService = RequestScopedAuthenticator
AuthenticationManager = RequestScopedAuthenticator
CeremonyManager = RequestScopedAuthenticator
