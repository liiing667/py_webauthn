from .generate_authentication_options import generate_authentication_options
from .verify_authentication_response import (
    verify_authentication_request,
    verify_authentication_response,
    verify_authentication_result,
)
from .request_context import (
    AuthenticationService,
    AuthenticationVerifier,
    RequestScopedAuthenticator,
)
from webauthn.helpers.structs import (
    AuthenticationCeremony,
    AuthenticationRequest,
    AuthenticationRequestRegistry,
    AuthenticationResult,
    AuthenticationResultStatus,
    AuthenticationStage,
    ChallengeStep,
    ChallengeStepStatus,
    FailureStage,
    FailureStageName,
    RequestStatus,
    ResponseField,
)

__all__ = [
    "generate_authentication_options",
    "verify_authentication_response",
    "verify_authentication_result",
    "verify_authentication_request",
    "AuthenticationRequest",
    "AuthenticationCeremony",
    "AuthenticationRequestRegistry",
    "AuthenticationResult",
    "AuthenticationResultStatus",
    "AuthenticationStage",
    "ChallengeStep",
    "ChallengeStepStatus",
    "FailureStage",
    "FailureStageName",
    "RequestStatus",
    "ResponseField",
    "RequestScopedAuthenticator",
    "AuthenticationVerifier",
    "AuthenticationService",
]


authenticate = verify_authentication_result
verify_authentication = verify_authentication_result
authenticate_response = verify_authentication_result
