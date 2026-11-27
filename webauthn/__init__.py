from .registration.generate_registration_options import generate_registration_options
from .registration.verify_registration_response import verify_registration_response
from .authentication.generate_authentication_options import (
    generate_authentication_options,
)
from .authentication.verify_authentication_response import (
    verify_authentication_response,
    verify_authentication_result,
    verify_authentication_request,
)
from .authentication.request_context import (
    AuthenticationService,
    AuthenticationVerifier,
    RequestScopedAuthenticator,
)
from .helpers import base64url_to_bytes, options_to_json
from .helpers.challenge_ledger import ChallengeLedger
from .helpers.structs import (
    AuthenticationCeremony,
    AuthenticationContext,
    AuthenticationRequest,
    AuthenticationRequestRegistry,
    AuthenticationResult,
    AuthResult,
    AuthenticationOutcome,
    AuthenticationStage,
    ChallengeStep,
    FailureStage,
    FailurePhase,
    FailureRecord,
    RequestCorrelation,
    RequestTracker,
    ResponseField,
)

__version__ = "3.0.1"

__all__ = [
    "generate_registration_options",
    "verify_registration_response",
    "generate_authentication_options",
    "verify_authentication_response",
    "verify_authentication_result",
    "verify_authentication_request",
    "authenticate",
    "verify_authentication",
    "authenticate_response",
    "process_authentication_response",
    "AuthenticationVerifier",
    "AuthenticationService",
    "RequestScopedAuthenticator",
    "AuthenticationRequest",
    "AuthenticationCeremony",
    "AuthenticationRequestRegistry",
    "AuthenticationResult",
    "AuthResult",
    "AuthenticationOutcome",
    "AuthenticationStage",
    "ChallengeStep",
    "FailureStage",
    "FailurePhase",
    "FailureRecord",
    "ResponseField",
    "RequestCorrelation",
    "AuthenticationContext",
    "RequestTracker",
    "ChallengeLedger",
    "base64url_to_bytes",
    "options_to_json",
]

authenticate = verify_authentication_result
verify_authentication = verify_authentication_result
authenticate_response = verify_authentication_result
process_authentication_response = verify_authentication_result
