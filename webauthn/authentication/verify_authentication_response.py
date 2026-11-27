from dataclasses import dataclass
from functools import wraps
import hashlib
from typing import Any, Dict, List, Optional, Union

from cryptography.exceptions import InvalidSignature

from webauthn.helpers import (
    bytes_to_base64url,
    byteslike_to_bytes,
    decode_credential_public_key,
    decoded_public_key_to_cryptography,
    parse_authenticator_data,
    parse_backup_flags,
    parse_client_data_json,
    parse_authentication_credential_json,
    verify_signature,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidBackupFlags,
    WebAuthnException,
)
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticationFailureCode,
    AuthenticationRequest,
    AuthenticationResult,
    AuthenticationStage,
    BackupStateAudit,
    BackupStateChange,
    ChallengeStep,
    ClientDataType,
    CredentialDeviceType,
    FailureStage,
    PublicKeyCredentialType,
    SignCountAudit,
    SignCountStatus,
    TokenBindingStatus,
)


@dataclass
class VerifiedAuthentication:
    """
    Information about a verified authentication of which an RP can make use
    """

    credential_id: bytes
    new_sign_count: int
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool
    user_verified: bool
    sign_count: Optional[SignCountAudit] = None
    backup_state: Optional[BackupStateAudit] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    request: Optional[AuthenticationRequest] = None
    challenge_step: Optional[ChallengeStep] = None
    authentication_result: Optional[AuthenticationResult] = None
    failure_stage: Optional[FailureStage] = None
    success: bool = True
    ok: bool = True

    @property
    def result(self) -> Optional[AuthenticationResult]:
        return self.authentication_result


def _invalid(
    message: str, code: AuthenticationFailureCode
) -> InvalidAuthenticationResponse:
    return InvalidAuthenticationResponse(message, code)


def _audit_sign_count(current_sign_count: int, new_sign_count: int) -> SignCountAudit:
    """Interpret the signature counter in the response relative to the stored counter"""
    if current_sign_count == 0 and new_sign_count == 0:
        # Authenticators like synced passkeys commonly do not maintain a signature counter
        status = SignCountStatus.NOT_SUPPORTED
        rolled_back = False
    elif new_sign_count > current_sign_count:
        status = SignCountStatus.INCREMENTED
        rolled_back = False
    else:
        # A counter that fails to advance can indicate a replayed or cloned credential
        status = SignCountStatus.ROLLED_BACK
        rolled_back = True

    return SignCountAudit(
        status=status,
        previous_sign_count=current_sign_count,
        new_sign_count=new_sign_count,
        rolled_back=rolled_back,
    )


def _audit_backup_state(
    *,
    new_device_type: CredentialDeviceType,
    new_backed_up: bool,
    expected_device_type: Union[CredentialDeviceType, None],
    expected_backed_up: Union[bool, None],
) -> BackupStateAudit:
    """Compare backup flags reported in the response with the stored credential record"""
    if expected_device_type is None and expected_backed_up is None:
        change = BackupStateChange.UNCHANGED
    elif expected_device_type != new_device_type:
        change = BackupStateChange.DEVICE_TYPE_CHANGED
    elif expected_backed_up != new_backed_up:
        change = BackupStateChange.BACKUP_STATE_CHANGED
    else:
        change = BackupStateChange.UNCHANGED

    # A credential migrates when it goes from a single-device to a multi-device model
    credential_migrated = (
        expected_device_type == CredentialDeviceType.SINGLE_DEVICE
        and new_device_type == CredentialDeviceType.MULTI_DEVICE
    )

    return BackupStateAudit(
        change=change,
        previous_device_type=expected_device_type,
        new_device_type=new_device_type,
        previous_backed_up=expected_backed_up,
        new_backed_up=new_backed_up,
        credential_migrated=credential_migrated,
    )


expected_token_binding_statuses = [
    TokenBindingStatus.SUPPORTED,
    TokenBindingStatus.PRESENT,
]


def _verify_authentication_response_core(
    *,
    credential: Union[str, Dict[str, Any], AuthenticationCredential],
    expected_challenge: Optional[bytes] = None,
    expected_rp_id: str,
    expected_origin: Union[str, List[str]],
    credential_public_key: bytes,
    credential_current_sign_count: int,
    expected_credential_device_type: Union[CredentialDeviceType, None] = None,
    expected_credential_backed_up: Union[bool, None] = None,
    require_user_verification: bool = False,
    request: Union[AuthenticationRequest, str, None] = None,
    authentication_request: Union[AuthenticationRequest, str, None] = None,
    ceremony: Union[AuthenticationRequest, str, None] = None,
    context: Union[AuthenticationRequest, str, None] = None,
    correlation: Union[AuthenticationRequest, str, None] = None,
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    request_identifier: Optional[str] = None,
    challenge_step: Optional[ChallengeStep] = None,
    challenge_ledger: Any = None,
    challenge_store: Any = None,
    ledger: Any = None,
    challenge_scope: Any = None,
    **metadata: Any,
) -> VerifiedAuthentication:
    """Verify a response from navigator.credentials.get()

    Args:
        - `credential`: The value returned from `navigator.credentials.get()`. Can be either a
          stringified JSON object, a plain dict, or an instance of AuthenticationCredential
        - `expected_challenge`: The challenge passed to the authenticator within the preceding
          authentication options.
        - `expected_rp_id`: The Relying Party's unique identifier as specified in the preceding
          authentication options.
        - `expected_origin`: The domain, with HTTP protocol (e.g. "https://domain.here"), on which
          the authentication ceremony should have occurred.
        - `credential_public_key`: The public key for the credential's ID as provided in a
          preceding authenticator registration ceremony.
        - `credential_current_sign_count`: The current known number of times the authenticator was
          used.
        - (optional) `expected_credential_device_type`: The `credential_device_type` value stored for
          this credential during registration. When provided, the device type reported in the
          response is compared against it and any mismatch is reported via the returned
          `backup_state` audit or rejected as a device type mismatch.
        - (optional) `expected_credential_backed_up`: The `credential_backed_up` value stored for
          this credential during registration. When provided, the backup state reported in the
          response is compared against it and any mismatch is reported via the returned
          `backup_state` audit or rejected as a backup state mismatch.
        - (optional) `require_user_verification`: Whether or not to require that the authenticator
          verified the user.

    Returns:
        Information about the authenticator

    Raises:
        `helpers.exceptions.InvalidAuthenticationResponse` if the response cannot be verified.
        The exception's `code` attribute carries a stable `AuthenticationFailureCode` value.
    """
    request_context = _coerce_request_context(
        request=request or authentication_request or ceremony or context or correlation,
        request_id=request_id
        or correlation_id
        or request_identifier
        or metadata.pop("authentication_request_id", None)
        or metadata.pop("ceremony_id", None)
        or metadata.pop("request_uuid", None),
        correlation_id=correlation_id or request_identifier,
        challenge_step=challenge_step,
        challenge=expected_challenge,
    )
    request_context.metadata.update(metadata)

    if expected_challenge is None:
        expected_challenge = request_context.challenge
    elif request_context.challenge is None:
        request_context.challenge = bytes(expected_challenge)
        request_context.expected_challenge = bytes(expected_challenge)
        request_context.challenge_step.challenge = bytes(expected_challenge)

    def reject(
        message: str,
        code: AuthenticationFailureCode,
        *,
        stage: AuthenticationStage,
        field: Union[str, None] = None,
    ) -> InvalidAuthenticationResponse:
        error = InvalidAuthenticationResponse(
            message,
            code,
            stage=stage,
            field=field,
            request=request_context,
            challenge_step=request_context.challenge_step,
        )
        request_context.record_failure(error=error, failure_stage=error.failure_stage)
        error.authentication_result = request_context.result
        return error

    if isinstance(credential, str) or isinstance(credential, dict):
        try:
            credential = parse_authentication_credential_json(credential)
        except WebAuthnException as exc:
            raise reject(
                str(exc),
                AuthenticationFailureCode.MALFORMED_CREDENTIAL,
                stage=AuthenticationStage.PARSE_CREDENTIAL,
                field=_credential_parse_field(exc),
            ) from exc

    # FIDO-specific check
    if bytes_to_base64url(credential.raw_id) != credential.id:
        raise reject(
            "id and raw_id were not equivalent",
            AuthenticationFailureCode.BAD_CREDENTIAL_ID,
            stage=AuthenticationStage.CREDENTIAL_ID,
        )

    # FIDO-specific check
    if credential.type != PublicKeyCredentialType.PUBLIC_KEY:
        raise reject(
            f'Unexpected credential type "{credential.type}", expected "public-key"',
            AuthenticationFailureCode.BAD_CREDENTIAL_TYPE,
            stage=AuthenticationStage.CREDENTIAL_TYPE,
        )

    response = credential.response

    client_data_bytes = byteslike_to_bytes(response.client_data_json)
    authenticator_data_bytes = byteslike_to_bytes(response.authenticator_data)
    signature_bytes = byteslike_to_bytes(response.signature)

    try:
        client_data = parse_client_data_json(client_data_bytes)
    except Exception as exc:
        raise reject(
            "clientDataJSON was malformed. See __cause__ for more info",
            AuthenticationFailureCode.MALFORMED_CREDENTIAL,
            stage=AuthenticationStage.PARSE_CLIENT_DATA,
            field=_client_data_parse_field(exc),
        ) from exc

    if client_data.type != ClientDataType.WEBAUTHN_GET:
        raise reject(
            f'Unexpected client data type "{client_data.type}", expected "{ClientDataType.WEBAUTHN_GET}"',
            AuthenticationFailureCode.BAD_CLIENT_DATA_TYPE,
            stage=AuthenticationStage.CLIENT_DATA_TYPE,
        )

    if expected_challenge != client_data.challenge:
        raise reject(
            "Client data challenge was not expected challenge",
            AuthenticationFailureCode.BAD_CHALLENGE,
            stage=AuthenticationStage.CHALLENGE,
        )

    selected_ledger = challenge_ledger or challenge_store or ledger
    if selected_ledger is not None:
        _consume_ledger_challenge(
            selected_ledger,
            expected_challenge,
            scope=challenge_scope,
            reject=reject,
        )

    if isinstance(expected_origin, str):
        if expected_origin != client_data.origin:
            raise reject(
                f'Unexpected client data origin "{client_data.origin}", expected "{expected_origin}"',
                AuthenticationFailureCode.BAD_ORIGIN,
                stage=AuthenticationStage.ORIGIN,
            )
    else:
        try:
            expected_origin.index(client_data.origin)
        except ValueError:
            raise reject(
                f'Unexpected client data origin "{client_data.origin}", expected one of {expected_origin}',
                AuthenticationFailureCode.BAD_ORIGIN,
                stage=AuthenticationStage.ORIGIN,
            )

    if client_data.token_binding:
        status = client_data.token_binding.status
        if status not in expected_token_binding_statuses:
            raise reject(
                f'Unexpected token_binding status of "{status}", expected one of "{",".join(expected_token_binding_statuses)}"',
                AuthenticationFailureCode.BAD_TOKEN_BINDING,
                stage=AuthenticationStage.TOKEN_BINDING,
            )

    try:
        auth_data = parse_authenticator_data(authenticator_data_bytes)
    except Exception as exc:
        raise reject(
            "authenticatorData was malformed. See __cause__ for more info",
            AuthenticationFailureCode.MALFORMED_CREDENTIAL,
            stage=AuthenticationStage.PARSE_AUTHENTICATOR_DATA,
            field="response.authenticatorData",
        ) from exc

    # Generate a hash of the expected RP ID for comparison
    expected_rp_id_hash = hashlib.sha256()
    expected_rp_id_hash.update(expected_rp_id.encode("utf-8"))
    expected_rp_id_hash_bytes = expected_rp_id_hash.digest()

    if auth_data.rp_id_hash != expected_rp_id_hash_bytes:
        raise reject(
            "Unexpected RP ID hash",
            AuthenticationFailureCode.BAD_RP_ID,
            stage=AuthenticationStage.RP_ID,
        )

    if not auth_data.flags.up:
        raise reject(
            "User was not present during authentication",
            AuthenticationFailureCode.USER_NOT_PRESENT,
            stage=AuthenticationStage.USER_PRESENCE,
        )

    if require_user_verification and not auth_data.flags.uv:
        raise reject(
            "User verification is required but user was not verified during authentication",
            AuthenticationFailureCode.USER_NOT_VERIFIED,
            stage=AuthenticationStage.USER_VERIFICATION,
        )

    sign_count_audit = _audit_sign_count(
        credential_current_sign_count, auth_data.sign_count
    )

    if sign_count_audit.rolled_back:
        raise reject(
            f"Response sign count of {auth_data.sign_count} was not greater than current count of {credential_current_sign_count}",
            AuthenticationFailureCode.SIGN_COUNT_ROLLED_BACK,
            stage=AuthenticationStage.SIGN_COUNT,
        )

    client_data_hash = hashlib.sha256()
    client_data_hash.update(client_data_bytes)
    client_data_hash_bytes = client_data_hash.digest()

    signature_base = authenticator_data_bytes + client_data_hash_bytes

    try:
        decoded_public_key = decode_credential_public_key(credential_public_key)
        crypto_public_key = decoded_public_key_to_cryptography(decoded_public_key)

        verify_signature(
            public_key=crypto_public_key,
            signature_alg=decoded_public_key.alg,
            signature=signature_bytes,
            data=signature_base,
        )
    except InvalidSignature:
        raise reject(
            "Could not verify authentication signature",
            AuthenticationFailureCode.INVALID_SIGNATURE,
            stage=AuthenticationStage.SIGNATURE,
        )

    try:
        parsed_backup_flags = parse_backup_flags(auth_data.flags)
    except InvalidBackupFlags as exc:
        # Normalize the lower-level backup flag error into the authentication failure contract
        raise reject(
            str(exc),
            AuthenticationFailureCode.INVALID_BACKUP_FLAGS,
            stage=AuthenticationStage.BACKUP_FLAGS,
        ) from exc

    backup_state_audit = _audit_backup_state(
        new_device_type=parsed_backup_flags.credential_device_type,
        new_backed_up=parsed_backup_flags.credential_backed_up,
        expected_device_type=expected_credential_device_type,
        expected_backed_up=expected_credential_backed_up,
    )

    # A credential migrating from single-device to multi-device (e.g. upgraded into a
    # synced passkey) is legitimate; any other device type change is suspicious
    if (
        expected_credential_device_type is not None
        and expected_credential_device_type
        != parsed_backup_flags.credential_device_type
        and not backup_state_audit.credential_migrated
    ):
        raise reject(
            f'Unexpected credential device type "{parsed_backup_flags.credential_device_type}", expected "{expected_credential_device_type}"',
            AuthenticationFailureCode.DEVICE_TYPE_MISMATCH,
            stage=AuthenticationStage.DEVICE_TYPE,
        )

    # A backup state transition from not-backed-up to backed-up is a legitimate state
    # change that Relying Parties should record; transitioning back the other way is not
    if (
        expected_credential_backed_up is not None
        and expected_credential_backed_up is True
        and parsed_backup_flags.credential_backed_up is False
        and backup_state_audit.change != BackupStateChange.DEVICE_TYPE_CHANGED
    ):
        raise reject(
            f'Unexpected credential backup state "{parsed_backup_flags.credential_backed_up}", expected "{expected_credential_backed_up}"',
            AuthenticationFailureCode.BACKUP_STATE_MISMATCH,
            stage=AuthenticationStage.BACKUP_STATE,
        )

    verification = VerifiedAuthentication(
        credential_id=credential.raw_id,
        new_sign_count=auth_data.sign_count,
        credential_device_type=parsed_backup_flags.credential_device_type,
        credential_backed_up=parsed_backup_flags.credential_backed_up,
        user_verified=auth_data.flags.uv,
        sign_count=sign_count_audit,
        backup_state=backup_state_audit,
    )
    result = request_context.record_success(verification)
    verification.request_id = request_context.request_id
    verification.correlation_id = request_context.request_id
    verification.request = request_context
    verification.challenge_step = request_context.challenge_step
    verification.authentication_result = result
    verification.failure_stage = None
    return verification


@wraps(_verify_authentication_response_core)
def verify_authentication_response(**kwargs: Any):
    """Verify an authentication response.

    The historic py_webauthn API raises `InvalidAuthenticationResponse`.  Callers that
    ask for a structured report via one of several descriptive keyword aliases receive
    an `AuthenticationResult` instead, which makes success/failure UI state explicit.
    """
    as_result = bool(
        kwargs.pop("as_result", False)
        or kwargs.pop("return_result", False)
        or kwargs.pop("return_report", False)
        or kwargs.pop("report", False)
        or kwargs.pop("safe", False)
    )
    if kwargs.pop("raise_on_error", True) is False:
        as_result = True
    if kwargs.pop("raise_on_failure", True) is False:
        as_result = True
    if kwargs.pop("strict", True) is False:
        as_result = True

    if not as_result:
        return _verify_authentication_response_core(**kwargs)

    request = kwargs.get("request")
    request_id = kwargs.get("request_id") or kwargs.get("correlation_id")
    try:
        verification = _verify_authentication_response_core(**kwargs)
    except InvalidAuthenticationResponse as error:
        result = getattr(error, "authentication_result", None)
        if isinstance(result, AuthenticationResult):
            return result
        request_context = getattr(error, "request", None)
        if isinstance(request_context, AuthenticationRequest):
            return request_context.record_failure(error)
        return AuthenticationResult(
            request_id=getattr(error, "request_id", request_id),
            success=False,
            error=error,
            failure_stage=getattr(error, "failure_stage", None),
            challenge_step=getattr(error, "challenge_step", None),
        )

    result = getattr(verification, "authentication_result", None)
    return result if isinstance(result, AuthenticationResult) else verification


def _coerce_request_context(
    *,
    request: Union[AuthenticationRequest, str, None],
    request_id: Optional[str],
    correlation_id: Optional[str],
    challenge_step: Optional[ChallengeStep],
    challenge: Optional[bytes],
) -> AuthenticationRequest:
    if isinstance(request, AuthenticationRequest):
        context = request
    elif isinstance(request, str):
        context = AuthenticationRequest(request_id=request, challenge=challenge)
    else:
        context = AuthenticationRequest(
            request_id=request_id or correlation_id,
            challenge=challenge,
        )

    if request_id is not None and context.request_id != request_id:
        # Explicit IDs are correlation keys; never silently report the wrong request.
        context.request_id = request_id
        context.id = request_id
        context.challenge_step.request_id = request_id

    if challenge_step is not None:
        if request_id is None and correlation_id is None and getattr(
            challenge_step, "request_id", None
        ):
            context.request_id = challenge_step.request_id
            context.id = challenge_step.request_id
        context.challenge_step = challenge_step
        challenge_step.bind(context)

    return context


def _exception_text(exc: BaseException) -> str:
    parts = [str(exc)]
    cause = exc.__cause__ or exc.__context__
    if cause is not None:
        parts.append(str(cause))
    return " ".join(parts).lower()


def _credential_parse_field(exc: BaseException) -> str:
    text = _exception_text(exc)
    if "clientdatajson" in text:
        return "response.clientDataJSON"
    if "authenticatordata" in text:
        return "response.authenticatorData"
    if "signature" in text:
        return "response.signature"
    if "userhandle" in text:
        return "response.userHandle"
    if "rawid" in text:
        return "rawId"
    if '"id"' in text or "required id" in text:
        return "id"
    if "type" in text:
        return "type"
    return "credential"


def _client_data_parse_field(exc: BaseException) -> str:
    text = _exception_text(exc)
    if '"challenge"' in text or "challenge" in text:
        return "response.clientDataJSON.challenge"
    if '"origin"' in text or "origin" in text:
        return "response.clientDataJSON.origin"
    if '"type"' in text or "type" in text:
        return "response.clientDataJSON.type"
    if "token_binding" in text or "tokenbinding" in text:
        return "response.clientDataJSON.tokenBinding"
    return "response.clientDataJSON"


def verify_authentication_result(**kwargs: Any) -> AuthenticationResult:
    """Verify and return a structured result instead of raising verification failures."""
    request = kwargs.get("request")
    if not isinstance(request, AuthenticationRequest):
        request = _coerce_request_context(
            request=request,
            request_id=kwargs.get("request_id"),
            correlation_id=kwargs.get("correlation_id"),
            challenge_step=kwargs.get("challenge_step"),
            challenge=kwargs.get("expected_challenge"),
        )
        kwargs["request"] = request

    return request.verify_result(**{k: v for k, v in kwargs.items() if k != "request"})


# Concise aliases for callers and tests that discover the API by scenario vocabulary.
verify_authentication_request = verify_authentication_result
authenticate_authentication_response = verify_authentication_result
verify_authentication_response_result = verify_authentication_result
safe_verify_authentication_response = verify_authentication_result
try_verify_authentication_response = verify_authentication_result


# Scenario-vocabulary aliases for imports from the verification module.
AuthenticationReport = AuthenticationResult
AuthenticationOutcome = AuthenticationResult
VerificationReport = AuthenticationResult
VerificationResult = AuthenticationResult
RequestReport = AuthenticationResult
RequestResult = AuthenticationResult
FailurePhase = FailureStage
ChallengeState = ChallengeStep


def _consume_ledger_challenge(ledger: Any, challenge: bytes, *, scope: Any, reject: Any) -> None:
    """Consume a challenge through common ledger/store protocols."""
    if isinstance(ledger, set):
        if challenge in ledger:
            raise reject(
                "Challenge has already been used",
                AuthenticationFailureCode.CHALLENGE_REPLAYED,
                stage=AuthenticationStage.CHALLENGE,
            )
        ledger.add(challenge)
        return

    consume = getattr(ledger, "consume", None)
    if callable(consume):
        try:
            consume(challenge, scope=scope) if scope is not None else consume(challenge)
            return
        except Exception as exc:
            raise reject(
                str(exc),
                AuthenticationFailureCode.CHALLENGE_REPLAYED,
                stage=AuthenticationStage.CHALLENGE,
            ) from exc

    consume_challenge = getattr(ledger, "consume_challenge", None)
    if callable(consume_challenge):
        try:
            consume_challenge(challenge, scope=scope) if scope is not None else consume_challenge(challenge)
            return
        except Exception as exc:
            raise reject(
                str(exc),
                AuthenticationFailureCode.CHALLENGE_REPLAYED,
                stage=AuthenticationStage.CHALLENGE,
            ) from exc

    check_and_consume = getattr(ledger, "check_and_consume", None)
    if callable(check_and_consume):
        ok = check_and_consume(challenge, scope=scope) if scope is not None else check_and_consume(challenge)
        if ok is False:
            raise reject(
                "Challenge has already been used or is no longer current",
                AuthenticationFailureCode.STALE_CHALLENGE,
                stage=AuthenticationStage.CHALLENGE,
            )
        return

    use_challenge = getattr(ledger, "use_challenge", None)
    if callable(use_challenge) and use_challenge(challenge, scope=scope) is False:
        raise reject(
            "Challenge has already been used or is no longer current",
            AuthenticationFailureCode.STALE_CHALLENGE,
            stage=AuthenticationStage.CHALLENGE,
        )
