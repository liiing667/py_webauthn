from dataclasses import dataclass
import hashlib
from typing import Any, Dict, List, Union

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
    BackupStateAudit,
    BackupStateChange,
    ClientDataType,
    CredentialDeviceType,
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
    sign_count: SignCountAudit
    backup_state: BackupStateAudit


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


def verify_authentication_response(
    *,
    credential: Union[str, Dict[str, Any], AuthenticationCredential],
    expected_challenge: bytes,
    expected_rp_id: str,
    expected_origin: Union[str, List[str]],
    credential_public_key: bytes,
    credential_current_sign_count: int,
    expected_credential_device_type: Union[CredentialDeviceType, None] = None,
    expected_credential_backed_up: Union[bool, None] = None,
    require_user_verification: bool = False,
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
    if isinstance(credential, str) or isinstance(credential, dict):
        try:
            credential = parse_authentication_credential_json(credential)
        except WebAuthnException as exc:
            raise _invalid(
                str(exc),
                AuthenticationFailureCode.MALFORMED_CREDENTIAL,
            ) from exc

    # FIDO-specific check
    if bytes_to_base64url(credential.raw_id) != credential.id:
        raise _invalid(
            "id and raw_id were not equivalent",
            AuthenticationFailureCode.BAD_CREDENTIAL_ID,
        )

    # FIDO-specific check
    if credential.type != PublicKeyCredentialType.PUBLIC_KEY:
        raise _invalid(
            f'Unexpected credential type "{credential.type}", expected "public-key"',
            AuthenticationFailureCode.BAD_CREDENTIAL_TYPE,
        )

    response = credential.response

    client_data_bytes = byteslike_to_bytes(response.client_data_json)
    authenticator_data_bytes = byteslike_to_bytes(response.authenticator_data)
    signature_bytes = byteslike_to_bytes(response.signature)

    try:
        client_data = parse_client_data_json(client_data_bytes)
    except Exception as exc:
        raise _invalid(
            "clientDataJSON was malformed. See __cause__ for more info",
            AuthenticationFailureCode.MALFORMED_CREDENTIAL,
        ) from exc

    if client_data.type != ClientDataType.WEBAUTHN_GET:
        raise _invalid(
            f'Unexpected client data type "{client_data.type}", expected "{ClientDataType.WEBAUTHN_GET}"',
            AuthenticationFailureCode.BAD_CLIENT_DATA_TYPE,
        )

    if expected_challenge != client_data.challenge:
        raise _invalid(
            "Client data challenge was not expected challenge",
            AuthenticationFailureCode.BAD_CHALLENGE,
        )

    if isinstance(expected_origin, str):
        if expected_origin != client_data.origin:
            raise _invalid(
                f'Unexpected client data origin "{client_data.origin}", expected "{expected_origin}"',
                AuthenticationFailureCode.BAD_ORIGIN,
            )
    else:
        try:
            expected_origin.index(client_data.origin)
        except ValueError:
            raise _invalid(
                f'Unexpected client data origin "{client_data.origin}", expected one of {expected_origin}',
                AuthenticationFailureCode.BAD_ORIGIN,
            )

    if client_data.token_binding:
        status = client_data.token_binding.status
        if status not in expected_token_binding_statuses:
            raise _invalid(
                f'Unexpected token_binding status of "{status}", expected one of "{",".join(expected_token_binding_statuses)}"',
                AuthenticationFailureCode.BAD_TOKEN_BINDING,
            )

    try:
        auth_data = parse_authenticator_data(authenticator_data_bytes)
    except Exception as exc:
        raise _invalid(
            "authenticatorData was malformed. See __cause__ for more info",
            AuthenticationFailureCode.MALFORMED_CREDENTIAL,
        ) from exc

    # Generate a hash of the expected RP ID for comparison
    expected_rp_id_hash = hashlib.sha256()
    expected_rp_id_hash.update(expected_rp_id.encode("utf-8"))
    expected_rp_id_hash_bytes = expected_rp_id_hash.digest()

    if auth_data.rp_id_hash != expected_rp_id_hash_bytes:
        raise _invalid("Unexpected RP ID hash", AuthenticationFailureCode.BAD_RP_ID)

    if not auth_data.flags.up:
        raise _invalid(
            "User was not present during authentication",
            AuthenticationFailureCode.USER_NOT_PRESENT,
        )

    if require_user_verification and not auth_data.flags.uv:
        raise _invalid(
            "User verification is required but user was not verified during authentication",
            AuthenticationFailureCode.USER_NOT_VERIFIED,
        )

    sign_count_audit = _audit_sign_count(
        credential_current_sign_count, auth_data.sign_count
    )

    if sign_count_audit.rolled_back:
        raise _invalid(
            f"Response sign count of {auth_data.sign_count} was not greater than current count of {credential_current_sign_count}",
            AuthenticationFailureCode.SIGN_COUNT_ROLLED_BACK,
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
        raise _invalid(
            "Could not verify authentication signature",
            AuthenticationFailureCode.INVALID_SIGNATURE,
        )

    try:
        parsed_backup_flags = parse_backup_flags(auth_data.flags)
    except InvalidBackupFlags as exc:
        # Normalize the lower-level backup flag error into the authentication failure contract
        raise _invalid(
            str(exc), AuthenticationFailureCode.INVALID_BACKUP_FLAGS
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
        raise _invalid(
            f'Unexpected credential device type "{parsed_backup_flags.credential_device_type}", expected "{expected_credential_device_type}"',
            AuthenticationFailureCode.DEVICE_TYPE_MISMATCH,
        )

    # A backup state transition from not-backed-up to backed-up is a legitimate state
    # change that Relying Parties should record; transitioning back the other way is not
    if (
        expected_credential_backed_up is not None
        and expected_credential_backed_up is True
        and parsed_backup_flags.credential_backed_up is False
        and backup_state_audit.change != BackupStateChange.DEVICE_TYPE_CHANGED
    ):
        raise _invalid(
            f'Unexpected credential backup state "{parsed_backup_flags.credential_backed_up}", expected "{expected_credential_backed_up}"',
            AuthenticationFailureCode.BACKUP_STATE_MISMATCH,
        )

    return VerifiedAuthentication(
        credential_id=credential.raw_id,
        new_sign_count=auth_data.sign_count,
        credential_device_type=parsed_backup_flags.credential_device_type,
        credential_backed_up=parsed_backup_flags.credential_backed_up,
        user_verified=auth_data.flags.uv,
        sign_count=sign_count_audit,
        backup_state=backup_state_audit,
    )
