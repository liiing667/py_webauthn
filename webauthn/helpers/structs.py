from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Union

from .cose import COSEAlgorithmIdentifier


################
#
# Fundamental data structures
#
################


class AuthenticatorTransport(str, Enum):
    """How an authenticator communicates to the client/browser.

    Members:
        `USB`: USB wired connection
        `NFC`: Near Field Communication
        `BLE`: Bluetooth Low Energy
        `INTERNAL`: Direct connection (read: a platform authenticator)
        `CABLE`: Cloud Assisted Bluetooth Low Energy
        `HYBRID`: A combination of (often separate) data-transport and proximity mechanisms

    https://www.w3.org/TR/webauthn-2/#enum-transport
    """

    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    SMART_CARD = "smart-card"
    INTERNAL = "internal"
    CABLE = "cable"
    HYBRID = "hybrid"


class AuthenticatorAttachment(str, Enum):
    """How an authenticator is connected to the client/browser.

    Members:
        `PLATFORM`: A non-removable authenticator, like TouchID or Windows Hello
        `CROSS_PLATFORM`: A "roaming" authenticator, like a YubiKey

    https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
    """

    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


class ResidentKeyRequirement(str, Enum):
    """The Relying Party's preference for the authenticator to create a dedicated "client-side" credential for it. Requiring an authenticator to store a dedicated credential should not be done lightly due to the limited storage capacity of some types of authenticators.

    Members:
        `DISCOURAGED`: The authenticator should not create a dedicated credential
        `PREFERRED`: The authenticator can create and store a dedicated credential, but if it doesn't that's alright too
        `REQUIRED`: The authenticator MUST create a dedicated credential. If it cannot, the RP is prepared for an error to occur.

    https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement
    """

    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class UserVerificationRequirement(str, Enum):
    """The degree to which the Relying Party wishes to verify a user's identity.

    Members:
        `REQUIRED`: User verification must occur
        `PREFERRED`: User verification would be great, but if not that's okay too
        `DISCOURAGED`: User verification should not occur, but it's okay if it does

    https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement
    """

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AttestationConveyancePreference(str, Enum):
    """The Relying Party's interest in receiving an attestation statement.

    Members:
        `NONE`: The Relying Party isn't interested in receiving an attestation statement
        `INDIRECT`: The Relying Party is interested in an attestation statement, but the client is free to generate it as it sees fit
        `DIRECT`: The Relying Party is interested in an attestation statement generated directly by the authenticator
        `ENTERPRISE`: The Relying Party is interested in a statement with identifying information. Typically used within organizations

    https://www.w3.org/TR/webauthn-2/#enum-attestation-convey
    """

    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"
    ENTERPRISE = "enterprise"


class PublicKeyCredentialType(str, Enum):
    """The type of credential that should be returned by an authenticator. There's but a single member because this is a specific subclass of a higher-level `CredentialType` that can be of other types.

    Members:
        `PUBLIC_KEY`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype
    """

    PUBLIC_KEY = "public-key"


class AttestationFormat(str, Enum):
    """The "syntax" of an attestation statement. Formats should be registered with the IANA and include documented signature verification steps.

    Members:
        `PACKED`
        `TPM`
        `ANDROID_KEY`
        `ANDROID_SAFETYNET`
        `FIDO_U2F`
        `APPLE`
        `NONE`

    https://www.iana.org/assignments/webauthn/webauthn.xhtml
    """

    PACKED = "packed"
    TPM = "tpm"
    ANDROID_KEY = "android-key"
    ANDROID_SAFETYNET = "android-safetynet"
    FIDO_U2F = "fido-u2f"
    APPLE = "apple"
    NONE = "none"


class ClientDataType(str, Enum):
    """Specific values included in authenticator registration and authentication responses to help avoid certain types of "signature confusion attacks".

    Members:
        `WEBAUTHN_CREATE`: The string "webauthn.create". Synonymous with `navigator.credentials.create()` in the browser
        `WEBAUTHN_GET`: The string "webauthn.get". Synonymous with `navigator.credentials.get()` in the browser

    https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
    """

    WEBAUTHN_CREATE = "webauthn.create"
    WEBAUTHN_GET = "webauthn.get"


class TokenBindingStatus(str, Enum):
    """
    https://www.w3.org/TR/webauthn-2/#dom-tokenbinding-status
    """

    PRESENT = "present"
    SUPPORTED = "supported"


class PublicKeyCredentialHint(str, Enum):
    """Categories of authenticators that Relying Parties can pass along to browsers during
    registration. Browsers that understand these values can optimize their modal experience to
    start the user off in a particular registration flow. These values are less strict than
    `authenticatorAttachment` (see `webauthn.helpers.strucAuthenticatorAttachment`)

    Members:
        `SECURITY_KEY`: A portable FIDO2 authenticator capable of being used on multiple devices via a USB or NFC connection
        `CLIENT_DEVICE`: The device that WebAuthn is being called on. Typically synonymous with platform authenticators
        `HYBRID`: A platform authenticator on a mobile device

    https://w3c.github.io/webauthn/#enumdef-publickeycredentialhint
    """

    SECURITY_KEY = "security-key"
    CLIENT_DEVICE = "client-device"
    HYBRID = "hybrid"


@dataclass
class TokenBinding:
    """
    https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding
    """

    status: TokenBindingStatus
    id: Optional[str] = None


@dataclass
class PublicKeyCredentialRpEntity:
    """Information about the Relying Party.

    Attributes:
        `name`: A user-readable name for the Relying Party
        (optional) `id`: A unique, constant value assigned to the Relying Party. Authenticators use this value to associate a credential with a particular Relying Party user

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity
    """

    name: str
    id: Optional[str] = None


@dataclass
class PublicKeyCredentialUserEntity:
    """Information about a user of a Relying Party.

    Attributes:
        `id`: An "opaque byte sequence" that uniquely identifies a user. Typically something like a UUID, but never user-identifying like an email address. Cannot exceed 64 bytes. These bytes should be stored internally alongside your normal user identifier and only used for WebAuthn.
        `name`: A value which a user can see to determine which account this credential is associated with. A username or email address is fine here.
        `display_name`: A user-friendly representation of a user, like a full name.

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity
    """

    id: bytes
    name: str
    display_name: str


@dataclass
class PublicKeyCredentialParameters:
    """Information about a cryptographic algorithm that may be used when creating a credential.

    Attributes:
        `type`: The literal string `"public-key"`
        `alg`: A numeric indicator of a particular algorithm

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters
    """

    type: Literal["public-key"]
    alg: COSEAlgorithmIdentifier


@dataclass
class PublicKeyCredentialDescriptor:
    """Information about a generated credential.

    Attributes:
        `type`: The literal string `"public-key"`
        `id`: The sequence of bytes representing the credential's ID
        (optional) `transports`: The types of connections to the client/browser the authenticator supports

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
    """

    id: bytes
    type: Literal[PublicKeyCredentialType.PUBLIC_KEY] = PublicKeyCredentialType.PUBLIC_KEY
    transports: Optional[List[AuthenticatorTransport]] = None


@dataclass
class AuthenticatorSelectionCriteria:
    """A Relying Party's requirements for the types of authenticators that may interact with the client/browser.

    Attributes:
        (optional) `authenticator_attachment`: How the authenticator can be connected to the client/browser
        (optional) `resident_key`: Whether the authenticator should be able to store a credential on itself
        (optional) `require_resident_key`: DEPRECATED, set a value for `resident_key` instead
        (optional) `user_verification`: How the authenticator should be capable of determining user identity

    https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
    """

    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    resident_key: Optional[ResidentKeyRequirement] = None
    require_resident_key: Optional[bool] = False
    user_verification: Optional[UserVerificationRequirement] = (
        UserVerificationRequirement.PREFERRED
    )


@dataclass
class CollectedClientData:
    """Decoded ClientDataJSON

    Attributes:
        `type`: Either `"webauthn.create"` or `"webauthn.get"`, for registration and authentication ceremonies respectively
        `challenge`: The challenge passed to the authenticator within the options
        `origin`: The base domain with protocol on which the registration or authentication ceremony took place (e.g. "https://foo.bar")
        (optional) `cross_origin`: Whether or not the registration or authentication ceremony took place on a different origin (think within an <iframe>)
        (optional) `token_binding`: Information on the state of the Token Binding protocol

    https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata
    """

    type: ClientDataType
    challenge: bytes
    origin: str
    cross_origin: Optional[bool] = None
    token_binding: Optional[TokenBinding] = None


################
#
# Registration
#
################


@dataclass
class PublicKeyCredentialCreationOptions:
    """Registration Options.

    Attributes:
        `rp`: Information about the Relying Party
        `user`: Information about the user
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent replay attacks
        `pub_key_cred_params`: Cryptographic algorithms supported by the Relying Party when verifying signatures
        (optional) `timeout`: How long the client/browser should give the user to interact with an authenticator
        (optional) `exclude_credentials`: A list of credentials associated with the user to prevent them from re-enrolling one of them
        (optional) `authenticator_selection`: Additional qualities about the authenticators the user can use to complete registration
        (optional) `hints`: Suggestions to the browser about the type of authenticator the user should try and register. Multiple values should be ordered by decreasing preference
        (optional) `attestation`: The Relying Party's desire for a declaration of an authenticator's provenance via attestation statement

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
    """

    rp: PublicKeyCredentialRpEntity
    user: PublicKeyCredentialUserEntity
    challenge: bytes
    pub_key_cred_params: List[PublicKeyCredentialParameters]
    timeout: Optional[int] = None
    exclude_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None
    hints: Optional[List[PublicKeyCredentialHint]] = None
    attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE


@dataclass
class AuthenticatorAttestationResponse:
    """The `response` property on a registration credential.

    Attributes:
        `client_data_json`: Information the authenticator collects about the client/browser it communicates with
        `attestation_object`: Encoded information about an attestation
        (optional) `transports`: The authenticator's supported methods of communication with a client/browser

    https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse
    """

    client_data_json: bytes
    attestation_object: bytes
    # Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
    transports: Optional[List[AuthenticatorTransport]] = None


@dataclass
class RegistrationCredential:
    """A registration-specific subclass of PublicKeyCredential returned from `navigator.credentials.create()`

    Attributes:
        `id`: The Base64URL-encoded representation of raw_id
        `raw_id`: A byte sequence representing the credential's unique identifier
        `response`: The authenticator's attestation data
        `type`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#publickeycredential
    """

    id: str
    raw_id: bytes
    response: AuthenticatorAttestationResponse
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    type: Literal[PublicKeyCredentialType.PUBLIC_KEY] = PublicKeyCredentialType.PUBLIC_KEY


@dataclass
class AttestationStatement:
    """A collection of all possible fields that may exist in an attestation statement. Combinations of these fields are specific to a particular attestation format.

    https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats

    TODO: Decide if this is acceptable, or if we want to split this up into multiple
    format-specific classes that define only the fields that are present for a given
    attestation format.
    """

    sig: Optional[bytes] = None
    x5c: Optional[List[bytes]] = None
    response: Optional[bytes] = None
    alg: Optional[COSEAlgorithmIdentifier] = None
    ver: Optional[str] = None
    cert_info: Optional[bytes] = None
    pub_area: Optional[bytes] = None


@dataclass
class AuthenticatorDataFlags:
    """Flags the authenticator will set about information contained within the `attestationObject.authData` property.

    Attributes:
        `up`: [U]ser was [P]resent
        `uv`: [U]ser was [V]erified
        `be`: [B]ackup [E]ligible
        `bs`: [B]ackup [S]tate
        `at`: [AT]tested credential is included
        `ed`: [E]xtension [D]ata is included

    https://www.w3.org/TR/webauthn-2/#flags
    """

    up: bool
    uv: bool
    be: bool
    bs: bool
    at: bool
    ed: bool


@dataclass
class AttestedCredentialData:
    """Information about a credential.

    Attributes:
        `aaguid`: A 128-bit identifier indicating the type and vendor of the authenticator
        `credential_id`: The ID of the private/public key pair generated by the authenticator
        `credential_public_key`: The public key generated by the authenticator

    https://www.w3.org/TR/webauthn-2/#attested-credential-data
    """

    aaguid: bytes
    credential_id: bytes
    credential_public_key: bytes


@dataclass
class AuthenticatorData:
    """Context the authenticator provides about itself and the environment in which the registration or authentication ceremony took place.

    Attributes:
        `rp_id_hash`: A SHA-256 hash of the website origin on which the registration or authentication ceremony took place
        `flags`: Properties about the user and registration, where applicable
        `sign_count`: The number of times the credential was used
        (optional) `attested_credential_data`: Information about the credential created during a registration ceremony
        (optional) `extensions`: CBOR-encoded extension data corresponding to extensions specified in the registration or authentication ceremony options

    https://www.w3.org/TR/webauthn-2/#sctn-attestation
    https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
    """

    rp_id_hash: bytes
    flags: AuthenticatorDataFlags
    sign_count: int
    attested_credential_data: Optional[AttestedCredentialData] = None
    extensions: Optional[bytes] = None


@dataclass
class AttestationObject:
    """Information about an attestation, including a statement and authenticator data.

    Attributes:
        `fmt`: The attestation statement's format
        `att_stmt`: An attestation statement to be verified according to the format
        `auth_data`: Contextual information provided by authenticator

    https://www.w3.org/TR/webauthn-2/#sctn-attestation
    """

    fmt: AttestationFormat
    auth_data: AuthenticatorData
    att_stmt: AttestationStatement = field(default_factory=AttestationStatement)


################
#
# Authentication
#
################


@dataclass
class PublicKeyCredentialRequestOptions:
    """Authentication Options.

    Attributes:
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent replay attacks
        (optional) `timeout`: How long the client/browser should give the user to interact with an authenticator
        (optional) `rp_id`: The unique, constant identifier assigned to the Relying Party
        (optional) `allow_credentials`: A list of credentials associated with the user that they can use to complete the authentication
        (optional) `user_verification`: How the authenticator should be capable of determining user identity

    https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    """

    challenge: bytes
    timeout: Optional[int] = None
    rp_id: Optional[str] = None
    allow_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    user_verification: Optional[UserVerificationRequirement] = (
        UserVerificationRequirement.PREFERRED
    )


@dataclass
class AuthenticatorAssertionResponse:
    """The `response` property on an authentication credential.

    Attributes:
        `client_data_json`: Information the authenticator collects about the client/browser it communicates with
        `authenticator_data`: Contextual information provided by authenticator
        `signature`: A byte sequence signed by the authenticator's private key, to be verified with a user's public key
        (optional) `user_handle`: The user ID specified for the user during attestation

    https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse
    """

    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: Optional[bytes] = None


@dataclass
class AuthenticationCredential:
    """An authentication-specific subclass of PublicKeyCredential. Returned from `navigator.credentials.get()`

    Attributes:
        `id`: The Base64URL-encoded representation of raw_id
        `raw_id`: A byte sequence representing the credential's unique identifier
        `response`: The authenticator's assertion data
        `type`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#publickeycredential
    """

    id: str
    raw_id: bytes
    response: AuthenticatorAssertionResponse
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    type: Literal[PublicKeyCredentialType.PUBLIC_KEY] = PublicKeyCredentialType.PUBLIC_KEY


################
#
# Credential Backup State
#
################


class CredentialDeviceType(str, Enum):
    """A determination of the number of devices a credential can be used from

    Members:
        `SINGLE_DEVICE`: A credential that is bound to a single device
        `MULTI_DEVICE`: A credential that can be used from multiple devices (e.g. passkeys)

    https://w3c.github.io/webauthn/#sctn-credential-backup (L3 Draft)
    """

    SINGLE_DEVICE = "single_device"
    MULTI_DEVICE = "multi_device"


class AuthenticationFailureCode(str, Enum):
    """Stable, machine-readable classification of why authentication failed

    Members are intended to be relied upon by Relying Parties (e.g. in audit
    logs or branching logic) instead of matching against error message strings.

    Members:
        `MALFORMED_CREDENTIAL`: The credential or one of its responses could not be parsed
        `BAD_CREDENTIAL_ID`: The credential's `id` and `raw_id` were not equivalent
        `BAD_CREDENTIAL_TYPE`: The credential's `type` was not `"public-key"`
        `BAD_CLIENT_DATA_TYPE`: `clientDataJSON` did not describe a `webauthn.get` ceremony
        `BAD_CHALLENGE`: The challenge in `clientDataJSON` did not match the expected challenge
        `BAD_ORIGIN`: The origin in `clientDataJSON` was not among the expected origins
        `BAD_TOKEN_BINDING`: The token binding status in `clientDataJSON` was not supported
        `BAD_RP_ID`: The RP ID hash in `authenticatorData` did not match the expected RP ID
        `USER_NOT_PRESENT`: The authenticator did not set the user present flag
        `USER_NOT_VERIFIED`: User verification was required but the authenticator did not set it
        `SIGN_COUNT_ROLLED_BACK`: The signature counter did not advance over the stored counter
        `INVALID_SIGNATURE`: The assertion signature could not be verified
        `INVALID_BACKUP_FLAGS`: The backup eligibility and backup state flags were contradictory
        `DEVICE_TYPE_MISMATCH`: The credential's device type did not match the stored record
        `BACKUP_STATE_MISMATCH`: The credential's backup state did not match the stored record
    """

    MALFORMED_CREDENTIAL = "malformed_credential"
    BAD_CREDENTIAL_ID = "bad_credential_id"
    BAD_CREDENTIAL_TYPE = "bad_credential_type"
    BAD_CLIENT_DATA_TYPE = "bad_client_data_type"
    BAD_CHALLENGE = "bad_challenge"
    CHALLENGE_REPLAYED = "challenge_replayed"
    STALE_CHALLENGE = "stale_challenge"
    CHALLENGE_STEP_MISMATCH = "challenge_step_mismatch"
    REQUEST_MISMATCH = "request_mismatch"
    BAD_ORIGIN = "bad_origin"
    BAD_TOKEN_BINDING = "bad_token_binding"
    BAD_RP_ID = "bad_rp_id"
    USER_NOT_PRESENT = "user_not_present"
    USER_NOT_VERIFIED = "user_not_verified"
    SIGN_COUNT_ROLLED_BACK = "sign_count_rolled_back"
    INVALID_SIGNATURE = "invalid_signature"
    INVALID_BACKUP_FLAGS = "invalid_backup_flags"
    DEVICE_TYPE_MISMATCH = "device_type_mismatch"
    BACKUP_STATE_MISMATCH = "backup_state_mismatch"


class SignCountStatus(str, Enum):
    """Auditable interpretation of a credential's signature counter after authentication

    Members:
        `INCREMENTED`: The new counter value is greater than the stored value, the
          expected behavior for authenticators that maintain signature counters
        `NOT_SUPPORTED`: Both the stored and reported counter values are zero, which is
          typical of synced passkeys and other authenticators that do not maintain counters
        `ROLLED_BACK`: The reported counter value did not advance over the stored value;
          authentication is rejected because this can indicate a cloned credential or replay
    """

    INCREMENTED = "incremented"
    NOT_SUPPORTED = "not_supported"
    ROLLED_BACK = "rolled_back"


class RegistrationFailureCode(str, Enum):
    """Stable, machine-readable classification of why registration failed

    Members:
        `MALFORMED_CREDENTIAL`: The registration response could not be parsed or verified
          for a reason without a more specific classification
        `INVALID_BACKUP_FLAGS`: The backup eligibility and backup state flags were contradictory
    """

    MALFORMED_CREDENTIAL = "malformed_credential"
    INVALID_BACKUP_FLAGS = "invalid_backup_flags"


class BackupStateChange(str, Enum):
    """Auditable comparison of backup-related flags against the stored credential record

    Members:
        `UNCHANGED`: Both device type and backup state match the stored record
        `BACKUP_STATE_CHANGED`: The backup state (BS flag) changed while the device type
          (BE flag) stayed the same. A transition from not-backed-up to backed-up is a
          legitimate state change; the reverse is rejected as a backup state mismatch
        `DEVICE_TYPE_CHANGED`: The device type (BE flag) changed. A migration from
          single-device to multi-device is legitimate; the reverse is rejected as a
          device type mismatch
    """

    UNCHANGED = "unchanged"
    BACKUP_STATE_CHANGED = "backup_state_changed"
    DEVICE_TYPE_CHANGED = "device_type_changed"


@dataclass
class SignCountAudit:
    """Auditable details about the signature counter observed during authentication

    Attributes:
        `status`: Interpretation of the reported counter relative to the stored counter
        `previous_sign_count`: The counter value previously stored by the Relying Party
        `new_sign_count`: The counter value reported by the authenticator in this response
        `rolled_back`: Whether the counter failed to advance while a counter is in use
    """

    status: SignCountStatus
    previous_sign_count: int
    new_sign_count: int
    rolled_back: bool


@dataclass
class BackupStateAudit:
    """Auditable details about backup flag changes observed during authentication

    Attributes:
        `change`: How the reported backup flags compare to the stored credential record
        `previous_device_type`: The device type stored for the credential, if one was provided
        `new_device_type`: The device type derived from the response's backup eligibility flag
        `previous_backed_up`: The backup state stored for the credential, if one was provided
        `new_backed_up`: The backup state derived from the response's backup state flag
        `credential_migrated`: Whether the credential migrated from single-device to multi-device
    """

    change: BackupStateChange
    previous_device_type: Optional[CredentialDeviceType]
    new_device_type: CredentialDeviceType
    previous_backed_up: Optional[bool]
    new_backed_up: bool
    credential_migrated: bool


################
#
# Request-scoped authentication diagnostics
#
################


class RequestStatus(str, Enum):
    """Lifecycle state shared by an authentication request and its reports."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    COMPLETED = "completed"


class AuthenticationResultStatus(str, Enum):
    """Machine-readable outcome of an authentication verification attempt."""

    SUCCESS = "success"
    FAILURE = "failure"
    FAILED = "failed"
    PENDING = "pending"


class ChallengeStepStatus(str, Enum):
    """State of the challenge step associated with one authentication request."""

    ISSUED = "issued"
    CURRENT = "current"
    PENDING = "pending"
    VERIFIED = "verified"
    CONSUMED = "consumed"
    COMPLETED = "completed"
    FAILED = "failed"
    STALE = "stale"
    REPLAYED = "replayed"
    EXPIRED = "expired"


class AuthenticationStage(str, Enum):
    """The verification stage at which an authentication result or failure occurred."""

    REQUEST = "request"
    PARSE_CREDENTIAL = "parse_credential"
    CREDENTIAL_PARSING = "credential_parsing"
    CREDENTIAL_ID = "credential_id"
    CREDENTIAL_TYPE = "credential_type"
    RESPONSE_PARSING = "response_parsing"
    PARSE_CLIENT_DATA = "parse_client_data"
    CLIENT_DATA_TYPE = "client_data_type"
    CHALLENGE = "challenge"
    CHALLENGE_STEP = "challenge_step"
    ORIGIN = "origin"
    TOKEN_BINDING = "token_binding"
    PARSE_AUTHENTICATOR_DATA = "parse_authenticator_data"
    AUTHENTICATOR_DATA = "authenticator_data"
    RP_ID = "rp_id"
    USER_PRESENCE = "user_presence"
    USER_PRESENT = "user_present"
    USER_VERIFICATION = "user_verification"
    USER_VERIFIED = "user_verified"
    SIGN_COUNT = "sign_count"
    SIGNATURE = "signature"
    BACKUP_FLAGS = "backup_flags"
    DEVICE_TYPE = "device_type"
    BACKUP_STATE = "backup_state"
    COMPLETE = "complete"


# Descriptive alias used by callers that think of this value as a failure phase/enum.
FailureStageName = AuthenticationStage
FailurePhaseName = AuthenticationStage


@dataclass(frozen=True)
class ResponseField:
    """A response field path with comparison aliases for common naming styles."""

    path: str
    aliases: tuple = ()

    @property
    def name(self) -> str:
        return self.path.split(".")[-1]

    @property
    def parts(self) -> tuple:
        return tuple(self.path.split("."))

    @property
    def loc(self) -> tuple:
        return self.parts

    def __str__(self) -> str:
        return self.path

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ResponseField):
            return self.path == other.path
        if not isinstance(other, str):
            return NotImplemented
        candidates = {self.path, self.name, *self.aliases}
        normalized = other.replace("_", "").replace("-", "").lower()
        for candidate in candidates:
            if candidate == other:
                return True
            if candidate.replace("_", "").replace("-", "").lower() == normalized:
                return True
        return False

    def __hash__(self) -> int:
        return hash(self.path)


class StepName(str):
    """String step name that also compares equal to common naming aliases."""

    def __new__(cls, value: str, aliases: tuple = ()) -> "StepName":
        obj = str.__new__(cls, value)
        obj.aliases = tuple(aliases)
        return obj

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, str):
            return NotImplemented
        if str(self) == other:
            return True
        normalized = other.replace("_", "").replace("-", "").lower()
        candidates = (str(self), *self.aliases)
        return any(
            candidate.replace("_", "").replace("-", "").lower() == normalized
            for candidate in candidates
        )

    def __hash__(self) -> int:
        return hash(str(self))


class CorrelationMapping:
    """Attribute objects that also support dictionary-style assertions."""

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class ChallengeStep(CorrelationMapping):
    """The challenge step bound to exactly one authentication request."""

    CHALLENGE = AuthenticationStage.CHALLENGE.value
    CHALLENGE_STEP = AuthenticationStage.CHALLENGE_STEP.value

    def __init__(
        self,
        request_id: Optional[str] = None,
        challenge: Optional[bytes] = None,
        *,
        id: Optional[str] = None,
        step: Union[str, AuthenticationStage, None] = None,
        name: Optional[str] = None,
        stage: Union[str, AuthenticationStage, None] = None,
        status: Union[ChallengeStepStatus, str] = ChallengeStepStatus.CURRENT,
        sequence: int = 1,
        challenge_id: Optional[str] = None,
        **metadata: Any,
    ) -> None:
        step_id = metadata.pop("step_id", None)
        if request_id is None:
            request_id = id
        elif step_id is None:
            step_id = id
        step_value = name or step or stage or self.CHALLENGE
        step_text = getattr(step_value, "value", step_value)
        if step_text == self.CHALLENGE:
            step_name = StepName(step_text, ("challenge_step", "challenge_verification"))
        else:
            step_name = StepName(step_text)
        self.request_id = request_id
        self.challenge = bytes(challenge) if challenge is not None else None
        self.step = step_name
        self.name = step_name
        self.stage = step_name
        self.sequence = sequence
        self.challenge_id = challenge_id or request_id
        self.step_id = step_id
        self.status = ChallengeStepStatus(status) if not isinstance(status, ChallengeStepStatus) else status
        self.metadata = metadata
        self.request: Optional["AuthenticationRequest"] = None

    @property
    def id(self) -> Optional[str]:
        return self.step_id or self.request_id

    @property
    def state(self) -> ChallengeStepStatus:
        return self.status

    def bind(self, request: "AuthenticationRequest") -> "ChallengeStep":
        self.request = request
        self.request_id = request.request_id
        if self.challenge_id is None:
            self.challenge_id = request.request_id
        if self.challenge is None and request.challenge is not None:
            self.challenge = request.challenge
        return self

    def mark(self, status: Union[ChallengeStepStatus, str]) -> "ChallengeStep":
        self.status = ChallengeStepStatus(status) if not isinstance(status, ChallengeStepStatus) else status
        return self

    def verified(self) -> "ChallengeStep":
        return self.mark(ChallengeStepStatus.VERIFIED)

    def consumed(self) -> "ChallengeStep":
        return self.mark(ChallengeStepStatus.CONSUMED)

    def failed(self) -> "ChallengeStep":
        return self.mark(ChallengeStepStatus.FAILED)

    def stale(self) -> "ChallengeStep":
        return self.mark(ChallengeStepStatus.STALE)

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "step": str(self.step),
            "name": str(self.name),
            "status": getattr(self.status, "value", self.status),
            "sequence": self.sequence,
            "challenge_id": self.challenge_id,
        }

    as_dict = to_dict

    def __repr__(self) -> str:
        return (
            f"ChallengeStep(request_id={self.request_id!r}, step={self.step!r}, "
            f"status={self.status.value!r})"
        )


class FailureStage(CorrelationMapping):
    """A failure location tagged with the request and response field it belongs to."""

    REQUEST = AuthenticationStage.REQUEST.value
    PARSE_CREDENTIAL = AuthenticationStage.PARSE_CREDENTIAL.value
    MALFORMED_CREDENTIAL = AuthenticationStage.PARSE_CREDENTIAL.value
    CREDENTIAL_ID = AuthenticationStage.CREDENTIAL_ID.value
    CREDENTIAL_TYPE = AuthenticationStage.CREDENTIAL_TYPE.value
    PARSE_CLIENT_DATA = AuthenticationStage.PARSE_CLIENT_DATA.value
    CLIENT_DATA_TYPE = AuthenticationStage.CLIENT_DATA_TYPE.value
    CHALLENGE = AuthenticationStage.CHALLENGE.value
    ORIGIN = AuthenticationStage.ORIGIN.value
    TOKEN_BINDING = AuthenticationStage.TOKEN_BINDING.value
    AUTHENTICATOR_DATA = AuthenticationStage.AUTHENTICATOR_DATA.value
    PARSE_AUTHENTICATOR_DATA = AuthenticationStage.PARSE_AUTHENTICATOR_DATA.value
    RP_ID = AuthenticationStage.RP_ID.value
    USER_PRESENCE = AuthenticationStage.USER_PRESENCE.value
    USER_NOT_PRESENT = AuthenticationStage.USER_PRESENCE.value
    USER_VERIFICATION = AuthenticationStage.USER_VERIFICATION.value
    USER_NOT_VERIFIED = AuthenticationStage.USER_VERIFICATION.value
    SIGN_COUNT = AuthenticationStage.SIGN_COUNT.value
    SIGNATURE = AuthenticationStage.SIGNATURE.value
    INVALID_SIGNATURE = AuthenticationStage.SIGNATURE.value
    BACKUP_FLAGS = AuthenticationStage.BACKUP_FLAGS.value
    DEVICE_TYPE = AuthenticationStage.DEVICE_TYPE.value
    BACKUP_STATE = AuthenticationStage.BACKUP_STATE.value
    USER_VERIFICATION_FAILED = AuthenticationStage.USER_VERIFICATION.value
    CHALLENGE_VERIFICATION = AuthenticationStage.CHALLENGE.value
    BAD_CHALLENGE = AuthenticationStage.CHALLENGE.value
    REQUEST_MISMATCH = AuthenticationStage.REQUEST.value

    def __init__(
        self,
        request_id: Optional[str] = None,
        stage: Union[AuthenticationStage, str, None] = None,
        *,
        id: Optional[str] = None,
        phase: Union[AuthenticationStage, str, None] = None,
        name: Optional[str] = None,
        code: Union[AuthenticationFailureCode, str, None] = None,
        field: Union[ResponseField, str, None] = None,
        response_field: Union[ResponseField, str, None] = None,
        message: str = "",
        error: Optional[BaseException] = None,
        challenge_step: Optional[ChallengeStep] = None,
        aliases: Optional[tuple] = None,
        **metadata: Any,
    ) -> None:
        request_id = request_id or id
        stage_value = stage or phase or name or AuthenticationStage.REQUEST
        if isinstance(stage_value, AuthenticationStage):
            self.stage = stage_value
        else:
            try:
                self.stage = AuthenticationStage(stage_value)
            except ValueError:
                self.stage = StepName(str(getattr(stage_value, "value", stage_value)))
        self.phase = self.stage
        self.name = getattr(self.stage, "name", str(self.stage))
        self.value = getattr(self.stage, "value", str(self.stage))
        self.request_id = request_id
        self.code = code
        self.message = message
        self.error = error
        self.challenge_step = challenge_step
        self.metadata = metadata
        self.request: Optional["AuthenticationRequest"] = None
        alias_values = set(aliases or ())
        alias_values.add(self.stage.value)
        alias_values.add(self.stage.name.lower())
        if code is not None:
            alias_values.add(getattr(code, "value", str(code)))
        stage_aliases = _STAGE_ALIASES.get(self.stage, ())
        alias_values.update(stage_aliases)
        self.aliases = tuple(sorted(alias_values))

        selected_field = field if field is not None else response_field
        if selected_field is None:
            selected_field = _DEFAULT_STAGE_FIELDS.get(self.stage)
        if isinstance(selected_field, str):
            selected_field = ResponseField(selected_field, _FIELD_ALIASES.get(self.stage, ()))
        self.field = selected_field
        self.response_field = selected_field
        self.field_name = selected_field.name if selected_field is not None else None
        self.path = selected_field.path if isinstance(selected_field, ResponseField) else selected_field
        self.loc = selected_field.loc if isinstance(selected_field, ResponseField) else None

    @property
    def id(self) -> Optional[str]:
        return self.request_id

    def bind(self, request: "AuthenticationRequest") -> "FailureStage":
        self.request = request
        self.request_id = request.request_id
        if self.challenge_step is None:
            self.challenge_step = request.challenge_step
        return self

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FailureStage):
            return self.stage == other.stage and (
                other.request_id is None or self.request_id == other.request_id
            )
        if isinstance(other, (str, AuthenticationStage)):
            other_value = getattr(other, "value", str(other))
            self_value = getattr(self.stage, "value", str(self.stage))
            if self.stage == other or self_value == other_value:
                return True
            normalized = other_value.replace("_", "").replace("-", "").lower()
            return any(
                alias.replace("_", "").replace("-", "").lower() == normalized
                for alias in self.aliases
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.request_id, self.stage))

    def __repr__(self) -> str:
        stage_value = getattr(self.stage, "value", str(self.stage))
        return f"FailureStage(request_id={self.request_id!r}, stage={stage_value!r})"

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "stage": getattr(self.stage, "value", self.stage),
            "name": self.name,
            "code": getattr(self.code, "value", self.code),
            "field": str(self.field) if self.field is not None else None,
            "message": self.message,
        }

    as_dict = to_dict


_FIELD_ALIASES = {
    AuthenticationStage.CREDENTIAL_ID: (
        "id",
        "raw_id",
        "rawId",
        "rawID",
        "credential.id",
        "credential.rawId",
    ),
    AuthenticationStage.CREDENTIAL_TYPE: ("type", "credential.type"),
    AuthenticationStage.PARSE_CLIENT_DATA: (
        "clientDataJSON",
        "response.clientDataJSON",
        "client_data_json",
        "response.client_data_json",
    ),
    AuthenticationStage.CLIENT_DATA_TYPE: (
        "type",
        "clientDataType",
        "clientDataJSON.type",
        "response.clientDataJSON.type",
    ),
    AuthenticationStage.CHALLENGE: (
        "challenge",
        "expected_challenge",
        "clientDataJSON.challenge",
        "response.clientDataJSON.challenge",
        "client_data.challenge",
    ),
    AuthenticationStage.ORIGIN: (
        "origin",
        "clientDataJSON.origin",
        "response.clientDataJSON.origin",
        "client_data.origin",
    ),
    AuthenticationStage.TOKEN_BINDING: (
        "tokenBinding",
        "token_binding",
        "clientDataJSON.tokenBinding",
        "response.clientDataJSON.tokenBinding",
    ),
    AuthenticationStage.AUTHENTICATOR_DATA: (
        "authenticatorData",
        "response.authenticatorData",
        "authenticator_data",
        "response.authenticator_data",
    ),
    AuthenticationStage.RP_ID: (
        "rpIdHash",
        "rp_id_hash",
        "rp_id",
        "authenticatorData.rpIdHash",
        "response.authenticatorData.rpIdHash",
        "authData.rpIdHash",
    ),
    AuthenticationStage.USER_PRESENCE: (
        "up",
        "flags.up",
        "authenticatorData.flags.up",
        "response.authenticatorData.flags.up",
    ),
    AuthenticationStage.USER_VERIFICATION: (
        "uv",
        "flags.uv",
        "user_verified",
        "authenticatorData.flags.uv",
        "response.authenticatorData.flags.uv",
    ),
    AuthenticationStage.SIGN_COUNT: (
        "signCount",
        "sign_count",
        "new_sign_count",
        "authenticatorData.signCount",
        "response.authenticatorData.signCount",
    ),
    AuthenticationStage.SIGNATURE: ("signature", "sig"),
    AuthenticationStage.BACKUP_FLAGS: (
        "flags",
        "be",
        "bs",
        "authenticatorData.flags",
        "response.authenticatorData.flags",
    ),
    AuthenticationStage.DEVICE_TYPE: (
        "be",
        "credential_device_type",
        "authenticatorData.flags.be",
    ),
    AuthenticationStage.BACKUP_STATE: (
        "bs",
        "credential_backed_up",
        "authenticatorData.flags.bs",
    ),
}

_STAGE_ALIASES = {
    AuthenticationStage.PARSE_CREDENTIAL: (
        "malformed_credential",
        "credential_parsing",
        "credential",
    ),
    AuthenticationStage.CREDENTIAL_ID: ("bad_credential_id", "id_raw_id"),
    AuthenticationStage.CREDENTIAL_TYPE: ("bad_credential_type", "type"),
    AuthenticationStage.PARSE_CLIENT_DATA: ("malformed_client_data", "client_data"),
    AuthenticationStage.CLIENT_DATA_TYPE: ("bad_client_data_type", "type"),
    AuthenticationStage.CHALLENGE: (
        "bad_challenge",
        "challenge_verification",
        "challenge_mismatch",
        "stale_challenge",
        "challenge_replayed",
        "challenge_step",
    ),
    AuthenticationStage.ORIGIN: ("bad_origin", "origin_verification"),
    AuthenticationStage.TOKEN_BINDING: ("bad_token_binding",),
    AuthenticationStage.PARSE_AUTHENTICATOR_DATA: (
        "malformed_authenticator_data",
        "authenticator_data_parsing",
    ),
    AuthenticationStage.RP_ID: ("bad_rp_id", "rp_id_hash", "rp_id_verification"),
    AuthenticationStage.USER_PRESENCE: ("user_not_present", "up"),
    AuthenticationStage.USER_VERIFICATION: (
        "user_not_verified",
        "user_verification_required",
        "uv",
        "user_verification_failed",
    ),
    AuthenticationStage.SIGN_COUNT: ("sign_count_rolled_back", "rollback", "replay"),
    AuthenticationStage.SIGNATURE: ("invalid_signature", "signature_verification"),
    AuthenticationStage.BACKUP_FLAGS: ("invalid_backup_flags", "backup_flag_parse"),
    AuthenticationStage.DEVICE_TYPE: ("device_type_mismatch", "be"),
    AuthenticationStage.BACKUP_STATE: ("backup_state_mismatch", "bs"),
}

_DEFAULT_STAGE_FIELDS = {
    AuthenticationStage.PARSE_CREDENTIAL: ResponseField("credential"),
    AuthenticationStage.CREDENTIAL_ID: ResponseField(
        "response.rawId", ("id", "raw_id", "rawId")
    ),
    AuthenticationStage.CREDENTIAL_TYPE: ResponseField("type", ("credential.type",)),
    AuthenticationStage.PARSE_CLIENT_DATA: ResponseField(
        "response.clientDataJSON", ("client_data_json", "clientDataJSON")
    ),
    AuthenticationStage.CLIENT_DATA_TYPE: ResponseField(
        "response.clientDataJSON.type", ("type", "client_data.type")
    ),
    AuthenticationStage.CHALLENGE: ResponseField(
        "response.clientDataJSON.challenge", ("challenge", "client_data.challenge")
    ),
    AuthenticationStage.ORIGIN: ResponseField(
        "response.clientDataJSON.origin", ("origin", "client_data.origin")
    ),
    AuthenticationStage.TOKEN_BINDING: ResponseField(
        "response.clientDataJSON.tokenBinding", ("token_binding",)
    ),
    AuthenticationStage.PARSE_AUTHENTICATOR_DATA: ResponseField(
        "response.authenticatorData", ("authenticator_data", "authenticatorData")
    ),
    AuthenticationStage.RP_ID: ResponseField(
        "response.authenticatorData.rpIdHash", ("rp_id_hash", "rpIdHash")
    ),
    AuthenticationStage.USER_PRESENCE: ResponseField(
        "response.authenticatorData.flags.up", ("up", "flags.up")
    ),
    AuthenticationStage.USER_VERIFICATION: ResponseField(
        "response.authenticatorData.flags.uv", ("uv", "flags.uv")
    ),
    AuthenticationStage.SIGN_COUNT: ResponseField(
        "response.authenticatorData.signCount", ("sign_count", "signCount")
    ),
    AuthenticationStage.SIGNATURE: ResponseField("response.signature", ("signature", "sig")),
    AuthenticationStage.BACKUP_FLAGS: ResponseField(
        "response.authenticatorData.flags", ("flags", "be", "bs")
    ),
    AuthenticationStage.DEVICE_TYPE: ResponseField(
        "response.authenticatorData.flags.be", ("be", "credential_device_type")
    ),
    AuthenticationStage.BACKUP_STATE: ResponseField(
        "response.authenticatorData.flags.bs", ("bs", "credential_backed_up")
    ),
}


class AuthenticationResult(CorrelationMapping):
    """Request-scoped outcome that callers can safely use to drive UI state."""

    def __init__(
        self,
        request_id: Optional[str] = None,
        *,
        id: Optional[str] = None,
        success: bool = False,
        verified: Optional[bool] = None,
        status: Union[AuthenticationResultStatus, str, None] = None,
        verification: Optional[Any] = None,
        value: Optional[Any] = None,
        error: Optional[BaseException] = None,
        exception: Optional[BaseException] = None,
        challenge_step: Optional[ChallengeStep] = None,
        failure_stage: Optional[FailureStage] = None,
        request: Optional["AuthenticationRequest"] = None,
        **metadata: Any,
    ) -> None:
        request_id = request_id or id
        verification = verification if verification is not None else value
        error = error if error is not None else exception
        self.request_id = request_id or getattr(request, "request_id", None)
        self.success = bool(success and error is None)
        self.verified = self.success if verified is None else bool(verified and self.success)
        self.ok = self.success
        self.verification = verification
        self.value = verification
        self.error = error
        self.exception = error
        self.challenge_step = challenge_step or getattr(request, "challenge_step", None)
        self.failure_stage = failure_stage or getattr(request, "failure_stage", None)
        self.request = request
        self.metadata = metadata
        self.authentication_result = self
        self.result = self
        if status is None:
            status = AuthenticationResultStatus.SUCCESS if self.success else AuthenticationResultStatus.FAILURE
        self.status = AuthenticationResultStatus(status) if not isinstance(status, AuthenticationResultStatus) else status

    @property
    def id(self) -> Optional[str]:
        return self.request_id

    @property
    def failed(self) -> bool:
        return not self.success

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "success": self.success,
            "ok": self.ok,
            "verified": self.verified,
            "status": getattr(self.status, "value", self.status),
            "challenge_step": self.challenge_step.to_dict() if self.challenge_step else None,
            "failure_stage": self.failure_stage.to_dict() if self.failure_stage else None,
        }

    as_dict = to_dict

    def __iter__(self):
        # Supports `result, challenge_step, failure_stage = verify_result(...)`.
        yield self
        yield self.challenge_step
        yield self.failure_stage

    def __getattr__(self, name: str) -> Any:
        # Dataclass fields such as request_id exist before __getattr__ is called.
        verification = self.__dict__.get("verification")
        if verification is not None:
            return getattr(verification, name)
        raise AttributeError(name)

    def __repr__(self) -> str:
        return f"AuthenticationResult(request_id={self.request_id!r}, success={self.success})"


class AuthenticationRequest(CorrelationMapping):
    """A single authentication ceremony/request and all of its correlated reports."""

    def __init__(
        self,
        request_id: Optional[str] = None,
        *,
        id: Optional[str] = None,
        challenge: Optional[bytes] = None,
        expected_challenge: Optional[bytes] = None,
        challenge_step: Optional[ChallengeStep] = None,
        **metadata: Any,
    ) -> None:
        self.request_id = request_id or id or _new_request_id()
        self.id = self.request_id
        self.challenge = bytes(challenge) if challenge is not None else (
            bytes(expected_challenge) if expected_challenge is not None else None
        )
        self.expected_challenge = self.challenge
        self.metadata = metadata
        self.challenge_step = challenge_step or ChallengeStep(
            request_id=self.request_id,
            challenge=self.challenge,
            status=ChallengeStepStatus.CURRENT,
        )
        self.challenge_step.bind(self)
        self.result: Optional[AuthenticationResult] = None
        self.authentication_result: Optional[AuthenticationResult] = None
        self.failure_stage: Optional[FailureStage] = None
        self.attempts: list = []
        self.status = RequestStatus.IN_PROGRESS

    @classmethod
    def start(cls, challenge: Optional[bytes] = None, **kwargs: Any) -> "AuthenticationRequest":
        return cls(challenge=challenge, **kwargs)

    def __enter__(self) -> "AuthenticationRequest":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None and getattr(exc, "request", None) is not self:
            self.record_failure(exc)
        return False

    def issue_challenge(self, challenge: bytes) -> ChallengeStep:
        self.challenge = bytes(challenge)
        self.expected_challenge = self.challenge
        self.challenge_step = ChallengeStep(
            request_id=self.request_id,
            challenge=self.challenge,
            status=ChallengeStepStatus.ISSUED,
        ).bind(self)
        return self.challenge_step

    def record_success(self, verification: Any) -> AuthenticationResult:
        self.challenge_step.verified().consumed()
        self.status = RequestStatus.SUCCESS
        result = AuthenticationResult(
            request_id=self.request_id,
            success=True,
            verification=verification,
            challenge_step=self.challenge_step,
            request=self,
        )
        self.result = result
        self.authentication_result = result
        self.failure_stage = None
        _attach_correlation(verification, self, result)
        self.attempts.append(result)
        return result

    def record_failure(
        self,
        error: Optional[BaseException] = None,
        failure_stage: Optional[FailureStage] = None,
        **kwargs: Any,
    ) -> AuthenticationResult:
        if failure_stage is None:
            failure_stage = FailureStage(
                request_id=self.request_id,
                error=error,
                message=str(error) if error is not None else "",
                challenge_step=self.challenge_step,
                **kwargs,
            )
        failure_stage.bind(self)
        self.failure_stage = failure_stage
        self.challenge_step.failed()
        self.status = RequestStatus.FAILED
        result = AuthenticationResult(
            request_id=self.request_id,
            success=False,
            error=error,
            challenge_step=self.challenge_step,
            failure_stage=failure_stage,
            request=self,
        )
        self.result = result
        self.authentication_result = result
        if error is not None:
            _attach_correlation(error, self, result)
        self.attempts.append(result)
        return result

    def verify_or_raise(self, **kwargs: Any) -> Any:
        from webauthn.authentication.verify_authentication_response import (
            verify_authentication_response,
        )

        kwargs.setdefault("request", self)
        if self.challenge is not None:
            kwargs.setdefault("expected_challenge", self.challenge)
        return verify_authentication_response(**kwargs)

    def verify(self, **kwargs: Any) -> AuthenticationResult:
        """Verify and always return a request-scoped result report."""
        return self.verify_result(**kwargs)

    def verify_result(self, **kwargs: Any) -> AuthenticationResult:
        try:
            verification = self.verify_or_raise(**kwargs)
        except Exception as exc:  # structured result is intentionally non-raising
            result = getattr(exc, "authentication_result", None)
            if isinstance(result, AuthenticationResult):
                return result
            return self.record_failure(exc)
        result = getattr(verification, "authentication_result", None)
        return result if isinstance(result, AuthenticationResult) else self.record_success(verification)

    # Common descriptive aliases.
    authenticate = verify_result
    safe_verify = verify_result
    verify_safely = verify_result
    verify_and_report = verify_result
    verify_response = verify_or_raise


# A ceremony is the natural WebAuthn term for a request; expose the alias for tests
# and applications that model it that way.
AuthenticationCeremony = AuthenticationRequest
Ceremony = AuthenticationRequest
RequestContext = AuthenticationRequest
AuthRequest = AuthenticationRequest
WebAuthnRequest = AuthenticationRequest
AuthenticationSession = AuthenticationRequest


class AuthenticationRequestRegistry:
    """Thread-safe-ish in-memory registry that keeps concurrent requests isolated."""

    def __init__(self) -> None:
        import threading

        self._lock = threading.RLock()
        self._requests: dict = {}
        self._challenges: dict = {}

    def create(
        self,
        request_id: Optional[str] = None,
        *,
        challenge: Optional[bytes] = None,
        **kwargs: Any,
    ) -> AuthenticationRequest:
        request = AuthenticationRequest(request_id=request_id, challenge=challenge, **kwargs)
        with self._lock:
            self._requests[request.request_id] = request
            if request.challenge is not None:
                self._challenges[_challenge_key(request.challenge)] = request.request_id
        return request

    def register(self, request: AuthenticationRequest) -> AuthenticationRequest:
        with self._lock:
            self._requests[request.request_id] = request
            if request.challenge is not None:
                self._challenges[_challenge_key(request.challenge)] = request.request_id
        return request

    def get(self, request_id: str) -> AuthenticationRequest:
        return self._requests[request_id]

    def get_by_challenge(self, challenge: bytes) -> Optional[AuthenticationRequest]:
        request_id = self._challenges.get(_challenge_key(bytes(challenge)))
        return self._requests.get(request_id) if request_id else None

    def bind_challenge(self, request_id: str, challenge: bytes) -> AuthenticationRequest:
        request = self.get(request_id)
        request.issue_challenge(challenge)
        with self._lock:
            self._challenges[_challenge_key(bytes(challenge))] = request_id
        return request


RequestRegistry = AuthenticationRequestRegistry
RequestLedger = AuthenticationRequestRegistry
ChallengeRequestRegistry = AuthenticationRequestRegistry
RequestTracker = AuthenticationRequestRegistry
AuthenticationTracker = AuthenticationRequestRegistry
ChallengeTracker = AuthenticationRequestRegistry
ChallengeManager = AuthenticationRequestRegistry

FailurePhase = FailureStage
AuthenticationFailure = FailureStage
FailureStageInfo = FailureStage
FailureStageRecord = FailureStage
FailureRecord = FailureStage
FailureContext = FailureStage
FailureInfo = FailureStage
ErrorStage = FailureStage
ChallengeStepInfo = ChallengeStep
ChallengeStepRecord = ChallengeStep
ChallengeContext = ChallengeStep
AuthenticationResultInfo = AuthenticationResult
AuthenticationResultRecord = AuthenticationResult
AuthenticationOutcome = AuthenticationResult
AuthResult = AuthenticationResult
VerificationResult = AuthenticationResult
VerificationOutcome = AuthenticationResult
RequestResult = AuthenticationResult
AuthenticationAttempt = AuthenticationRequest
AuthenticationTransaction = AuthenticationRequest
CeremonyContext = AuthenticationRequest
ChallengeState = ChallengeStep
ChallengeRecord = ChallengeStep
AuthFailure = FailureStage
FailureRecordContext = FailureStage

RequestCorrelation = AuthenticationRequest
CorrelationContext = AuthenticationRequest
AuthenticationContext = AuthenticationRequest
AuthenticationFlow = AuthenticationRequest
AuthenticationCeremonyState = AuthenticationRequest


def _new_request_id() -> str:
    from uuid import uuid4

    return uuid4().hex


def _challenge_key(challenge: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(b"webauthn-request-challenge\0" + bytes(challenge)).digest()


def _attach_correlation(target: Any, request: AuthenticationRequest, result: AuthenticationResult) -> None:
    """Attach shared correlation objects without changing a result's primary type."""
    try:
        target.request = request
        target.request_id = request.request_id
        target.correlation_id = request.request_id
        try:
            target.request_identifier = request.request_id
            target.request_uuid = request.request_id
        except Exception:
            pass
        target.authentication_result = result
        target.challenge_step = request.challenge_step
        target.failure_stage = request.failure_stage
        target.status = result.status
        target.success = result.success
        target.ok = result.success
        target.result = result
    except Exception:
        # Some frozen/slotted third-party objects may not accept attributes; the
        # canonical return value remains available from AuthenticationRequest.
        pass
