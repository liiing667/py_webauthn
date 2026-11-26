from __future__ import annotations

import base64
import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from .bytes_to_base64url import bytes_to_base64url
from .exceptions import DeviceIdentityMismatchError


class IdentityConsistencyStatus(str, Enum):
    """Result of comparing a stored device identity with a ceremony result."""

    CONSISTENT = "consistent"
    RECOVERED = "recovered"
    MIGRATED = "migrated"
    MISMATCH = "mismatch"


@dataclass(frozen=True)
class DeviceIdentity:
    """Stable identity for one WebAuthn credential/device binding.

    The credential ID is the RP-visible stable handle.  The public-key fingerprint
    additionally binds that handle to the key accepted during registration.  AAGUID and
    backup flags are provenance/state metadata, not identity: they can change during
    passkey provider migration or account recovery without creating a different device.
    """

    credential_id: bytes
    public_key_sha256: Optional[str] = None
    rp_id: Optional[str] = None

    @classmethod
    def from_credential(
        cls,
        credential_id: bytes,
        credential_public_key: Optional[bytes] = None,
        rp_id: Optional[str] = None,
    ) -> "DeviceIdentity":
        return cls(
            credential_id=bytes(credential_id),
            public_key_sha256=fingerprint_public_key(credential_public_key),
            rp_id=rp_id,
        )

    @classmethod
    def from_registration(
        cls,
        verification: Any,
        rp_id: Optional[str] = None,
    ) -> "DeviceIdentity":
        existing = getattr(verification, "device_identity", None)
        if existing is not None:
            return existing
        return cls.from_credential(
            credential_id=verification.credential_id,
            credential_public_key=getattr(verification, "credential_public_key", None),
            rp_id=rp_id,
        )

    @classmethod
    def from_authentication(
        cls,
        verification: Any,
        credential_public_key: Optional[bytes] = None,
        rp_id: Optional[str] = None,
    ) -> "DeviceIdentity":
        existing = getattr(verification, "device_identity", None)
        if existing is not None and credential_public_key is None:
            return existing
        return cls.from_credential(
            credential_id=verification.credential_id,
            credential_public_key=credential_public_key,
            rp_id=rp_id or getattr(existing, "rp_id", None),
        )

    @property
    def identity_digest(self) -> str:
        """Non-secret stable digest suitable for indexing or audit correlation."""
        digest = hashlib.sha256(b"webauthn-device-identity/v1\0")
        if self.rp_id is not None:
            rp_bytes = self.rp_id.encode("utf-8")
            digest.update(len(rp_bytes).to_bytes(2, "big"))
            digest.update(rp_bytes)
        digest.update(len(self.credential_id).to_bytes(4, "big"))
        digest.update(self.credential_id)
        if self.public_key_sha256:
            pk_bytes = self.public_key_sha256.encode("ascii")
            digest.update(len(pk_bytes).to_bytes(2, "big"))
            digest.update(pk_bytes)
        return digest.hexdigest()

    @property
    def device_id(self) -> str:
        """URL-safe opaque identifier derived from :attr:`identity_digest`."""
        raw = bytes.fromhex(self.identity_digest)
        return bytes_to_base64url(raw)

    # Common aliases used by audit interfaces.
    @property
    def stable_id(self) -> str:
        return self.device_id

    @property
    def fingerprint(self) -> str:
        return self.identity_digest

    def matches_core(self, observed: "DeviceIdentity") -> bool:
        if self.credential_id != observed.credential_id:
            return False
        if (
            self.public_key_sha256
            and observed.public_key_sha256
            and self.public_key_sha256 != observed.public_key_sha256
        ):
            return False
        if self.rp_id is not None and observed.rp_id is not None:
            if self.rp_id != observed.rp_id:
                return False
        return True

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "identity_digest": self.identity_digest,
            "credential_id": bytes_to_base64url(self.credential_id),
            "public_key_sha256": self.public_key_sha256,
            "rp_id": self.rp_id,
        }


@dataclass(frozen=True)
class DeviceProvenance:
    """Registration-time evidence that explains where a device credential came from."""

    aaguid: Optional[str] = None
    attestation_format: Optional[str] = None
    credential_device_type: Optional[str] = None
    credential_backed_up: Optional[bool] = None
    attestation_certificate_sha256: Optional[str] = None
    attestation_certificate_subject: Optional[str] = None
    attestation_root_sha256: Optional[str] = None
    attestation_root_subject: Optional[str] = None
    attestation_root_name: Optional[str] = None
    source: str = "webauthn_registration"

    def to_audit_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceIdentityAudit:
    """Auditable result of reconciling stored and observed device identity."""

    status: IdentityConsistencyStatus
    consistent: bool
    recovery: bool
    stored_identity: DeviceIdentity
    observed_identity: DeviceIdentity
    changes: List[str] = field(default_factory=list)
    reason: Optional[str] = None

    @property
    def identity_digest(self) -> str:
        return self.stored_identity.identity_digest

    def raise_if_inconsistent(self) -> None:
        if not self.consistent:
            raise DeviceIdentityMismatchError(self.reason or "Device identity mismatch")

    # Concise alias.
    def require_consistent(self) -> None:
        self.raise_if_inconsistent()

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "consistent": self.consistent,
            "recovery": self.recovery,
            "identity_digest": self.identity_digest,
            "device_id": self.stored_identity.device_id,
            "changes": list(self.changes),
            "reason": self.reason,
            "stored_identity": self.stored_identity.to_audit_dict(),
            "observed_identity": self.observed_identity.to_audit_dict(),
        }


# A descriptive alias for callers that prefer "report" terminology.
DeviceIdentityReport = DeviceIdentityAudit
DeviceAudit = DeviceIdentityAudit

# "Source"/"origin" are audit-UI language for the same provenance record.
DeviceSource = DeviceProvenance
DeviceOrigin = DeviceProvenance


def fingerprint_public_key(credential_public_key: Optional[bytes]) -> Optional[str]:
    if credential_public_key is None:
        return None
    return hashlib.sha256(bytes(credential_public_key)).hexdigest()


def _normalize_cert_digest(digest: Union[bytes, str]) -> str:
    if isinstance(digest, bytes):
        digest = digest.decode("ascii", "replace")
    return digest.replace(":", "").lower()


def _pem_cert_fingerprint(pem_cert: bytes) -> str:
    lines = [
        line.strip()
        for line in pem_cert.splitlines()
        if line.strip() and not line.strip().startswith(b"-----")
    ]
    return hashlib.sha256(base64.b64decode(b"".join(lines))).hexdigest()


def _cert_summary_der(cert_der: bytes) -> Dict[str, str]:
    # Fingerprint is always SHA-256 over the raw DER certificate bytes.
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    subject = ""
    try:
        from cryptography.x509 import load_der_x509_certificate

        cert = load_der_x509_certificate(cert_der)
        subject = cert.subject.rfc4514_string()
    except Exception:
        # Some attestation certificates intentionally contain non-standard values;
        # the fingerprint still gives audit tooling a stable correlation key.
        pass

    return {
        "sha256": fingerprint,
        "subject": subject,
    }


def _android_root_names_by_fingerprint() -> Dict[str, str]:
    from .known_root_certs import (
        google_hardware_attestation_root_2,
        google_hardware_attestation_root_3,
        google_hardware_attestation_root_4,
        google_hardware_attestation_root_5,
    )

    roots = {
        "google_hardware_attestation_root_2": google_hardware_attestation_root_2,
        "google_hardware_attestation_root_3": google_hardware_attestation_root_3,
        "google_hardware_attestation_root_4": google_hardware_attestation_root_4,
        "google_hardware_attestation_root_5": google_hardware_attestation_root_5,
    }
    result: Dict[str, str] = {}
    for name, pem in roots.items():
        try:
            result[_pem_cert_fingerprint(pem)] = name
        except Exception:
            continue
    return result


def attestation_provenance_from_registration(verification: Any) -> DeviceProvenance:
    """Extract audit-friendly device source information from a VerifiedRegistration."""

    fmt = getattr(verification.fmt, "value", verification.fmt)
    device_type = getattr(
        verification.credential_device_type,
        "value",
        verification.credential_device_type,
    )

    leaf_summary: Optional[Dict[str, str]] = None
    root_summary: Optional[Dict[str, str]] = None
    root_name: Optional[str] = None

    try:
        from .parse_attestation_object import parse_attestation_object

        attestation = parse_attestation_object(verification.attestation_object)
        x5c = getattr(attestation.att_stmt, "x5c", None) or []
        if x5c:
            leaf_summary = _cert_summary_der(x5c[0])
            root_summary = _cert_summary_der(x5c[-1])
            if fmt == "android-key":
                root_name = _android_root_names_by_fingerprint().get(
                    root_summary["sha256"]
                )
    except Exception:
        # Audit enrichment must not turn an already-verified response into a failure.
        pass

    return DeviceProvenance(
        aaguid=getattr(verification, "aaguid", None),
        attestation_format=fmt,
        credential_device_type=device_type,
        credential_backed_up=getattr(verification, "credential_backed_up", None),
        attestation_certificate_sha256=(leaf_summary or {}).get("sha256"),
        attestation_certificate_subject=(leaf_summary or {}).get("subject"),
        attestation_root_sha256=(root_summary or {}).get("sha256"),
        attestation_root_subject=(root_summary or {}).get("subject"),
        attestation_root_name=root_name,
    )


# Shorter functional alias.
def build_provenance(verification: Any) -> DeviceProvenance:
    return attestation_provenance_from_registration(verification)


def compare_device_identity(
    stored: Union[DeviceIdentity, "DeviceIdentityRecord"],
    observed: Union[DeviceIdentity, Any],
    *,
    recovery: bool = False,
    previous_device_type: Optional[Any] = None,
    new_device_type: Optional[Any] = None,
    previous_backed_up: Optional[bool] = None,
    new_backed_up: Optional[bool] = None,
) -> DeviceIdentityAudit:
    """Compare stable identity while allowing recovery/migration metadata changes."""

    stored_identity = (
        stored.identity if isinstance(stored, DeviceIdentityRecord) else stored
    )

    if isinstance(observed, DeviceIdentity):
        observed_identity = observed
    else:
        observed_identity = DeviceIdentity.from_authentication(observed)

    changes: List[str] = []
    reason: Optional[str] = None

    if stored_identity.credential_id != observed_identity.credential_id:
        reason = "Credential ID did not match the stored device identity"
    elif (
        stored_identity.public_key_sha256
        and observed_identity.public_key_sha256
        and stored_identity.public_key_sha256 != observed_identity.public_key_sha256
    ):
        reason = "Credential public key did not match the stored device identity"
    elif (
        stored_identity.rp_id is not None
        and observed_identity.rp_id is not None
        and stored_identity.rp_id != observed_identity.rp_id
    ):
        reason = "Relying party ID did not match the stored device identity"

    def _value(value: Any) -> Any:
        return getattr(value, "value", value)

    old_type = _value(previous_device_type)
    next_type = _value(new_device_type)
    if old_type is not None and next_type is not None and old_type != next_type:
        changes.append(f"credential_device_type:{old_type}->{next_type}")

    if previous_backed_up is not None and previous_backed_up != new_backed_up:
        changes.append(f"credential_backed_up:{previous_backed_up}->{new_backed_up}")

    if reason is not None:
        status = IdentityConsistencyStatus.MISMATCH
        consistent = False
    elif recovery:
        status = IdentityConsistencyStatus.RECOVERED
        consistent = True
    elif changes:
        status = IdentityConsistencyStatus.MIGRATED
        consistent = True
    else:
        status = IdentityConsistencyStatus.CONSISTENT
        consistent = True

    return DeviceIdentityAudit(
        status=status,
        consistent=consistent,
        recovery=recovery,
        stored_identity=stored_identity,
        observed_identity=observed_identity,
        changes=changes,
        reason=reason,
    )


def assert_device_identity(
    stored: Union[DeviceIdentity, "DeviceIdentityRecord"],
    observed: Union[DeviceIdentity, Any],
    **kwargs: Any,
) -> DeviceIdentityAudit:
    """Compare identities and raise :class:`DeviceIdentityMismatchError` on mismatch."""

    report = compare_device_identity(stored, observed, **kwargs)
    report.raise_if_inconsistent()
    return report


# Descriptive functional aliases.
verify_device_identity = compare_device_identity


def recover_device_identity(
    record: "DeviceIdentityRecord",
    verification: Any,
    **kwargs: Any,
) -> DeviceIdentityAudit:
    """Reconcile a recovery ceremony against a stored device record."""

    return record.recover(verification, **kwargs)


@dataclass
class DeviceIdentityRecord:
    """Stored device binding plus the audit state an RP should persist."""

    identity: DeviceIdentity
    account_id: Optional[str] = None
    provenance: Optional[DeviceProvenance] = None
    credential_device_type: Optional[str] = None
    credential_backed_up: Optional[bool] = None
    sign_count: int = 0
    recovery_count: int = 0
    audit_events: List[Dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_registration(
        cls,
        verification: Any,
        *,
        account_id: Optional[str] = None,
        rp_id: Optional[str] = None,
    ) -> "DeviceIdentityRecord":
        identity = DeviceIdentity.from_registration(verification, rp_id=rp_id)
        provenance = attestation_provenance_from_registration(verification)
        device_type = getattr(verification, "credential_device_type", None)
        return cls(
            identity=identity,
            account_id=account_id,
            provenance=provenance,
            credential_device_type=getattr(device_type, "value", device_type),
            credential_backed_up=getattr(verification, "credential_backed_up", None),
            sign_count=getattr(verification, "sign_count", 0),
            audit_events=[
                {
                    "event": "registered",
                    "account_id": account_id,
                    "device_id": identity.device_id,
                }
            ],
        )

    def observe(
        self,
        verification: Any,
        *,
        recovery: bool = False,
        credential_public_key: Optional[bytes] = None,
        rp_id: Optional[str] = None,
    ) -> DeviceIdentityAudit:
        observed = DeviceIdentity.from_authentication(
            verification,
            credential_public_key=credential_public_key,
            rp_id=rp_id or self.identity.rp_id,
        )

        new_type = getattr(verification, "credential_device_type", None)
        new_backed_up = getattr(verification, "credential_backed_up", None)
        report = compare_device_identity(
            self.identity,
            observed,
            recovery=recovery,
            previous_device_type=self.credential_device_type,
            new_device_type=new_type,
            previous_backed_up=self.credential_backed_up,
            new_backed_up=new_backed_up,
        )

        if not report.consistent:
            # Audit the failed attempt without mutating the trusted record.
            self.audit_events.append(
                {"event": "identity_mismatch", **report.to_audit_dict()}
            )
            return report

        self.identity = report.stored_identity
        if new_type is not None:
            self.credential_device_type = getattr(new_type, "value", new_type)
        if new_backed_up is not None:
            self.credential_backed_up = new_backed_up
        if hasattr(verification, "new_sign_count"):
            self.sign_count = verification.new_sign_count
        elif hasattr(verification, "sign_count"):
            self.sign_count = verification.sign_count

        if recovery:
            self.recovery_count += 1

        event_name = "recovered" if recovery else "authenticated"
        self.audit_events.append({"event": event_name, **report.to_audit_dict()})
        return report

    # Semantic aliases for the three lifecycle phases.
    def record_login(self, verification: Any, **kwargs: Any) -> DeviceIdentityAudit:
        return self.observe(verification, recovery=False, **kwargs)

    def recover(self, verification: Any, **kwargs: Any) -> DeviceIdentityAudit:
        return self.observe(verification, recovery=True, **kwargs)

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "identity": self.identity.to_audit_dict(),
            "provenance": self.provenance.to_audit_dict() if self.provenance else None,
            "credential_device_type": self.credential_device_type,
            "credential_backed_up": self.credential_backed_up,
            "sign_count": self.sign_count,
            "recovery_count": self.recovery_count,
            "events": list(self.audit_events),
        }


class DeviceIdentityRegistry:
    """In-memory account-to-device binding registry and audit view.

    Real deployments should persist :meth:`DeviceIdentityRecord.to_audit_dict` data in
    their database.  This class documents the consistency boundary: challenges are
    single-use and account-scoped, registration creates the binding, login proves
    control of the same credential key, and recovery may update backup metadata without
    replacing the stable device identity.
    """

    def __init__(self) -> None:
        self._records: Dict[str, Dict[bytes, DeviceIdentityRecord]] = {}
        self._credential_account_index: Dict[bytes, str] = {}

    def bind_registration(
        self,
        account_id: Union[str, int],
        verification: Any,
        *,
        rp_id: Optional[str] = None,
        allow_replacement: bool = False,
    ) -> DeviceIdentityRecord:
        account_key = str(account_id)
        record = DeviceIdentityRecord.from_registration(
            verification,
            account_id=account_key,
            rp_id=rp_id,
        )
        credential_id = record.identity.credential_id
        existing_account = self._credential_account_index.get(credential_id)
        if existing_account is not None and existing_account != account_key:
            raise DeviceIdentityMismatchError(
                "Credential ID is already bound to another account"
            )

        existing = self._records.get(account_key, {}).get(credential_id)
        if (
            existing is not None
            and existing.identity.public_key_sha256
            and record.identity.public_key_sha256
            and existing.identity.public_key_sha256
            != record.identity.public_key_sha256
            and not allow_replacement
        ):
            raise DeviceIdentityMismatchError(
                "Cannot replace the public key for an existing credential ID; "
                "use an explicit recovery/replacement flow or allow_replacement=True"
            )

        self._records.setdefault(account_key, {})[credential_id] = record
        self._credential_account_index[credential_id] = account_key
        return record

    # Familiar aliases.
    register_device = bind_registration
    add_device = bind_registration

    def get_record(
        self,
        account_id: Union[str, int],
        credential_id: bytes,
    ) -> DeviceIdentityRecord:
        try:
            return self._records[str(account_id)][bytes(credential_id)]
        except KeyError as exc:
            raise DeviceIdentityMismatchError(
                "Credential is not bound to this account"
            ) from exc

    def observe(
        self,
        account_id: Union[str, int],
        verification: Any,
        *,
        recovery: bool = False,
        credential_public_key: Optional[bytes] = None,
    ) -> DeviceIdentityAudit:
        record = self.get_record(account_id, verification.credential_id)
        return record.observe(
            verification,
            recovery=recovery,
            credential_public_key=credential_public_key,
        )

    def verify_login(
        self,
        account_id: Union[str, int],
        verification: Any,
        *,
        credential_public_key: Optional[bytes] = None,
    ) -> DeviceIdentityAudit:
        return self.observe(
            account_id,
            verification,
            recovery=False,
            credential_public_key=credential_public_key,
        )

    def recover_device(
        self,
        account_id: Union[str, int],
        verification: Any,
        *,
        credential_public_key: Optional[bytes] = None,
    ) -> DeviceIdentityAudit:
        return self.observe(
            account_id,
            verification,
            recovery=True,
            credential_public_key=credential_public_key,
        )

    def audit_account(self, account_id: Union[str, int]) -> List[Dict[str, Any]]:
        return [
            record.to_audit_dict()
            for record in self._records.get(str(account_id), {}).values()
        ]

    def audit(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            account_id: [record.to_audit_dict() for record in records.values()]
            for account_id, records in self._records.items()
        }


# Short aliases for code that uses "registry"/"store" terminology.
DeviceRegistry = DeviceIdentityRegistry
DeviceIdentityStore = DeviceIdentityRegistry
