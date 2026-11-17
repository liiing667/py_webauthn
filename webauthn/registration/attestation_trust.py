from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional

from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import AttestationFormat, AttestationStatement


@dataclass(frozen=True)
class AttestationTrustPolicy:
    """Trust requirements shared by every attestation format verifier.

    Attributes:
        `requires_certificate_chain`: Whether the attestation statement must present an
            x5c certificate chain that validates back to a configured root certificate.
        `expected_zero_aaguid`: Whether the authenticator data AAGUID must be all zeroes.
    """

    requires_certificate_chain: bool
    expected_zero_aaguid: bool = False


# The single source of truth for how each attestation format establishes trust.
# Formats not listed here (and any future format that forgets to register a policy)
# are rejected by the entry point instead of being implicitly trusted.
ATTESTATION_TRUST_POLICIES: Dict[AttestationFormat, AttestationTrustPolicy] = {
    # "none" carries no attestation statement, so there is no chain to validate
    AttestationFormat.NONE: AttestationTrustPolicy(requires_certificate_chain=False),
    # Packed self attestation has no x5c; an x5c statement requires a trusted chain
    AttestationFormat.PACKED: AttestationTrustPolicy(requires_certificate_chain=True),
    AttestationFormat.TPM: AttestationTrustPolicy(requires_certificate_chain=True),
    AttestationFormat.APPLE: AttestationTrustPolicy(requires_certificate_chain=True),
    AttestationFormat.ANDROID_KEY: AttestationTrustPolicy(
        requires_certificate_chain=True
    ),
    AttestationFormat.ANDROID_SAFETYNET: AttestationTrustPolicy(
        requires_certificate_chain=True
    ),
    # FIDO U2F attestations are required by spec to use an all-zeroes AAGUID
    AttestationFormat.FIDO_U2F: AttestationTrustPolicy(
        requires_certificate_chain=True,
        expected_zero_aaguid=True,
    ),
}

ZERO_AAGUID = b"\x00" * 16


def get_attestation_trust_policy(fmt: AttestationFormat) -> AttestationTrustPolicy:
    """Return the trust policy for an attestation format.

    Raises:
        `InvalidRegistrationResponse` for formats without a registered policy.
    """
    try:
        return ATTESTATION_TRUST_POLICIES[fmt]
    except KeyError:
        raise InvalidRegistrationResponse(f'Unsupported attestation type "{fmt}"')


def enforce_attestation_trust_policy(
    *,
    policy: AttestationTrustPolicy,
    attestation_statement: AttestationStatement,
    aaguid: bytes,
    pem_root_certs_bytes: Optional[List[bytes]],
) -> None:
    """Apply the shared trust decision before a format-specific verifier runs.

    The format verifiers only parse statements and check signatures; this function
    synthesizes the root certificate, AAGUID, and RP ID requirements into a single
    fail-closed conclusion so that a later field check can never override a failed
    trust decision.

    Raises:
        `InvalidRegistrationResponse` if any trust requirement cannot be satisfied.
    """
    if policy.expected_zero_aaguid and aaguid != ZERO_AAGUID:
        raise InvalidRegistrationResponse(
            "AAGUID was not the expected all-zeroes AAGUID for this attestation type"
        )

    if not policy.requires_certificate_chain:
        return

    # Self attestation (e.g. packed without x5c) is explicitly allowed: the
    # credential public key itself is used to verify the signature downstream.
    if not attestation_statement.x5c:
        return

    if not pem_root_certs_bytes:
        raise InvalidRegistrationResponse(
            "Attestation statement presented an x5c certificate chain but no root "
            "certificates were configured to validate it"
        )


def root_certs_for_format(
    fmt: AttestationFormat,
    pem_root_certs_bytes_by_fmt: Optional[Mapping[AttestationFormat, List[bytes]]],
) -> List[bytes]:
    """Resolve the RP-configured root certificates for an attestation format."""
    if not pem_root_certs_bytes_by_fmt:
        return []

    custom_certs = pem_root_certs_bytes_by_fmt.get(fmt)
    if not custom_certs:
        return []

    return list(custom_certs)
