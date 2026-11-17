import hashlib
import json
import re
from pathlib import Path
from unittest import TestCase

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn import verify_registration_response
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    encode_cbor,
    parse_authenticator_data,
    parse_cbor,
)
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.known_root_certs import globalsign_root_ca, yubico_u2f_root_ca
from webauthn.helpers.structs import AttestationFormat, AttestationStatement
from webauthn.registration.attestation_trust import (
    ATTESTATION_TRUST_POLICIES,
    ZERO_AAGUID,
    AttestationTrustPolicy,
    enforce_attestation_trust_policy,
    get_attestation_trust_policy,
)


def _first_credential(path: str) -> dict:
    text = Path(path).read_text()
    return json.loads(re.findall(r'"""(.*?)"""', text, re.S)[0])


def _self_attested_packed_credential() -> dict:
    """Build a valid packed self-attestation response (no x5c) at runtime."""
    none_blob = (
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_"
        "krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRR"
        "Jk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjm"
        "OPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n6"
        "6r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA"
    )
    parsed = parse_cbor(base64url_to_bytes(none_blob))
    auth_data_bytes = parsed["authData"]
    auth_data = parse_authenticator_data(auth_data_bytes)
    attested = auth_data.attested_credential_data

    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    cose_key = encode_cbor(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )
    new_attested = (
        attested.aaguid
        + len(attested.credential_id).to_bytes(2, "big")
        + attested.credential_id
        + cose_key
    )
    new_auth_data = auth_data_bytes[:37] + new_attested

    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw",
            "origin": "http://localhost:5000",
            "crossOrigin": False,
        },
        separators=(",", ":"),
    ).encode()
    client_data_hash = hashlib.sha256(client_data_json).digest()
    signature = private_key.sign(
        new_auth_data + client_data_hash,
        ec.ECDSA(hashes.SHA256()),
    )

    attestation_object = encode_cbor(
        {
            "fmt": "packed",
            "attStmt": {"alg": -7, "sig": signature},
            "authData": new_auth_data,
        }
    )

    return {
        "id": bytes_to_base64url(attested.credential_id),
        "rawId": bytes_to_base64url(attested.credential_id),
        "response": {
            "attestationObject": bytes_to_base64url(attestation_object),
            "clientDataJSON": bytes_to_base64url(client_data_json),
        },
        "type": "public-key",
    }


class TestAttestationTrustPolicy(TestCase):
    def test_every_known_format_has_a_policy(self) -> None:
        for fmt in AttestationFormat:
            self.assertIsInstance(
                get_attestation_trust_policy(fmt),
                AttestationTrustPolicy,
            )

    def test_unknown_format_has_no_policy(self) -> None:
        with self.assertRaises(InvalidRegistrationResponse):
            get_attestation_trust_policy("not_a_real_format")  # type: ignore[arg-type]

    def test_none_and_self_attestation_do_not_require_chains(self) -> None:
        # "none" never carries an x5c chain and remains explicitly supported
        self.assertFalse(
            ATTESTATION_TRUST_POLICIES[
                AttestationFormat.NONE
            ].requires_certificate_chain
        )

        # Packed self attestation (no x5c) is allowed without root certificates...
        enforce_attestation_trust_policy(
            policy=ATTESTATION_TRUST_POLICIES[AttestationFormat.PACKED],
            attestation_statement=AttestationStatement(),
            aaguid=ZERO_AAGUID,
            pem_root_certs_bytes=None,
        )

        # ...but a packed x5c statement without configured roots fails closed
        with self.assertRaisesRegex(
            InvalidRegistrationResponse, "no root certificates were configured"
        ):
            enforce_attestation_trust_policy(
                policy=ATTESTATION_TRUST_POLICIES[AttestationFormat.PACKED],
                attestation_statement=AttestationStatement(x5c=[b"not-a-real-cert"]),
                aaguid=ZERO_AAGUID,
                pem_root_certs_bytes=None,
            )

    def test_fido_u2f_requires_zero_aaguid(self) -> None:
        policy = ATTESTATION_TRUST_POLICIES[AttestationFormat.FIDO_U2F]
        self.assertTrue(policy.expected_zero_aaguid)

        with self.assertRaises(InvalidRegistrationResponse):
            enforce_attestation_trust_policy(
                policy=policy,
                attestation_statement=AttestationStatement(x5c=[b"cert"]),
                aaguid=b"\x01" * 16,
                pem_root_certs_bytes=[yubico_u2f_root_ca],
            )


class TestRegistrationFailClosed(TestCase):
    challenge = base64url_to_bytes(
        "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
    )

    def _packed_yubikey_credential(self) -> tuple[dict, bytes, str, str]:
        credential = _first_credential(
            "tests/test_verify_registration_response_packed.py"
        )
        challenge = base64url_to_bytes(
            "8LBCiOY3q1cBZHFAWtS4AZZChzGphy67lK7I70zKi4yC7pgrQ2Pch7nAjLk1wq9greshIAsW2AjibhXjjI0TmQ"
        )
        return credential, challenge, "localhost", "http://localhost:5000"

    def test_packed_x5c_without_roots_is_rejected(self) -> None:
        # Regression test: a self-signed/unknown packed attestation used to be accepted
        # because chain validation was skipped entirely when no roots were configured
        credential, challenge, rp_id, origin = self._packed_yubikey_credential()

        with self.assertRaisesRegex(
            InvalidRegistrationResponse, "no root certificates were configured"
        ):
            verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
            )

    def test_packed_x5c_with_unrelated_root_is_rejected(self) -> None:
        credential, challenge, rp_id, origin = self._packed_yubikey_credential()

        with self.assertRaises(InvalidRegistrationResponse):
            verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                pem_root_certs_bytes_by_fmt={
                    # This root is for android-safetynet, not packed YubiKey attestations
                    AttestationFormat.PACKED: [globalsign_root_ca],
                },
            )

    def test_packed_x5c_with_matching_root_is_accepted(self) -> None:
        credential, challenge, rp_id, origin = self._packed_yubikey_credential()

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            pem_root_certs_bytes_by_fmt={
                AttestationFormat.PACKED: [yubico_u2f_root_ca],
            },
        )

        self.assertEqual(verification.fmt, AttestationFormat.PACKED)

    def test_packed_self_attestation_without_roots_is_accepted(self) -> None:
        # Explicit "direct"/self attestation compatibility: no x5c means the credential
        # public key itself anchors trust, so no root certificates need to be configured
        verification = verify_registration_response(
            credential=_self_attested_packed_credential(),
            expected_challenge=self.challenge,
            expected_origin="http://localhost:5000",
            expected_rp_id="localhost",
        )

        self.assertEqual(verification.fmt, AttestationFormat.PACKED)
