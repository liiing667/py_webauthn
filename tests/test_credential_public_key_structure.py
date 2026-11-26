import hashlib
import json
from unittest import TestCase

import cbor2
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)

from webauthn import (
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    bytes_to_base64url,
    encode_cbor,
)
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)


_MISSING = object()


class TestCredentialPublicKeyStructure(TestCase):
    """Regression tests for structurally ambiguous credential public keys.

    A COSE public key is a CBOR map. CBOR arrays can put values at the same
    integer positions that ``decode_credential_public_key`` looks up, which
    previously made the meaning of a key depend on element order. Structurally
    equivalent keys must all receive the same security conclusion.
    """

    def setUp(self) -> None:
        self.rp_id = "localhost"
        self.origin = "http://localhost:5000"
        self.challenge = b"challenge-challenge-challenge"
        self.rp_id_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()

        public_numbers = (
            generate_private_key(SECP256R1()).public_key().public_numbers()
        )
        self.x = public_numbers.x.to_bytes(32, "big")
        self.y = public_numbers.y.to_bytes(32, "big")

        self.valid_key = cbor2.dumps(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: self.x,
                -3: self.y,
            }
        )

    def _client_data(self, ceremony_type: str) -> bytes:
        return json.dumps(
            {
                "type": ceremony_type,
                "challenge": bytes_to_base64url(self.challenge),
                "origin": self.origin,
            }
        ).encode("utf-8")

    def _registration_credential(
        self,
        public_key: bytes,
        *,
        att_stmt=_MISSING,
        fmt: str = "none",
    ) -> dict:
        credential_id = b"credential-id"
        auth_data = b"".join(
            [
                self.rp_id_hash,
                bytes([0x45]),  # UP | UV | AT
                (0).to_bytes(4, "big"),
                b"\x00" * 16,
                len(credential_id).to_bytes(2, "big"),
                credential_id,
                public_key,
            ]
        )
        attestation_object = {
            "fmt": fmt,
            "authData": auth_data,
        }
        if att_stmt is not _MISSING:
            attestation_object["attStmt"] = att_stmt

        return {
            "id": bytes_to_base64url(credential_id),
            "rawId": bytes_to_base64url(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(
                    self._client_data("webauthn.create")
                ),
                "attestationObject": bytes_to_base64url(
                    encode_cbor(attestation_object)
                ),
            },
        }

    def _authentication_credential(self) -> dict:
        credential_id = b"credential-id"
        auth_data = b"".join(
            [
                self.rp_id_hash,
                bytes([0x05]),  # UP | UV
                (1).to_bytes(4, "big"),
            ]
        )
        return {
            "id": bytes_to_base64url(credential_id),
            "rawId": bytes_to_base64url(credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(
                    self._client_data("webauthn.get")
                ),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(b"not-a-real-signature"),
            },
        }

    def assert_registration_rejected(self, public_key: bytes) -> None:
        with self.assertRaises(InvalidRegistrationResponse):
            verify_registration_response(
                credential=self._registration_credential(public_key),
                expected_challenge=self.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
            )

    def test_rejects_cose_key_encoded_as_cbor_array(self) -> None:
        # These arrays were previously interpreted positionally as COSE key
        # fields. Their element order determines which values line up with KTY,
        # ALG, CRV, X, and Y.
        keys = (
            cbor2.dumps([0, 2, 0, -7, 32, 32, 1]),
            cbor2.dumps([2, 0, -7, 0, 1, 32, 32]),
        )

        for key in keys:
            with self.subTest(key=key.hex()):
                self.assert_registration_rejected(key)

    def test_rejects_incomplete_cose_key_map(self) -> None:
        keys = (
            cbor2.dumps({1: 2}),
            cbor2.dumps({1: 2, 3: -7}),
            cbor2.dumps({1: 2, 3: -7, -1: 1}),
            cbor2.dumps({1: 2, 3: -7, -1: 1, -2: self.x}),
        )

        for key in keys:
            with self.subTest(key=key.hex()):
                self.assert_registration_rejected(key)

    def test_rejects_non_byte_coordinates(self) -> None:
        key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: 32, -3: 32})

        self.assert_registration_rejected(key)

    def test_rejects_truncated_uncompressed_ec2_key(self) -> None:
        self.assert_registration_rejected(b"\x04")

    def test_rejects_ec2_point_not_on_curve(self) -> None:
        key = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: b"\x01" * 32,
                -3: b"\x02" * 32,
            }
        )

        self.assert_registration_rejected(key)

    def test_accepts_equivalent_cose_key_map_field_orders(self) -> None:
        reordered_key = cbor2.dumps(
            {
                -3: self.y,
                -2: self.x,
                -1: 1,
                3: -7,
                1: 2,
            }
        )

        for key in (self.valid_key, reordered_key):
            with self.subTest(key=key.hex()):
                verification = verify_registration_response(
                    credential=self._registration_credential(key),
                    expected_challenge=self.challenge,
                    expected_rp_id=self.rp_id,
                    expected_origin=self.origin,
                )

                # A valid key must not be rewritten into a different structure.
                self.assertEqual(verification.credential_public_key, key)

    def test_rejects_non_map_attestation_statement(self) -> None:
        for att_stmt in ("", [], 0):
            with self.subTest(att_stmt=att_stmt):
                with self.assertRaises(InvalidRegistrationResponse):
                    verify_registration_response(
                        credential=self._registration_credential(
                            self.valid_key,
                            att_stmt=att_stmt,
                        ),
                        expected_challenge=self.challenge,
                        expected_rp_id=self.rp_id,
                        expected_origin=self.origin,
                    )

    def test_rejects_unexpected_attestation_statement_field(self) -> None:
        with self.assertRaises(InvalidRegistrationResponse):
            verify_registration_response(
                credential=self._registration_credential(
                    self.valid_key,
                    att_stmt={"unexpected": b"value"},
                ),
                expected_challenge=self.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
            )

    def test_authentication_rejects_malformed_stored_public_keys(self) -> None:
        malformed_keys = (
            b"",
            b"\x04",
            cbor2.dumps([0, 2, 0, -7, 32, 32, 1]),
            cbor2.dumps({1: 2, 3: -7}),
            cbor2.dumps({1: 2, 3: -7, -1: 1, -2: 32, -3: 32}),
        )

        for key in malformed_keys:
            with self.subTest(key=key.hex()):
                with self.assertRaises(InvalidAuthenticationResponse):
                    verify_authentication_response(
                        credential=self._authentication_credential(),
                        expected_challenge=self.challenge,
                        expected_rp_id=self.rp_id,
                        expected_origin=self.origin,
                        credential_public_key=key,
                        credential_current_sign_count=0,
                    )
