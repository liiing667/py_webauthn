import hashlib
import json
from unittest import TestCase
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    encode_cbor,
    parse_attestation_object,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier, COSECRV, COSEKTY, COSEKey
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidBackupFlags,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticationFailureCode,
    BackupStateChange,
    CredentialDeviceType,
    RegistrationFailureCode,
    SignCountStatus,
)


def _generate_es256_credential():
    """Generate an ES256 private key and its CBOR-encoded COSE public key"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()

    public_key_cbor = encode_cbor(
        {
            COSEKey.KTY: COSEKTY.EC2,
            COSEKey.ALG: COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEKey.CRV: COSECRV.P256,
            COSEKey.X: numbers.x.to_bytes(32, "big"),
            COSEKey.Y: numbers.y.to_bytes(32, "big"),
        }
    )

    return private_key, public_key_cbor


def _build_credential(
    *,
    private_key,
    rp_id: str,
    challenge: bytes,
    origin: str,
    flags_byte: int,
    sign_count: int,
):
    """Build a signed authentication credential with arbitrary flags and counter"""
    rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    authenticator_data = (
        rp_id_hash + bytes([flags_byte]) + sign_count.to_bytes(4, "big")
    )

    client_data = {
        "type": "webauthn.get",
        "challenge": bytes_to_base64url(challenge),
        "origin": origin,
    }
    client_data_json = json.dumps(client_data).encode("utf-8")

    signature_base = authenticator_data + hashlib.sha256(client_data_json).digest()
    der_signature = private_key.sign(signature_base, ec.ECDSA(hashes.SHA256()))

    credential_id = b"test-credential-id"
    return {
        "id": bytes_to_base64url(credential_id),
        "rawId": bytes_to_base64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "authenticatorData": bytes_to_base64url(authenticator_data),
            "signature": bytes_to_base64url(der_signature),
        },
    }


# Flag bits: UP=0b00000001, BE=0b00001000, BS=0b00010000
FLAGS_UP = 0b00000001
FLAGS_UP_BE = 0b00001001
FLAGS_UP_BE_BS = 0b00011001


class TestAuthenticationStatusContract(TestCase):
    def setUp(self) -> None:
        self.private_key, self.public_key_cbor = _generate_es256_credential()
        self.rp_id = "localhost"
        self.origin = "http://localhost:5000"
        self.challenge = b"test-challenge-value"

    def _verify(self, *, flags_byte, sign_count, current_sign_count, **kwargs):
        credential = _build_credential(
            private_key=self.private_key,
            rp_id=self.rp_id,
            challenge=self.challenge,
            origin=self.origin,
            flags_byte=flags_byte,
            sign_count=sign_count,
        )
        return verify_authentication_response(
            credential=credential,
            expected_challenge=self.challenge,
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
            credential_public_key=self.public_key_cbor,
            credential_current_sign_count=current_sign_count,
            **kwargs,
        )

    def test_synced_passkey_with_zero_counters_is_accepted(self) -> None:
        verification = self._verify(
            flags_byte=FLAGS_UP_BE_BS,
            sign_count=0,
            current_sign_count=0,
        )

        self.assertEqual(
            verification.credential_device_type,
            CredentialDeviceType.MULTI_DEVICE,
        )
        self.assertTrue(verification.credential_backed_up)
        self.assertEqual(verification.sign_count.status, SignCountStatus.NOT_SUPPORTED)
        self.assertFalse(verification.sign_count.rolled_back)
        self.assertEqual(verification.sign_count.previous_sign_count, 0)
        self.assertEqual(verification.sign_count.new_sign_count, 0)
        self.assertEqual(verification.backup_state.change, BackupStateChange.UNCHANGED)
        self.assertFalse(verification.backup_state.credential_migrated)

    def test_traditional_hardware_key_with_incrementing_counter_is_accepted(
        self,
    ) -> None:
        verification = self._verify(
            flags_byte=FLAGS_UP,
            sign_count=78,
            current_sign_count=77,
        )

        self.assertEqual(
            verification.credential_device_type,
            CredentialDeviceType.SINGLE_DEVICE,
        )
        self.assertFalse(verification.credential_backed_up)
        self.assertEqual(verification.sign_count.status, SignCountStatus.INCREMENTED)
        self.assertFalse(verification.sign_count.rolled_back)
        self.assertEqual(verification.new_sign_count, 78)

    def test_sign_count_rollback_raises_with_stable_code(self) -> None:
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify(
                flags_byte=FLAGS_UP,
                sign_count=50,
                current_sign_count=77,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.SIGN_COUNT_ROLLED_BACK,
        )

    def test_equal_nonzero_sign_counts_are_rolled_back(self) -> None:
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify(
                flags_byte=FLAGS_UP,
                sign_count=42,
                current_sign_count=42,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.SIGN_COUNT_ROLLED_BACK,
        )

    def test_backup_state_change_is_audited_when_record_matches(self) -> None:
        # Stored record says multi-device but not yet backed up; the response
        # reports the same device type now backed up
        verification = self._verify(
            flags_byte=FLAGS_UP_BE_BS,
            sign_count=1,
            current_sign_count=0,
            expected_credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            expected_credential_backed_up=False,
        )

        self.assertEqual(
            verification.backup_state.change,
            BackupStateChange.BACKUP_STATE_CHANGED,
        )
        self.assertFalse(verification.backup_state.credential_migrated)
        self.assertEqual(verification.backup_state.previous_backed_up, False)
        self.assertTrue(verification.backup_state.new_backed_up)

    def test_backup_state_mismatch_raises_with_stable_code(self) -> None:
        # Stored record says the multi-device credential was backed up, but the
        # response now claims it is not
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify(
                flags_byte=FLAGS_UP_BE,
                sign_count=1,
                current_sign_count=0,
                expected_credential_device_type=CredentialDeviceType.MULTI_DEVICE,
                expected_credential_backed_up=True,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.BACKUP_STATE_MISMATCH,
        )

    def test_single_to_multi_device_migration_is_accepted_and_audited(
        self,
    ) -> None:
        verification = self._verify(
            flags_byte=FLAGS_UP_BE_BS,
            sign_count=0,
            current_sign_count=0,
            expected_credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
            expected_credential_backed_up=False,
        )

        self.assertEqual(
            verification.backup_state.change,
            BackupStateChange.DEVICE_TYPE_CHANGED,
        )
        self.assertTrue(verification.backup_state.credential_migrated)
        self.assertEqual(
            verification.backup_state.previous_device_type,
            CredentialDeviceType.SINGLE_DEVICE,
        )
        self.assertEqual(
            verification.backup_state.new_device_type,
            CredentialDeviceType.MULTI_DEVICE,
        )

    def test_multi_to_single_device_change_raises_mismatch(self) -> None:
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify(
                flags_byte=FLAGS_UP,
                sign_count=1,
                current_sign_count=0,
                expected_credential_device_type=CredentialDeviceType.MULTI_DEVICE,
                expected_credential_backed_up=True,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.DEVICE_TYPE_MISMATCH,
        )

    def test_contradictory_backup_flags_raise_normalized_authentication_error(
        self,
    ) -> None:
        # BS set without BE: impossible per the spec
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify(
                flags_byte=FLAGS_UP | 0b00010000,
                sign_count=1,
                current_sign_count=0,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.INVALID_BACKUP_FLAGS,
        )
        self.assertIsInstance(raised.exception.__cause__, InvalidBackupFlags)

    def test_bad_challenge_raises_stable_code(self) -> None:
        credential = _build_credential(
            private_key=self.private_key,
            rp_id=self.rp_id,
            challenge=self.challenge,
            origin=self.origin,
            flags_byte=FLAGS_UP,
            sign_count=1,
        )

        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            verify_authentication_response(
                credential=credential,
                expected_challenge=b"different-challenge",
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=self.public_key_cbor,
                credential_current_sign_count=0,
            )

        self.assertEqual(raised.exception.code, AuthenticationFailureCode.BAD_CHALLENGE)

    def test_bad_origin_raises_stable_code(self) -> None:
        credential = _build_credential(
            private_key=self.private_key,
            rp_id=self.rp_id,
            challenge=self.challenge,
            origin=self.origin,
            flags_byte=FLAGS_UP,
            sign_count=1,
        )

        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            verify_authentication_response(
                credential=credential,
                expected_challenge=self.challenge,
                expected_rp_id=self.rp_id,
                expected_origin="https://evil.example",
                credential_public_key=self.public_key_cbor,
                credential_current_sign_count=0,
            )

        self.assertEqual(raised.exception.code, AuthenticationFailureCode.BAD_ORIGIN)

    def test_bad_signature_raises_stable_code(self) -> None:
        other_private_key, other_public_key = _generate_es256_credential()
        credential = _build_credential(
            private_key=other_private_key,
            rp_id=self.rp_id,
            challenge=self.challenge,
            origin=self.origin,
            flags_byte=FLAGS_UP,
            sign_count=1,
        )

        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            verify_authentication_response(
                credential=credential,
                expected_challenge=self.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=self.public_key_cbor,
                credential_current_sign_count=0,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.INVALID_SIGNATURE,
        )

    def test_malformed_credential_raises_stable_code(self) -> None:
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            verify_authentication_response(
                credential='{"not": "a valid credential"}',
                expected_challenge=self.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=self.public_key_cbor,
                credential_current_sign_count=0,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.MALFORMED_CREDENTIAL,
        )

    def test_failure_code_default_keeps_backwards_compatibility(self) -> None:
        error = InvalidAuthenticationResponse("legacy message")
        self.assertEqual(error.code, AuthenticationFailureCode.MALFORMED_CREDENTIAL)
        self.assertEqual(str(error), "legacy message")

    def test_backup_state_downgrade_raises_mismatch(self) -> None:
        # Multi-device credential previously backed up, now reporting not backed up
        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify(
                flags_byte=FLAGS_UP_BE,
                sign_count=1,
                current_sign_count=0,
                expected_credential_device_type=CredentialDeviceType.MULTI_DEVICE,
                expected_credential_backed_up=True,
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.BACKUP_STATE_MISMATCH,
        )

    def test_registration_normalizes_contradictory_backup_flags(self) -> None:
        credential = parse_registration_credential_json(
            {
                "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
                "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
                "response": {
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                },
                "type": "public-key",
                "clientExtensionResults": {},
                "transports": ["nfc", "usb"],
            }
        )

        attestation_object = parse_attestation_object(
            credential.response.attestation_object
        )
        # BS set while BE remains unset: an impossible backup flag combination
        attestation_object.auth_data.flags.be = False
        attestation_object.auth_data.flags.bs = True

        with patch(
            "webauthn.registration.verify_registration_response.parse_attestation_object",
            return_value=attestation_object,
        ):
            with self.assertRaises(InvalidRegistrationResponse) as raised:
                verify_registration_response(
                    credential=credential,
                    expected_challenge=base64url_to_bytes(
                        "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
                    ),
                    expected_origin="http://localhost:5000",
                    expected_rp_id="localhost",
                )

        self.assertEqual(
            raised.exception.code,
            RegistrationFailureCode.INVALID_BACKUP_FLAGS,
        )
        self.assertIsInstance(raised.exception.__cause__, InvalidBackupFlags)

    def test_registration_failure_code_default_keeps_backwards_compat(
        self,
    ) -> None:
        error = InvalidRegistrationResponse("legacy message")
        self.assertEqual(error.code, RegistrationFailureCode.MALFORMED_CREDENTIAL)
        self.assertEqual(str(error), "legacy message")
