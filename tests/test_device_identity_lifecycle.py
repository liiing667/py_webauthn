import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest import TestCase

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from webauthn import (
    ChallengeLedger,
    DeviceIdentityMismatchError,
    DeviceIdentityRegistry,
    IdentityConsistencyStatus,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, encode_cbor
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.known_root_certs import google_hardware_attestation_root_2
from webauthn.helpers.structs import (
    AuthenticationFailureCode,
    RegistrationFailureCode,
)
from webauthn.registration.formats.android_key import is_known_android_key_root


RP_ID = "device.example"
ORIGIN = "https://device.example"
CREDENTIAL_ID = b"stable-device-credential-id"


def _cose_public_key(private_key):
    numbers = private_key.public_key().public_numbers()
    return encode_cbor(
        {
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # curve: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        }
    )


def _registration_credential(*, challenge: bytes, private_key, flags: int = 0x41):
    rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
    cose_key = _cose_public_key(private_key)
    attested_data = (
        b"\x00" * 16
        + len(CREDENTIAL_ID).to_bytes(2, "big")
        + CREDENTIAL_ID
        + cose_key
    )
    authenticator_data = (
        rp_id_hash + bytes([flags]) + (0).to_bytes(4, "big") + attested_data
    )
    attestation_object = encode_cbor(
        {"fmt": "none", "attStmt": {}, "authData": authenticator_data}
    )
    client_data_json = json.dumps(
        {
            "type": "webauthn.create",
            "challenge": bytes_to_base64url(challenge),
            "origin": ORIGIN,
        },
        separators=(",", ":"),
    ).encode()

    credential_b64 = bytes_to_base64url(CREDENTIAL_ID)
    return {
        "id": credential_b64,
        "rawId": credential_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "attestationObject": bytes_to_base64url(attestation_object),
        },
    }


def _authentication_credential(
    *,
    challenge: bytes,
    private_key,
    flags: int,
    sign_count: int,
):
    rp_id_hash = hashlib.sha256(RP_ID.encode()).digest()
    authenticator_data = rp_id_hash + bytes([flags]) + sign_count.to_bytes(4, "big")
    client_data_json = json.dumps(
        {
            "type": "webauthn.get",
            "challenge": bytes_to_base64url(challenge),
            "origin": ORIGIN,
        },
        separators=(",", ":"),
    ).encode()
    signature_base = authenticator_data + hashlib.sha256(client_data_json).digest()
    signature = private_key.sign(signature_base, ec.ECDSA(hashes.SHA256()))
    credential_b64 = bytes_to_base64url(CREDENTIAL_ID)

    return {
        "id": credential_b64,
        "rawId": credential_b64,
        "type": "public-key",
        "response": {
            "clientDataJSON": bytes_to_base64url(client_data_json),
            "authenticatorData": bytes_to_base64url(authenticator_data),
            "signature": bytes_to_base64url(signature),
        },
    }


class DeviceIdentityLifecycleTests(TestCase):
    def _verify_registration(self, challenge, private_key, ledger, scope):
        return verify_registration_response(
            credential=_registration_credential(
                challenge=challenge,
                private_key=private_key,
            ),
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            challenge_ledger=ledger,
            challenge_scope=scope,
        )

    def _verify_login(
        self,
        challenge,
        private_key,
        ledger,
        scope,
        *,
        count,
        flags=0x01,
        public_key=None,
    ):
        cose_key = public_key or _cose_public_key(private_key)
        return verify_authentication_response(
            credential=_authentication_credential(
                challenge=challenge,
                private_key=private_key,
                flags=flags,
                sign_count=count,
            ),
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=cose_key,
            credential_current_sign_count=max(0, count - 1),
            challenge_ledger=ledger,
            challenge_scope=scope,
        )

    def test_registration_login_and_recovery_keep_same_device_identity(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        ledger = ChallengeLedger()
        scope = "account:user-1"

        registration_challenge = ledger.issue(scope=scope)
        registration = self._verify_registration(
            registration_challenge, private_key, ledger, scope
        )

        self.assertIsNotNone(registration.device_identity)
        self.assertEqual(registration.device_identity.credential_id, CREDENTIAL_ID)
        self.assertIsNotNone(registration.device_provenance)
        self.assertEqual(
            registration.device_provenance.attestation_format, "none"
        )

        registry = DeviceIdentityRegistry()
        record = registry.bind_registration("user-1", registration)
        original_digest = record.identity.identity_digest

        login_challenge = ledger.issue(scope=scope)
        login = self._verify_login(
            login_challenge, private_key, ledger, scope, count=1
        )

        self.assertEqual(login.device_identity.identity_digest, original_digest)
        login_report = registry.verify_login("user-1", login)
        self.assertTrue(login_report.consistent)
        self.assertEqual(
            login_report.status, IdentityConsistencyStatus.CONSISTENT
        )

        recovery_challenge = ledger.issue(scope=scope)
        recovery = self._verify_login(
            recovery_challenge,
            private_key,
            ledger,
            scope,
            count=2,
            flags=0x19,  # UP + BE + BS
        )

        recovery_report = registry.recover_device("user-1", recovery)
        recovery_report.require_consistent()

        self.assertEqual(
            recovery_report.status, IdentityConsistencyStatus.RECOVERED
        )
        self.assertTrue(recovery_report.recovery)
        self.assertEqual(
            recovery_report.stored_identity.identity_digest, original_digest
        )
        self.assertEqual(recovery.device_identity.identity_digest, original_digest)
        self.assertTrue(
            any(
                change.startswith("credential_device_type:")
                for change in recovery_report.changes
            )
        )
        self.assertEqual(record.credential_device_type, "multi_device")
        self.assertEqual(record.recovery_count, 1)

        audit = registry.audit_account("user-1")[0]
        self.assertEqual(audit["identity"]["identity_digest"], original_digest)
        self.assertEqual(audit["provenance"]["attestation_format"], "none")
        self.assertEqual(
            audit["provenance"]["aaguid"],
            "00000000-0000-0000-0000-000000000000",
        )
        self.assertEqual(
            [event["event"] for event in audit["events"]],
            ["registered", "authenticated", "recovered"],
        )

    def test_replayed_registration_challenge_is_rejected(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        ledger = ChallengeLedger()
        scope = "account:user-1"
        challenge = ledger.issue(scope=scope)

        first = self._verify_registration(
            challenge, private_key, ledger, scope
        )
        self.assertEqual(first.credential_id, CREDENTIAL_ID)

        with self.assertRaises(InvalidRegistrationResponse) as raised:
            self._verify_registration(challenge, private_key, ledger, scope)

        self.assertEqual(
            raised.exception.code,
            RegistrationFailureCode.CHALLENGE_REPLAYED,
        )
        self.assertIn("already been used", str(raised.exception))

    def test_replayed_authentication_challenge_is_rejected(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        ledger = ChallengeLedger()
        scope = "account:user-1"
        challenge = ledger.issue(scope=scope)
        login = self._verify_login(
            challenge, private_key, ledger, scope, count=1
        )
        self.assertEqual(login.credential_id, CREDENTIAL_ID)

        with self.assertRaises(InvalidAuthenticationResponse) as raised:
            self._verify_login(
                challenge, private_key, ledger, scope, count=1
            )

        self.assertEqual(
            raised.exception.code,
            AuthenticationFailureCode.CHALLENGE_REPLAYED,
        )

    def test_challenge_cannot_be_used_for_another_account_scope(self):
        ledger = ChallengeLedger()
        attacker_challenge = ledger.issue(scope="account:attacker")

        with self.assertRaises(InvalidRegistrationResponse) as raised:
            verify_registration_response(
                credential=_registration_credential(
                    challenge=attacker_challenge,
                    private_key=ec.generate_private_key(ec.SECP256R1()),
                ),
                expected_challenge=attacker_challenge,
                expected_rp_id=RP_ID,
                expected_origin=ORIGIN,
                challenge_ledger=ledger,
                challenge_scope="account:victim",
            )

        self.assertEqual(
            raised.exception.code,
            RegistrationFailureCode.CHALLENGE_SCOPE_MISMATCH,
        )

    def test_same_credential_id_with_new_public_key_is_identity_mismatch(self):
        original_key = ec.generate_private_key(ec.SECP256R1())
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        ledger = ChallengeLedger()
        scope = "account:user-1"

        registration_challenge = ledger.issue(scope=scope)
        registration = self._verify_registration(
            registration_challenge, original_key, ledger, scope
        )
        record = DeviceIdentityRegistry().bind_registration(
            "user-1", registration
        )

        login_challenge = ledger.issue(scope=scope)
        wrong_key_login = self._verify_login(
            login_challenge,
            attacker_key,
            ledger,
            scope,
            count=1,
            public_key=_cose_public_key(attacker_key),
        )

        report = record.observe(wrong_key_login)
        self.assertFalse(report.consistent)
        self.assertEqual(report.status, IdentityConsistencyStatus.MISMATCH)
        self.assertIn("public key", report.reason)

        with self.assertRaises(Exception):
            report.require_consistent()

    def test_registry_refuses_to_overwrite_bound_device_identity(self):
        original_key = ec.generate_private_key(ec.SECP256R1())
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        ledger = ChallengeLedger()
        scope = "account:user-1"

        registration = self._verify_registration(
            ledger.issue(scope=scope), original_key, ledger, scope
        )
        registry = DeviceIdentityRegistry()
        registry.bind_registration("user-1", registration)

        forged_registration = self._verify_registration(
            ledger.issue(scope=scope), attacker_key, ledger, scope
        )
        with self.assertRaises(DeviceIdentityMismatchError):
            registry.bind_registration("user-1", forged_registration)

        with self.assertRaises(DeviceIdentityMismatchError):
            registry.bind_registration("user-2", registration)

    def test_forged_android_root_is_not_known_trust_anchor(self):
        attacker_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME, "Totally Google Hardware Root"
                )
            ]
        )
        now = datetime.now(timezone.utc)
        forged_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(attacker_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(attacker_key, hashes.SHA256())
        )
        forged_pem = forged_cert.public_bytes(serialization.Encoding.PEM)

        self.assertFalse(is_known_android_key_root(forged_pem))
        self.assertTrue(is_known_android_key_root(google_hardware_attestation_root_2))
        self.assertTrue(is_known_android_key_root(forged_pem, [forged_pem]))
