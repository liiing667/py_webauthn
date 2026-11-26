from typing import Any, Dict, Union
from dataclasses import dataclass

from .byteslike_to_bytes import byteslike_to_bytes
from .cose import COSECRV, COSEKTY, COSEAlgorithmIdentifier, COSEKey
from .exceptions import InvalidPublicKeyStructure, UnsupportedPublicKeyType
from .parse_cbor import parse_cbor


@dataclass
class DecodedOKPPublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    crv: COSECRV
    x: bytes


@dataclass
class DecodedEC2PublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    crv: COSECRV
    x: bytes
    y: bytes


@dataclass
class DecodedRSAPublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    n: bytes
    e: bytes


@dataclass
class DecodedMLDSAPublicKey:
    kty: COSEKTY
    alg: COSEAlgorithmIdentifier
    pub: bytes


_EC2_SIGNATURE_ALGORITHMS = {
    COSEAlgorithmIdentifier.ECDSA_SHA_256.value,
    COSEAlgorithmIdentifier.ECDSA_SHA_512.value,
}

_RSA_SIGNATURE_ALGORITHMS = {
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_1.value,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256.value,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384.value,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512.value,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256.value,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384.value,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512.value,
}

_EC2_COORDINATE_LENGTHS_BY_CURVE = {
    COSECRV.P256.value: 32,
    COSECRV.P384.value: 48,
    COSECRV.P521.value: 66,
}

_ML_DSA_PUBLIC_KEY_LENGTHS_BY_ALG = {
    COSEAlgorithmIdentifier.ML_DSA_44.value: 1312,
    COSEAlgorithmIdentifier.ML_DSA_65.value: 1952,
    COSEAlgorithmIdentifier.ML_DSA_87.value: 2592,
}


def _get_cose_value(
    decoded_key: Dict[Any, Any],
    cose_key: COSEKey,
    label: str,
) -> Any:
    """Look up a COSE key field, requiring an integer key and a unique match.

    Python treats booleans and floats as equivalent to certain integers for dict
    lookups (e.g. ``True == 1``). Requiring an actual integer key keeps a malformed
    map from being interpreted differently depending on which representation an
    authenticator used.
    """
    matches = [
        map_key
        for map_key in decoded_key
        if isinstance(map_key, int)
        and not isinstance(map_key, bool)
        and map_key == cose_key.value
    ]

    if not matches:
        raise InvalidPublicKeyStructure(f"Credential public key missing {label}")
    if len(matches) > 1:
        raise InvalidPublicKeyStructure(f"Credential public key had duplicate {label}")

    return decoded_key[matches[0]]


def _get_int_value(
    decoded_key: Dict[Any, Any],
    cose_key: COSEKey,
    label: str,
) -> int:
    value = _get_cose_value(decoded_key, cose_key, label)

    # bool is a subclass of int in Python; CBOR booleans are not valid COSE
    # identifiers.
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidPublicKeyStructure(f"Credential public key {label} was not an integer")

    return value


def _get_bytes_value(
    decoded_key: Dict[Any, Any],
    cose_key: COSEKey,
    label: str,
) -> bytes:
    value = _get_cose_value(decoded_key, cose_key, label)

    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise InvalidPublicKeyStructure(
            f"Credential public key {label} was not a byte string"
        )

    value = bytes(value)
    if not value:
        raise InvalidPublicKeyStructure(f"Credential public key missing {label}")

    return value


def decode_credential_public_key(
    key: bytes,
) -> Union[DecodedOKPPublicKey, DecodedEC2PublicKey, DecodedRSAPublicKey, DecodedMLDSAPublicKey]:
    """
    Decode a CBOR-encoded public key and turn it into a data structure.

    Supports OKP, EC2, RSA, and ML-DSA public keys.
    """
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise InvalidPublicKeyStructure("Credential public key was not a byte string")

    key = byteslike_to_bytes(key)
    if not key:
        raise InvalidPublicKeyStructure("Credential public key was empty")

    # Occasionally we might be given a public key in an "uncompressed" format,
    # typically from older U2F security keys. As per the FIDO spec this is indicated by
    # a leading 0x04 "uncompressed point compression method" format byte. In that case
    # we need to fill in some blanks to turn it into a full EC2 key for signature
    # verification
    #
    # See https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#public-key-representation-formats
    if key[0] == 0x04:
        # An uncompressed P-256 point is exactly 0x04 followed by 32-byte X and
        # 32-byte Y coordinates. Slicing a shorter value would silently produce an
        # incomplete key that can only fail later, during authentication.
        if len(key) != 65:
            raise InvalidPublicKeyStructure(
                "Uncompressed EC2 credential public key was not 65 bytes"
            )

        return DecodedEC2PublicKey(
            kty=COSEKTY.EC2,
            alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
            crv=COSECRV.P256,
            x=key[1:33],
            y=key[33:65],
        )

    decoded_key = parse_cbor(key)

    # A COSE key is a CBOR map. Rejecting other CBOR types is important because a
    # list, for example, would otherwise be indexed positionally by the integer
    # COSE key identifiers below.
    if not isinstance(decoded_key, dict):
        raise InvalidPublicKeyStructure("Credential public key was not a CBOR map")

    kty = _get_int_value(decoded_key, COSEKey.KTY, "kty")
    alg = _get_int_value(decoded_key, COSEKey.ALG, "alg")

    if kty == COSEKTY.OKP.value:
        crv = _get_int_value(decoded_key, COSEKey.CRV, "crv")
        x = _get_bytes_value(decoded_key, COSEKey.X, "x")

        if crv != COSECRV.ED25519.value:
            raise InvalidPublicKeyStructure(f"Unsupported OKP credential public key curve {crv}")
        if alg != COSEAlgorithmIdentifier.EDDSA.value:
            raise InvalidPublicKeyStructure(
                f"OKP credential public key used unexpected algorithm {alg}"
            )
        if len(x) != 32:
            raise InvalidPublicKeyStructure(
                f"OKP credential public key x coordinate was {len(x)} bytes, expected 32"
            )

        return DecodedOKPPublicKey(
            kty=COSEKTY.OKP,
            alg=COSEAlgorithmIdentifier.EDDSA,
            crv=COSECRV.ED25519,
            x=x,
        )
    elif kty == COSEKTY.EC2.value:
        crv = _get_int_value(decoded_key, COSEKey.CRV, "crv")
        x = _get_bytes_value(decoded_key, COSEKey.X, "x")
        y = _get_bytes_value(decoded_key, COSEKey.Y, "y")

        coordinate_length = _EC2_COORDINATE_LENGTHS_BY_CURVE.get(crv)
        if coordinate_length is None:
            raise InvalidPublicKeyStructure(
                f"Unsupported EC2 credential public key curve {crv}"
            )
        if alg not in _EC2_SIGNATURE_ALGORITHMS:
            raise InvalidPublicKeyStructure(
                f"EC2 credential public key used unexpected algorithm {alg}"
            )
        if len(x) != coordinate_length or len(y) != coordinate_length:
            raise InvalidPublicKeyStructure(
                "EC2 credential public key coordinates did not match its curve"
            )

        return DecodedEC2PublicKey(
            kty=COSEKTY.EC2,
            alg=COSEAlgorithmIdentifier(alg),
            crv=COSECRV(crv),
            x=x,
            y=y,
        )
    elif kty == COSEKTY.RSA.value:
        n = _get_bytes_value(decoded_key, COSEKey.N, "n")
        e = _get_bytes_value(decoded_key, COSEKey.E, "e")

        if alg not in _RSA_SIGNATURE_ALGORITHMS:
            raise InvalidPublicKeyStructure(
                f"RSA credential public key used unexpected algorithm {alg}"
            )

        return DecodedRSAPublicKey(
            kty=COSEKTY.RSA,
            alg=COSEAlgorithmIdentifier(alg),
            n=n,
            e=e,
        )
    elif kty == COSEKTY.ML_DSA.value:
        pub = _get_bytes_value(decoded_key, COSEKey.PUB, "pub")

        expected_public_key_length = _ML_DSA_PUBLIC_KEY_LENGTHS_BY_ALG.get(alg)
        if expected_public_key_length is None:
            raise InvalidPublicKeyStructure(
                f"ML-DSA credential public key used unexpected algorithm {alg}"
            )
        if len(pub) != expected_public_key_length:
            raise InvalidPublicKeyStructure(
                f"ML-DSA credential public key was {len(pub)} bytes, "
                f"expected {expected_public_key_length}"
            )

        return DecodedMLDSAPublicKey(
            kty=COSEKTY.ML_DSA,
            alg=COSEAlgorithmIdentifier(alg),
            pub=pub,
        )

    raise UnsupportedPublicKeyType(f'Unsupported credential public key type "{kty}"')
