from typing import Any, Dict

from .exceptions import InvalidAttestationObjectStructure
from .structs import AttestationStatement


def parse_attestation_statement(val: Dict[str, Any]) -> AttestationStatement:
    """
    Turn `response.attestationObject.attStmt` into structured data
    """
    if not isinstance(val, dict):
        raise InvalidAttestationObjectStructure("attStmt was not a CBOR map")

    attestation_statement = AttestationStatement()

    known_fields = {
        "sig",
        "x5c",
        "response",
        "alg",
        "ver",
        "certInfo",
        "pubArea",
    }
    unexpected_fields = [field for field in val if field not in known_fields]
    if unexpected_fields:
        raise InvalidAttestationObjectStructure(
            f"attStmt contained unexpected field(s): {unexpected_fields}"
        )

    # Populate optional fields that may exist in the attestation statement
    if "sig" in val:
        if not isinstance(val["sig"], (bytes, bytearray, memoryview)):
            raise InvalidAttestationObjectStructure("attStmt sig was not a byte string")
        if not val["sig"]:
            raise InvalidAttestationObjectStructure("attStmt sig was empty")
        attestation_statement.sig = bytes(val["sig"])
    if "x5c" in val:
        if not isinstance(val["x5c"], (list, tuple)):
            raise InvalidAttestationObjectStructure("attStmt x5c was not an array")
        if not val["x5c"]:
            raise InvalidAttestationObjectStructure("attStmt x5c was empty")
        for cert in val["x5c"]:
            if not isinstance(cert, (bytes, bytearray, memoryview)):
                raise InvalidAttestationObjectStructure(
                    "attStmt x5c contained a value that was not a byte string"
                )
            if not cert:
                raise InvalidAttestationObjectStructure(
                    "attStmt x5c contained an empty certificate"
                )
        attestation_statement.x5c = [bytes(cert) for cert in val["x5c"]]
    if "response" in val:
        if not isinstance(val["response"], (bytes, bytearray, memoryview)):
            raise InvalidAttestationObjectStructure(
                "attStmt response was not a byte string"
            )
        if not val["response"]:
            raise InvalidAttestationObjectStructure("attStmt response was empty")
        attestation_statement.response = bytes(val["response"])
    if "alg" in val:
        if not isinstance(val["alg"], int) or isinstance(val["alg"], bool):
            raise InvalidAttestationObjectStructure("attStmt alg was not an integer")
        attestation_statement.alg = val["alg"]
    if "ver" in val:
        if not isinstance(val["ver"], str):
            raise InvalidAttestationObjectStructure("attStmt ver was not a string")
        attestation_statement.ver = val["ver"]
    if "certInfo" in val:
        if not isinstance(val["certInfo"], (bytes, bytearray, memoryview)):
            raise InvalidAttestationObjectStructure(
                "attStmt certInfo was not a byte string"
            )
        if not val["certInfo"]:
            raise InvalidAttestationObjectStructure("attStmt certInfo was empty")
        attestation_statement.cert_info = bytes(val["certInfo"])
    if "pubArea" in val:
        if not isinstance(val["pubArea"], (bytes, bytearray, memoryview)):
            raise InvalidAttestationObjectStructure(
                "attStmt pubArea was not a byte string"
            )
        if not val["pubArea"]:
            raise InvalidAttestationObjectStructure("attStmt pubArea was empty")
        attestation_statement.pub_area = bytes(val["pubArea"])

    return attestation_statement
