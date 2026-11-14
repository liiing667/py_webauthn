class WebAuthnException(Exception):
    pass


class InvalidRegistrationOptions(WebAuthnException):
    pass


class InvalidRegistrationResponse(WebAuthnException):
    pass


class InvalidAuthenticationOptions(WebAuthnException):
    pass


class InvalidAuthenticationResponse(WebAuthnException):
    pass


class InvalidCrossOriginCeremony(WebAuthnException):
    """A cross-origin ceremony was rejected by the top-origin policy"""

    pass


class InvalidCrossOriginRegistrationResponse(
    InvalidRegistrationResponse, InvalidCrossOriginCeremony
):
    pass


class InvalidCrossOriginAuthenticationResponse(
    InvalidAuthenticationResponse, InvalidCrossOriginCeremony
):
    pass


class InvalidPublicKeyStructure(WebAuthnException):
    pass


class UnsupportedPublicKeyType(WebAuthnException):
    pass


class InvalidJSONStructure(WebAuthnException):
    pass


class InvalidAuthenticatorDataStructure(WebAuthnException):
    pass


class SignatureVerificationException(WebAuthnException):
    pass


class UnsupportedAlgorithm(WebAuthnException):
    pass


class UnsupportedPublicKey(WebAuthnException):
    pass


class UnsupportedEC2Curve(WebAuthnException):
    pass


class InvalidTPMPubAreaStructure(WebAuthnException):
    pass


class InvalidTPMCertInfoStructure(WebAuthnException):
    pass


class InvalidCertificateChain(WebAuthnException):
    pass


class InvalidBackupFlags(WebAuthnException):
    pass


class InvalidCBORData(WebAuthnException):
    pass


class InvalidAttestationObjectStructure(WebAuthnException):
    pass
