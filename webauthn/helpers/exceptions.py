from .structs import AuthenticationFailureCode, RegistrationFailureCode


class WebAuthnException(Exception):
    pass


class InvalidRegistrationOptions(WebAuthnException):
    pass


class InvalidRegistrationResponse(WebAuthnException):
    """A registration response could not be verified

    Attributes:
        `code`: A stable, machine-readable `RegistrationFailureCode` describing why
          verification failed. Defaults to `RegistrationFailureCode.MALFORMED_CREDENTIAL`
          for backwards-compatible callers that construct this exception directly.
    """

    def __init__(
        self,
        message: str,
        code: RegistrationFailureCode = RegistrationFailureCode.MALFORMED_CREDENTIAL,
    ) -> None:
        super().__init__(message)
        self.code = code


class InvalidAuthenticationOptions(WebAuthnException):
    pass


class InvalidAuthenticationResponse(WebAuthnException):
    """An authentication response could not be verified

    Attributes:
        `code`: A stable, machine-readable `AuthenticationFailureCode` describing why
          verification failed. Defaults to `AuthenticationFailureCode.MALFORMED_CREDENTIAL`
          for backwards-compatible callers that construct this exception directly.
    """

    def __init__(
        self,
        message: str,
        code: AuthenticationFailureCode = AuthenticationFailureCode.MALFORMED_CREDENTIAL,
    ) -> None:
        super().__init__(message)
        self.code = code


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
