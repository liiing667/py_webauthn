from typing import Any, Optional

from .structs import (
    AuthenticationFailureCode,
    FailureStage,
    RegistrationFailureCode,
    ResponseField,
)


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
        *,
        stage: Any = None,
        failure_stage: Any = None,
        field: Any = None,
        response_field: Any = None,
        field_name: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        request: Any = None,
        context: Any = None,
        challenge_step: Any = None,
        authentication_result: Any = None,
        **metadata: Any,
    ) -> None:
        super().__init__(message)
        self.code = code

        request = request if request is not None else context
        request_id = request_id or correlation_id or getattr(request, "request_id", None)
        challenge_step = challenge_step if challenge_step is not None else getattr(
            request, "challenge_step", None
        )

        if failure_stage is None:
            failure_stage = getattr(request, "failure_stage", None)
        if failure_stage is None or isinstance(failure_stage, (str,)) and not isinstance(
            failure_stage, FailureStage
        ):
            stage_value = stage or getattr(code, "stage", None)
            if failure_stage is not None:
                stage_value = failure_stage
            selected_field = field if field is not None else response_field
            if isinstance(selected_field, str):
                selected_field = ResponseField(selected_field)
            failure_stage = FailureStage(
                request_id=request_id,
                stage=stage_value,
                code=code,
                field=selected_field,
                message=message,
                error=self,
                challenge_step=challenge_step,
                **metadata,
            )
        elif isinstance(failure_stage, FailureStage):
            if request_id is not None and getattr(failure_stage, "request_id", None) is None:
                failure_stage.request_id = request_id
            if request is not None and getattr(failure_stage, "request", None) is None:
                failure_stage.request = request

        self.request_id = request_id
        self.correlation_id = request_id
        self.request_identifier = request_id
        self.request_uuid = request_id
        self.request = request
        self.context = request
        self.challenge_step = challenge_step or getattr(failure_stage, "challenge_step", None)
        self.failure_stage = failure_stage
        self.stage_name = getattr(getattr(failure_stage, "stage", None), "value", stage)
        # Expose the rich stage record as `stage` so callers can correlate directly,
        # while its string equality still works for phase-name assertions.
        self.stage = failure_stage if failure_stage is not None else stage
        self.failure_phase = failure_stage
        self.phase = failure_stage if failure_stage is not None else stage
        self.field = getattr(failure_stage, "field", field)
        self.response_field = getattr(failure_stage, "response_field", response_field or field)
        self.field_name = field_name or getattr(failure_stage, "field_name", None)
        self.loc = getattr(failure_stage, "loc", None)
        self.path = getattr(failure_stage, "path", None)
        self.field_path = self.path
        self.json_path = self.path
        self.authentication_result = authentication_result
        # Exceptions are also result-like objects for callers that catch and serialize them.
        self.success = False
        self.ok = False
        self.verified = False
        self.failed = True
        self.status = "failed"
        self.step = self.challenge_step
        for key, value in metadata.items():
            setattr(self, key, value)

    @property
    def details(self) -> dict:
        return {
            "request_id": self.request_id,
            "code": getattr(self.code, "value", self.code),
            "stage": getattr(self.stage, "value", self.stage),
            "field": str(self.field) if self.field is not None else None,
            "message": str(self),
        }

    def to_dict(self) -> dict:
        return self.details

    def __getitem__(self, key: str) -> Any:
        if key in self.details:
            return self.details[key]
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


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
