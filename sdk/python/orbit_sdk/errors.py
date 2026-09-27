from __future__ import annotations


class OrbitError(RuntimeError):
    """Safe structured SDK error metadata; server messages and inputs are omitted."""

    def __init__(
        self,
        kind: str,
        code: str,
        request_id: str | None = None,
        status: int = 1,
    ) -> None:
        self.kind = kind
        self.code = code
        self.request_id = request_id
        self.status = status
        super().__init__(self.__str__())

    def __str__(self) -> str:
        detail = f"kind={self.kind}, code={self.code}"
        if self.request_id is not None:
            detail += f", request_id={self.request_id}"
        return f"Orbit SDK operation failed ({detail})"

    def __repr__(self) -> str:
        return str(self)


CONFIGURATION = "configuration"
CANCELLED = "cancelled"
TRANSIENT = "transient"
DENIED = "denied"
INVALID_RESPONSE = "invalid_response"
TRANSPORT_SECURITY = "transport_security"
REAUTHENTICATION_REQUIRED = "reauthentication_required"
STALE_RESPONSE = "stale_response"
STORAGE = "storage"
CLOCK_UNCERTAIN = "clock_uncertain"


def error(kind: str, code: str, request_id: str | None = None) -> OrbitError:
    return OrbitError(kind, code, request_id)


class NotActivatedError(OrbitError):
    """No usable access: the installation has not been activated (or its
    activation no longer provides access). Distinguishable from
    ``FeatureUnavailableError`` without comparing ``code`` strings."""

    def __init__(self, request_id: str | None = None, status: int = 1) -> None:
        super().__init__(DENIED, "access_unavailable", request_id, status)


class FeatureUnavailableError(OrbitError):
    """Activation grants access, but not the requested feature."""

    def __init__(self, request_id: str | None = None, status: int = 1) -> None:
        super().__init__(DENIED, "feature_unavailable", request_id, status)
