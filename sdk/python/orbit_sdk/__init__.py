"""Native Python SDK for the Orbit installed-client protocol."""

from .app_key import AppKey
from .client import (
    AccessStatus,
    Account,
    Cancellation,
    Client,
    DeviceBinding,
    OwnedLicence,
    OwnedLicencePage,
    PendingRegistration,
    RegistrationResult,
    SensitiveAuthorization,
    Snapshot,
    SessionMetadata,
    StorageMode,
)
from .device import installation_id_new, machine_fingerprint, native_fingerprint
from .downloads import DownloadTicket, DownloadTicketVerifier
from .errors import AppVersionUnsupportedError, FeatureUnavailableError, NotActivatedError, OrbitError
from .offline import OfflineRequest
from .online import (Artifact, Release, Update, UpdateTarget, DownloadAuthorization, UsageCounter,
                     UsageConsumption, ResourceCounter, ResourceAllocation, UsageLimit, ResourceLimit,
                     LimitReachedError, MutationUncertainError)
from .download_file import download_file

__all__ = [
    "AccessStatus",
    "Account",
    "AppKey",
    "AppVersionUnsupportedError",
    "Cancellation",
    "Client",
    "DeviceBinding",
    "DownloadTicket",
    "DownloadTicketVerifier",
    "FeatureUnavailableError",
    "NotActivatedError",
    "OrbitError",
    "OfflineRequest",
    "OwnedLicence",
    "OwnedLicencePage",
    "PendingRegistration",
    "RegistrationResult",
    "SensitiveAuthorization",
    "Snapshot",
    "SessionMetadata",
    "StorageMode",
    "installation_id_new",
    "machine_fingerprint",
    "native_fingerprint",
    "Artifact", "Release", "Update", "UpdateTarget", "DownloadAuthorization", "UsageCounter",
    "UsageConsumption", "ResourceCounter", "ResourceAllocation", "UsageLimit", "ResourceLimit",
    "LimitReachedError", "MutationUncertainError", "download_file",
]
