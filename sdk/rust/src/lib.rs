//! Orbit v1 key and customer SDK. Check access before each protected operation.
mod access;
mod accounts;
mod app_key;
mod clock;
mod device;
mod diagnostics;
mod grants;
mod installed;
mod offline;
#[cfg(test)]
mod parser_fuzz;
#[cfg(all(
    test,
    feature = "local-development",
    any(target_os = "linux", target_os = "windows", target_os = "macos")
))]
mod sleep_tests;
mod storage;
pub mod transport;

pub use access::{Access, Client, Snapshot};
pub(crate) use access::{Config, Device};
pub use accounts::{
    Account, Customer, CustomerSessionProof, OwnedLicence, OwnedLicences, PendingRegistration,
    Registration,
};
pub use app_key::{AppEnvironment, AppKey};
pub use device::{machine_fingerprint, native_fingerprint};
pub use diagnostics::SupportSummary;
pub use installed::{MachineBinding, Options};
pub use offline::OfflineRequest;
#[cfg(test)]
pub(crate) use storage::MemoryStorage;
pub(crate) use storage::{Storage, StoredCredential};
pub(crate) use transport::Cancellation;
pub use transport::Transport;

#[derive(Clone)]
pub enum Error {
    Configuration,
    Cancelled,
    Transient {
        code: Option<String>,
        request_id: Option<String>,
    },
    Denied {
        code: String,
        request_id: Option<String>,
    },
    NotActivated,
    FeatureUnavailable,
    InvalidResponse,
    TransportSecurity,
    ReauthenticationRequired,
    StaleResponse,
    Storage,
    ClockUncertain,
    InstallationInUse,
    CorruptState,
    PendingActivation,
    Closed,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "Invalid Orbit configuration",
            Self::Cancelled => "Operation cancelled",
            Self::Transient { .. } => self
                .guidance()
                .unwrap_or("Orbit is temporarily unreachable. Try again later."),
            Self::Denied { .. } => self
                .guidance()
                .unwrap_or("Orbit denied access. Contact application support."),
            Self::NotActivated => "Activate a licence to continue.",
            Self::FeatureUnavailable => "This licence does not include the requested feature.",
            Self::InvalidResponse => "Orbit response verification failed",
            Self::TransportSecurity => "Secure connection failed",
            Self::ReauthenticationRequired => "Fresh licence authentication is required",
            Self::StaleResponse => "Discarded a superseded response",
            Self::Storage => "Credential storage failed",
            Self::ClockUncertain => "Online clock validation is required",
            Self::InstallationInUse => "This installation is already open; share one client and do not delete its lock",
            Self::CorruptState => "Installed state is missing or corrupt; restore a trusted backup or deliberately choose a new state directory",
            Self::PendingActivation => "An activation is unresolved; retry the same input within 24 hours or explicitly resolve it",
            Self::Closed => "The Orbit client is closed",
        })
    }
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
