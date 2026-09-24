//! Orbit v1 key and customer SDK. Check access before each protected operation.
mod access;
mod accounts;
mod clock;
mod device;
mod diagnostics;
mod grants;
#[cfg(test)]
mod parser_fuzz;
mod setup;
#[cfg(all(
    test,
    feature = "local-development",
    any(target_os = "linux", target_os = "windows")
))]
mod sleep_tests;
mod storage;
pub mod transport;

pub use access::{Access, Client, Config, Device, Snapshot};
pub use accounts::{
    Account, Customer, CustomerSessionProof, OwnedLicence, OwnedLicences, PendingRegistration,
    Registration,
};
pub use device::{machine_fingerprint, native_fingerprint};
pub use diagnostics::SupportSummary;
pub use setup::Setup;
pub use storage::{MemoryStorage, SecretServiceStorage, Storage, StoredCredential, WindowsStorage};
pub use transport::{Cancellation, Transport};

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
    InvalidResponse,
    TransportSecurity,
    ReauthenticationRequired,
    StaleResponse,
    Storage,
    ClockUncertain,
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
            Self::InvalidResponse => "Orbit response verification failed",
            Self::TransportSecurity => "Secure connection failed",
            Self::ReauthenticationRequired => "Fresh licence authentication is required",
            Self::StaleResponse => "Discarded a superseded response",
            Self::Storage => "Credential storage failed",
            Self::ClockUncertain => "Online clock validation is required",
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
