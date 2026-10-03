//! Command-line syntax. Handlers live in the command modules.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "orbit",
    version,
    about = "Manage Orbit licences and releases with a management token"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args)]
#[command(next_help_heading = "Global options")]
pub struct Global {
    /// Named credential profile [env: ORBIT_PROFILE] [default: default]
    #[arg(long, global = true, value_name = "NAME")]
    pub profile: Option<String>,
    /// Orbit API origin [env: ORBIT_API_URL]
    #[arg(long, global = true, value_name = "URL")]
    pub api_url: Option<String>,
    /// Application ID [env: ORBIT_APPLICATION_ID]
    #[arg(long, global = true, value_name = "ID")]
    pub application_id: Option<String>,
    /// Environment ID [env: ORBIT_ENVIRONMENT_ID]
    #[arg(long, global = true, value_name = "ID")]
    pub environment_id: Option<String>,
    /// Print the API response JSON unchanged
    #[arg(long, global = true)]
    pub json: bool,
    /// Idempotency key for a retry of an earlier operation
    #[arg(long, global = true, value_name = "KEY")]
    pub idempotency_key: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Store, inspect or remove the management token
    #[command(subcommand)]
    Credentials(Credentials),
    /// List and create licence policy versions
    #[command(subcommand)]
    Policies(Policies),
    /// Manage licences
    #[command(subcommand, alias = "licenses")]
    Licences(Licences),
    /// Manage releases and their downloadable files
    #[command(subcommand)]
    Releases(Releases),
}

#[derive(Subcommand)]
pub enum Credentials {
    /// Save a management token read from standard input or a hidden prompt
    Set,
    /// Show the active credentials with the token redacted
    Show,
    /// Delete the saved profile
    Remove,
}

#[derive(Subcommand)]
pub enum Policies {
    /// List the latest policy versions
    List,
    /// Create a policy, or a new version of one with the same name
    Create(Box<PolicyTerms>),
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Expiry {
    Perpetual,
    Fixed,
    FirstActivation,
}

#[derive(Args)]
pub struct PolicyTerms {
    /// Start from this policy version's terms; other flags change them
    #[arg(long, value_name = "POLICY_ID")]
    pub from: Option<String>,
    /// Policy name; an existing name creates that policy's next version
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, value_enum)]
    pub expiry: Option<Expiry>,
    /// Licence lifetime from first activation, such as 30d
    #[arg(long, value_name = "DURATION")]
    pub duration: Option<String>,
    /// Fixed expiry time (RFC 3339)
    #[arg(long, value_name = "TIME")]
    pub expires_at: Option<String>,
    /// Devices each licence may activate
    #[arg(long, value_name = "N")]
    pub device_limit: Option<i32>,
    #[arg(long, value_name = "BOOL", action = clap::ArgAction::Set)]
    pub hwid_locked: Option<bool>,
    /// Allow offline use between check-ins
    #[arg(long, value_name = "BOOL", action = clap::ArgAction::Set)]
    pub offline: Option<bool>,
    /// How long a device may stay offline, such as 12h
    #[arg(long, value_name = "DURATION")]
    pub offline_allowance: Option<String>,
    /// Longest offline file validity, such as 180d, or 0 for no offline files
    #[arg(long, value_name = "DURATION")]
    pub offline_file_allowance: Option<String>,
    /// Concurrent floating sessions per licence, or 0 for no limit
    #[arg(long, value_name = "N")]
    pub concurrent_sessions: Option<i32>,
    /// Entitlement to include, as NAME or NAME=false to include it turned off
    #[arg(long, value_name = "NAME[=BOOL]")]
    pub entitlement: Vec<String>,
    /// Entitlement to leave out of the copied terms
    #[arg(long, value_name = "NAME")]
    pub remove_entitlement: Vec<String>,
}

#[derive(Args)]
pub struct Reason {
    /// Audit reason recorded with the change
    #[arg(long)]
    pub reason: String,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SearchStatus {
    Active,
    Revoked,
    All,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SessionState {
    Active,
    Ended,
    Expired,
}

#[derive(Subcommand)]
pub enum Licences {
    /// Search licences by ID, key, key suffix or reference
    #[command(alias = "search")]
    List {
        /// Licence ID, full key, key suffix or reference text
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long, value_enum)]
        status: Option<SearchStatus>,
        /// Cursor from the previous page
        #[arg(long)]
        after: Option<String>,
    },
    /// Show one licence
    Show { licence: String },
    /// Move licences to another policy version after a preview
    ChangePolicy {
        /// Target policy version ID
        #[arg(long, value_name = "POLICY_ID")]
        policy: String,
        #[command(flatten)]
        reason: Reason,
        /// Apply without the confirmation prompt
        #[arg(long)]
        yes: bool,
        #[arg(required = true, value_name = "LICENCE_ID")]
        licences: Vec<String>,
    },
    /// Issue licences from a policy and print their keys once
    Issue {
        /// Policy version ID
        #[arg(long)]
        policy: String,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(i32).range(1..=100))]
        quantity: i32,
        #[arg(long, default_value = "")]
        reference: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Suspend a licence
    Suspend {
        licence: String,
        #[command(flatten)]
        reason: Reason,
    },
    /// Re-enable a suspended licence
    Reinstate {
        licence: String,
        #[command(flatten)]
        reason: Reason,
    },
    /// Permanently revoke a licence
    Revoke {
        licence: String,
        #[command(flatten)]
        reason: Reason,
        /// Confirm that revocation cannot be undone
        #[arg(long)]
        yes: bool,
    },
    /// Extend a licence's expiry
    Extend {
        licence: String,
        /// Duration such as 30d, 12h, 90m or 3600s
        #[arg(long, value_name = "DURATION")]
        by: String,
        #[command(flatten)]
        reason: Reason,
    },
    /// Turn entitlements on or off for one licence
    Entitlements {
        licence: String,
        #[arg(long, value_name = "NAME")]
        enable: Vec<String>,
        #[arg(long, value_name = "NAME")]
        disable: Vec<String>,
        #[command(flatten)]
        reason: Reason,
    },
    /// Change a licence's reference or note
    Annotate {
        licence: String,
        #[arg(long)]
        reference: Option<String>,
        #[arg(long)]
        note: Option<String>,
        #[command(flatten)]
        reason: Reason,
    },
    /// List a licence's registered devices
    Devices {
        licence: String,
        #[arg(long)]
        after: Option<String>,
    },
    /// Release one device from a licence
    ResetDevice {
        licence: String,
        /// Activation ID from `orbit licences devices`
        activation: String,
        #[command(flatten)]
        reason: Reason,
    },
    /// Replace a licence key and print the new key once
    ReplaceKey {
        licence: String,
        #[command(flatten)]
        reason: Reason,
    },
    /// List a licence's floating sessions
    Sessions {
        licence: String,
        #[arg(long, value_enum)]
        state: Option<SessionState>,
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=100))]
        limit: Option<u8>,
        #[arg(long)]
        after: Option<String>,
    },
    /// End one floating session
    EndSession {
        licence: String,
        session: String,
        #[command(flatten)]
        reason: Reason,
    },
    /// Issue a signed offline file for an exported offline request
    OfflineFile {
        licence: String,
        /// Request file exported by the installed SDK
        #[arg(long, value_name = "PATH")]
        request: PathBuf,
        /// Validity such as 180d (1d to 366d)
        #[arg(long, value_name = "DURATION")]
        duration: String,
        /// Destination for the signed file; must not exist
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Delivery {
    /// Anyone holding the URL can download
    Public,
    /// Your endpoint verifies an Orbit download ticket
    Protected,
}

#[derive(Args)]
pub struct Notes {
    /// Plain-text release notes
    #[arg(long, conflicts_with = "notes_file")]
    pub notes: Option<String>,
    /// Read release notes from a UTF-8 file
    #[arg(long, value_name = "PATH")]
    pub notes_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Releases {
    /// List releases, newest first
    List {
        #[arg(long)]
        channel: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=100))]
        limit: Option<u8>,
        #[arg(long)]
        after: Option<String>,
    },
    /// Show one release and its files
    Show { release: String },
    /// Create a draft release
    Create {
        /// Display version, for example 2.4.0
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[command(flatten)]
        notes: Notes,
    },
    /// Replace a draft's channel, version or notes
    Edit {
        release: String,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        channel: Option<String>,
        #[command(flatten)]
        notes: Notes,
    },
    /// Add a file you host to a draft; length and SHA-256 come from the local copy
    AddArtifact {
        release: String,
        /// Local copy of the exact file served from the URL
        file: PathBuf,
        /// HTTPS URL that serves the file
        #[arg(long)]
        url: String,
        /// Target platform, for example windows, macos or linux
        #[arg(long)]
        platform: String,
        /// Target architecture, for example x86_64 or aarch64
        #[arg(long = "arch", value_name = "ARCH")]
        architecture: String,
        /// Filename shown to users [default: local file name]
        #[arg(long)]
        filename: Option<String>,
        /// Boolean entitlement required to download
        #[arg(long, value_name = "NAME")]
        required_feature: Option<String>,
        #[arg(long, value_enum, default_value = "public")]
        delivery: Delivery,
    },
    /// Remove a file from a draft
    RemoveArtifact { release: String, artifact: String },
    /// Publish a release so eligible installations can find it
    Publish { release: String },
    /// Stop offering a published release
    Unpublish { release: String },
}
