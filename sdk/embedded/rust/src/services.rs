//! Optional heapless licensed services and explicit offline-file profiles.
use super::*;

#[cfg(feature = "offline")]
const EXTENSION_BYTES: usize = 392;
#[cfg(not(feature = "offline"))]
const EXTENSION_BYTES: usize = 288;
#[repr(C, align(8))]
struct Extension([u8; EXTENSION_BYTES]);
/// Additional caller-owned state. Connected-only `Buffers` keep their original
/// size when the `services` feature is disabled.
pub struct ServiceBuffers {
    extension: Extension,
}
impl ServiceBuffers {
    pub const fn new() -> Self {
        Self {
            extension: Extension([0; EXTENSION_BYTES]),
        }
    }
}
impl Default for ServiceBuffers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "offline")]
#[repr(C)]
struct Transaction<const FILE: usize> {
    metadata: [u8; 1024],
    file: [u8; FILE],
}
#[cfg(feature = "offline")]
impl<const FILE: usize> Transaction<FILE> {
    // The C storage callback may borrow the complete metadata + file extent.
    // Derive provenance from this whole repr(C) object, never a field borrow.
    fn as_mut_ptr(&mut self) -> *mut u8 {
        (self as *mut Self).cast()
    }
}
/// Explicit file-size profile: 4096 or 16384 signed bytes plus 1024 metadata bytes.
/// The `offline-full` feature selects journal support for the larger profile.
#[cfg(feature = "offline")]
pub struct OfflineBuffers<const FILE: usize = 4096> {
    services: ServiceBuffers,
    keys: [u8; 1545],
    transaction: Transaction<FILE>,
}
#[cfg(feature = "offline")]
impl<const FILE: usize> OfflineBuffers<FILE> {
    pub const fn new() -> Self {
        Self {
            services: ServiceBuffers::new(),
            keys: [0; 1545],
            transaction: Transaction {
                metadata: [0; 1024],
                file: [0; FILE],
            },
        }
    }
}
#[cfg(feature = "offline")]
impl<const FILE: usize> Default for OfflineBuffers<FILE> {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(feature = "offline")]
#[repr(C)]
struct RawOffline {
    keys: *const u8,
    transaction: *mut u8,
    capacity: u32,
    maximum: u32,
    app_key: Slice,
}

fn platform_services<P: Platform>(platform: &mut P) -> Services {
    let p = (platform as *mut P).cast();
    Services {
        context: p,
        exchange: exchange::<P>,
        clock: clock::<P>,
        entropy: entropy::<P>,
        load: load::<P>,
        commit: commit::<P>,
        crypto: Crypto {
            context: p,
            validate: validate::<P>,
            sha256: sha256::<P>,
            verify: verify::<P>,
        },
    }
}
fn raw_config(app: &AppKey<'_>, binding: Option<(&str, &str)>) -> Result<RawConfig, Error> {
    let (fingerprint, provider) = binding.unwrap_or(("", ""));
    Ok(RawConfig {
        origin: Slice::str(app.api_origin())?,
        issuer: Slice::str(app.api_origin())?,
        application: Slice::str(app.application_id())?,
        environment: Slice::str(app.environment_id())?,
        fingerprint: Slice::str(fingerprint)?,
        provider: Slice::str(provider)?,
        environment_kind: match app.environment() {
            Environment::Test => 1,
            Environment::Live => 2,
        },
    })
}
impl<'a, P: Platform> Client<'a, P> {
    pub fn open<const N: usize>(
        buffers: &'a mut Buffers<N>,
        platform: &'a mut P,
        app: &'a AppKey<'a>,
        services: &'a mut ServiceBuffers,
    ) -> Result<Self, Error> {
        Self::open_with_binding(buffers, platform, app, services, None)
    }
    pub fn open_with_binding<const N: usize>(
        buffers: &'a mut Buffers<N>,
        platform: &'a mut P,
        app: &'a AppKey<'a>,
        services: &'a mut ServiceBuffers,
        binding: Option<(&'a str, &'a str)>,
    ) -> Result<Self, Error> {
        let raw = raw_config(app, binding)?;
        let svc = platform_services(platform);
        let state = &mut buffers.state as *mut State;
        check(unsafe {
            orbit_client_init_extended(
                state,
                &raw,
                &svc,
                &mut services.extension,
                buffers.arena.as_mut_ptr(),
                u32::try_from(N).map_err(|_| Error::ARGUMENT)?,
                buffers.scratch.as_mut_ptr().cast(),
                2048,
                core::ptr::null(),
            )
        })?;
        Ok(Self {
            state,
            _borrow: PhantomData,
        })
    }
    #[cfg(feature = "offline")]
    pub fn open_offline<const N: usize, const FILE: usize>(
        buffers: &'a mut Buffers<N>,
        platform: &'a mut P,
        app: &'a AppKey<'a>,
        offline: &'a mut OfflineBuffers<FILE>,
        trusted_jwks: &[u8],
        binding: Option<(&'a str, &'a str)>,
    ) -> Result<Self, Error> {
        if !matches!(FILE, 4096 | 16384) || (FILE == 16384 && !cfg!(feature = "offline-full")) {
            return Err(Error::ARGUMENT);
        }
        let raw = raw_config(app, binding)?;
        let svc = platform_services(platform);
        if unsafe {
            orbit_jwks_import(
                trusted_jwks.as_ptr(),
                u32::try_from(trusted_jwks.len()).map_err(|_| Error::ARGUMENT)?,
                &svc.crypto,
                offline.keys.as_mut_ptr(),
            )
        } != 0
        {
            return Err(Error::UNTRUSTED);
        }
        let off = RawOffline {
            keys: offline.keys.as_ptr(),
            transaction: offline.transaction.as_mut_ptr(),
            capacity: (1024 + FILE) as u32,
            maximum: FILE as u32,
            app_key: Slice::str(app.as_str())?,
        };
        let state = &mut buffers.state as *mut State;
        check(unsafe {
            orbit_client_init_extended(
                state,
                &raw,
                &svc,
                &mut offline.services.extension,
                buffers.arena.as_mut_ptr(),
                u32::try_from(N).map_err(|_| Error::ARGUMENT)?,
                buffers.scratch.as_mut_ptr().cast(),
                2048,
                (&off as *const RawOffline).cast(),
            )
        })?;
        Ok(Self {
            state,
            _borrow: PhantomData,
        })
    }
    #[cfg(feature = "offline")]
    pub fn import_offline_file(&mut self, file: &[u8]) -> Result<(), Error> {
        check(unsafe {
            orbit_client_import_offline_file(
                self.state,
                Slice {
                    data: file.as_ptr(),
                    length: u32::try_from(file.len()).map_err(|_| Error::ARGUMENT)?,
                },
            )
        })
    }
    /// Reads a bounded file into the existing transaction buffer, without a
    /// second file-sized allocation. Zero bytes means EOF. The reader must
    /// return promptly and may return no more than the provided slice length.
    #[cfg(feature = "offline")]
    pub fn import_offline_reader<F>(
        &mut self,
        reader: &mut F,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<(), Error>
    where
        F: FnMut(&mut [u8]) -> Result<usize, Error>,
    {
        let op = raw_operation(operation)?;
        check(unsafe {
            orbit_client_import_offline_reader(
                self.state,
                offline_read::<F>,
                (reader as *mut F).cast(),
                &op,
            )
        })
    }
    #[cfg(feature = "offline")]
    pub fn offline_request<'b>(&mut self, output: &'b mut [u8]) -> Result<&'b str, Error> {
        let mut n = 0;
        check(unsafe {
            orbit_client_offline_request(
                self.state,
                output.as_mut_ptr(),
                u32::try_from(output.len()).map_err(|_| Error::ARGUMENT)?,
                &mut n,
            )
        })?;
        core::str::from_utf8(output.get(..n as usize).ok_or(Error::UNTRUSTED)?)
            .map_err(|_| Error::UNTRUSTED)
    }
    pub fn start_session(
        &mut self,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<Session, Error> {
        let op = raw_operation(operation)?;
        let mut out = Session::default();
        check(unsafe { orbit_client_start_session(self.state, &op, &mut out) })?;
        Ok(out)
    }
    pub fn end_session(&mut self, operation: Option<&mut Operation<'_>>) -> Result<(), Error> {
        let op = raw_operation(operation)?;
        check(unsafe { orbit_client_end_session(self.state, &op) })
    }
    pub fn session(&mut self) -> Result<Session, Error> {
        let mut out = Session::default();
        check(unsafe { orbit_client_session(self.state, &mut out) })?;
        Ok(out)
    }
    pub fn close(self) -> Result<(), Error> {
        check(unsafe { orbit_client_close(self.state, core::ptr::null()) })
    }
    pub fn usage(&mut self, name: &str) -> Result<Counter, Error> {
        let mut out = LimitResult::default();
        check(unsafe {
            orbit_client_usage(self.state, Slice::str(name)?, core::ptr::null(), &mut out)
        })?;
        Ok(out.counter)
    }
    pub fn resources(&mut self, name: &str) -> Result<Counter, Error> {
        let mut out = LimitResult::default();
        check(unsafe {
            orbit_client_resources(self.state, Slice::str(name)?, core::ptr::null(), &mut out)
        })?;
        Ok(out.counter)
    }
    #[allow(
        clippy::result_large_err,
        reason = "Heapless firmware returns the bounded retry ID and validated counter without allocation"
    )]
    pub fn consume(
        &mut self,
        name: &str,
        units: u64,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<LimitResult, MutationError> {
        self.mutate(name, "", units, operation, 0)
    }
    #[allow(
        clippy::result_large_err,
        reason = "Heapless firmware returns the bounded retry ID and validated counter without allocation"
    )]
    pub fn acquire_resource(
        &mut self,
        name: &str,
        resource_id: &str,
        units: u64,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<LimitResult, MutationError> {
        self.mutate(name, resource_id, units, operation, 1)
    }
    #[allow(
        clippy::result_large_err,
        reason = "Heapless firmware returns the bounded retry ID and validated counter without allocation"
    )]
    pub fn release_resource(
        &mut self,
        name: &str,
        allocation_id: &str,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<LimitResult, MutationError> {
        self.mutate(name, allocation_id, 0, operation, 2)
    }
    #[allow(
        clippy::result_large_err,
        reason = "Heapless firmware returns the bounded retry ID and validated counter without allocation"
    )]
    fn mutate(
        &mut self,
        name: &str,
        id: &str,
        units: u64,
        operation: Option<&mut Operation<'_>>,
        kind: u8,
    ) -> Result<LimitResult, MutationError> {
        let mut result = LimitResult::default();
        let outcome = (|| {
            let name = Slice::str(name)?;
            let id = Slice::str(id)?;
            let op = raw_operation(operation)?;
            check(unsafe {
                match kind {
                    0 => orbit_client_consume(self.state, name, units, &op, &mut result),
                    1 => {
                        orbit_client_acquire_resource(self.state, name, id, units, &op, &mut result)
                    }
                    _ => orbit_client_release_resource(self.state, name, id, &op, &mut result),
                }
            })
        })();
        outcome.map(|()| result).map_err(|error| MutationError {
            error,
            counter: if result.capacity_denied() {
                Some(result.counter)
            } else {
                None
            },
            requested_units: result.units,
            operation_id: result.operation_id,
            operation_id_length: result.operation_id_length,
            uncertain: result.uncertain(),
        })
    }
}

#[cfg(feature = "offline")]
unsafe extern "C" fn offline_read<F>(p: *mut c_void, b: *mut u8, n: u32, out: *mut u32) -> i32
where
    F: FnMut(&mut [u8]) -> Result<usize, Error>,
{
    match (&mut *p.cast::<F>())(core::slice::from_raw_parts_mut(b, n as usize)) {
        Ok(got) if got <= n as usize => {
            *out = got as u32;
            0
        }
        Ok(_) => Error::ARGUMENT.0,
        Err(e) => e.0,
    }
}

/// Persist the ID with the application's job when recovery must survive restart.
/// A cancellation cannot prove a server-side mutation did not happen.
#[derive(Default)]
pub struct Operation<'a> {
    pub id: Option<&'a str>,
    pub cancelled: Option<&'a mut dyn FnMut() -> bool>,
}
#[repr(C)]
pub(super) struct RawOperation {
    id: Slice,
    context: *mut c_void,
    cancelled: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
}
unsafe extern "C" fn cancelled(p: *mut c_void) -> i32 {
    let op = &mut *p.cast::<Operation<'_>>();
    i32::from(op.cancelled.as_mut().is_some_and(|f| f()))
}
fn raw_operation(operation: Option<&mut Operation<'_>>) -> Result<RawOperation, Error> {
    match operation {
        Some(op) => Ok(RawOperation {
            id: Slice::str(op.id.unwrap_or(""))?,
            context: (op as *mut Operation<'_>).cast(),
            cancelled: Some(cancelled),
        }),
        None => Ok(RawOperation {
            id: Slice::str("")?,
            context: core::ptr::null_mut(),
            cancelled: None,
        }),
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Counter {
    pub limit: u64,
    pub used: u64,
    pub remaining: u64,
    pub period_started_at: i64,
    pub resets_at: i64,
    name: [u8; 64],
    name_length: u8,
    period: u8,
    usage: u8,
}
impl Counter {
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_length as usize]).unwrap_or("")
    }
    pub fn period(&self) -> Option<Period> {
        if self.usage == 0 {
            None
        } else {
            Some(match self.period {
                1 => Period::Day,
                2 => Period::Month,
                _ => Period::Lifetime,
            })
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Period {
    Lifetime,
    Day,
    Month,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LimitResult {
    pub counter: Counter,
    pub units: u64,
    operation_id: [u8; 128],
    allocation_id: [u8; 128],
    resource_id: [u8; 128],
    operation_id_length: u8,
    allocation_id_length: u8,
    resource_id_length: u8,
    released: u8,
    capacity_denied: u8,
    uncertain: u8,
}
impl Default for LimitResult {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
impl LimitResult {
    pub fn operation_id(&self) -> &str {
        core::str::from_utf8(&self.operation_id[..self.operation_id_length as usize]).unwrap_or("")
    }
    pub fn allocation_id(&self) -> &str {
        core::str::from_utf8(&self.allocation_id[..self.allocation_id_length as usize])
            .unwrap_or("")
    }
    pub fn resource_id(&self) -> &str {
        core::str::from_utf8(&self.resource_id[..self.resource_id_length as usize]).unwrap_or("")
    }
    pub fn released(&self) -> bool {
        self.released != 0
    }
    pub fn capacity_denied(&self) -> bool {
        self.capacity_denied != 0
    }
    pub fn uncertain(&self) -> bool {
        self.uncertain != 0
    }
}
#[derive(Debug)]
pub struct MutationError {
    pub error: Error,
    pub counter: Option<Counter>,
    pub requested_units: u64,
    operation_id: [u8; 128],
    operation_id_length: u8,
    pub uncertain: bool,
}
impl MutationError {
    pub fn operation_id(&self) -> &str {
        core::str::from_utf8(&self.operation_id[..self.operation_id_length as usize]).unwrap_or("")
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Session {
    id: [u8; 128],
    pub sequence: u64,
    pub expires_at: i64,
    pub refresh_after: i64,
    id_length: u8,
    required: u8,
    active: u8,
    automatic: u8,
}
impl Default for Session {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
impl Session {
    pub fn id(&self) -> &str {
        core::str::from_utf8(&self.id[..self.id_length as usize]).unwrap_or("")
    }
    pub fn required(&self) -> bool {
        self.required != 0
    }
    pub fn active(&self) -> bool {
        self.active != 0
    }
    pub fn automatic(&self) -> bool {
        self.automatic != 0
    }
}
extern "C" {
    fn orbit_client_init_extended(
        c: *mut State,
        cfg: *const RawConfig,
        svc: *const Services,
        e: *mut Extension,
        a: *mut u8,
        n: u32,
        scratch: *mut c_void,
        scratch_length: u32,
        offline: *const c_void,
    ) -> i32;
    pub(super) fn orbit_client_close(c: *mut State, op: *const RawOperation) -> i32;
    fn orbit_client_start_session(c: *mut State, op: *const RawOperation, s: *mut Session) -> i32;
    fn orbit_client_end_session(c: *mut State, op: *const RawOperation) -> i32;
    fn orbit_client_session(c: *mut State, s: *mut Session) -> i32;
    fn orbit_client_usage(
        c: *mut State,
        name: Slice,
        op: *const RawOperation,
        r: *mut LimitResult,
    ) -> i32;
    fn orbit_client_resources(
        c: *mut State,
        name: Slice,
        op: *const RawOperation,
        r: *mut LimitResult,
    ) -> i32;
    fn orbit_client_consume(
        c: *mut State,
        name: Slice,
        units: u64,
        op: *const RawOperation,
        r: *mut LimitResult,
    ) -> i32;
    fn orbit_client_acquire_resource(
        c: *mut State,
        name: Slice,
        id: Slice,
        units: u64,
        op: *const RawOperation,
        r: *mut LimitResult,
    ) -> i32;
    fn orbit_client_release_resource(
        c: *mut State,
        name: Slice,
        id: Slice,
        op: *const RawOperation,
        r: *mut LimitResult,
    ) -> i32;
    #[cfg(feature = "offline")]
    fn orbit_jwks_import(b: *const u8, n: u32, crypto: *const Crypto, keys: *mut u8) -> i32;
    #[cfg(feature = "offline")]
    fn orbit_client_import_offline_file(c: *mut State, file: Slice) -> i32;
    #[cfg(feature = "offline")]
    fn orbit_client_import_offline_reader(
        c: *mut State,
        read: unsafe extern "C" fn(*mut c_void, *mut u8, u32, *mut u32) -> i32,
        context: *mut c_void,
        op: *const RawOperation,
    ) -> i32;
    #[cfg(feature = "offline")]
    fn orbit_client_offline_request(
        c: *mut State,
        out: *mut u8,
        capacity: u32,
        length: *mut u32,
    ) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawArtifact {
    id: Slice,
    release_id: Slice,
    platform: Slice,
    architecture: Slice,
    filename: Slice,
    url: Slice,
    required_feature: Slice,
    byte_length: u64,
    sha256: [u8; 32],
    protected_delivery: u8,
}
#[repr(C)]
struct RawRelease {
    id: Slice,
    channel: Slice,
    version: Slice,
    notes: Slice,
    release_number: u64,
    created_at: i64,
    published_at: i64,
}
#[repr(C)]
struct RawUpdate {
    release: RawRelease,
    artifact: RawArtifact,
    available: u8,
}
#[repr(C)]
struct RawAuthorization {
    artifact: RawArtifact,
    ticket: Slice,
    expires_at: i64,
}
/// Owned bounded identifier, allowing a discovered selection to outlive the
/// metadata borrow without allocating a string.
#[derive(Clone, Copy, Debug)]
pub struct Id {
    bytes: [u8; 128],
    length: u8,
}
impl Id {
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(Error::ARGUMENT);
        }
        let mut id = Self {
            bytes: [0; 128],
            length: value.len() as u8,
        };
        id.bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(id)
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.length as usize]).unwrap_or("")
    }
}
#[derive(Clone, Copy, Debug)]
pub struct DownloadSelection {
    pub release_id: Id,
    pub artifact_id: Id,
}
pub struct Artifact<'a> {
    pub id: Id,
    pub release_id: Id,
    pub platform: &'a str,
    pub architecture: &'a str,
    pub filename: &'a str,
    pub url: &'a str,
    pub required_feature: Option<&'a str>,
    pub byte_length: u64,
    pub sha256: [u8; 32],
    pub protected_delivery: bool,
}
impl Artifact<'_> {
    pub fn selection(&self) -> DownloadSelection {
        DownloadSelection {
            release_id: self.release_id,
            artifact_id: self.id,
        }
    }
}
#[derive(Debug)]
pub struct Release<'a> {
    pub id: Id,
    pub channel: &'a str,
    pub version: &'a str,
    pub notes: &'a str,
    pub release_number: u64,
    pub created_at: i64,
    pub published_at: i64,
}
#[derive(Debug)]
pub struct Update<'a> {
    pub release: Release<'a>,
    pub artifact: Artifact<'a>,
}
pub struct DownloadAuthorization<'a> {
    artifact: Artifact<'a>,
    ticket: Option<&'a str>,
    pub expires_at: Option<i64>,
}
unsafe fn raw_str<'a>(slice: Slice) -> Result<&'a str, Error> {
    core::str::from_utf8(bytes(slice.data, slice.length)).map_err(|_| Error::UNTRUSTED)
}
unsafe fn artifact_view<'a>(raw: &RawArtifact) -> Result<Artifact<'a>, Error> {
    Ok(Artifact {
        id: Id::new(raw_str(raw.id)?)?,
        release_id: Id::new(raw_str(raw.release_id)?)?,
        platform: raw_str(raw.platform)?,
        architecture: raw_str(raw.architecture)?,
        filename: raw_str(raw.filename)?,
        url: raw_str(raw.url)?,
        required_feature: if raw.required_feature.length == 0 {
            None
        } else {
            Some(raw_str(raw.required_feature)?)
        },
        byte_length: raw.byte_length,
        sha256: raw.sha256,
        protected_delivery: raw.protected_delivery != 0,
    })
}
fn raw_artifact(a: &Artifact<'_>) -> Result<RawArtifact, Error> {
    Ok(RawArtifact {
        id: Slice::str(a.id.as_str())?,
        release_id: Slice::str(a.release_id.as_str())?,
        platform: Slice::str(a.platform)?,
        architecture: Slice::str(a.architecture)?,
        filename: Slice::str(a.filename)?,
        url: Slice::str(a.url)?,
        required_feature: Slice::str(a.required_feature.unwrap_or(""))?,
        byte_length: a.byte_length,
        sha256: a.sha256,
        protected_delivery: u8::from(a.protected_delivery),
    })
}
impl<P: Platform> Client<'_, P> {
    /// Use the exact board target. There is no cross-target fallback.
    pub fn check_for_updates<'b>(
        &'b mut self,
        installed_release_number: u64,
        platform: &str,
        architecture: &str,
        channel: Option<&str>,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<Option<Update<'b>>, Error> {
        let op = raw_operation(operation)?;
        let mut out: RawUpdate = unsafe { core::mem::zeroed() };
        check(unsafe {
            orbit_client_check_for_updates(
                self.state,
                installed_release_number,
                Slice::str(channel.unwrap_or("stable"))?,
                Slice::str(platform)?,
                Slice::str(architecture)?,
                &op,
                &mut out,
            )
        })?;
        if out.available == 0 {
            return Ok(None);
        }
        unsafe {
            Ok(Some(Update {
                artifact: artifact_view(&out.artifact)?,
                release: Release {
                    id: Id::new(raw_str(out.release.id)?)?,
                    channel: raw_str(out.release.channel)?,
                    version: raw_str(out.release.version)?,
                    notes: raw_str(out.release.notes)?,
                    release_number: out.release.release_number,
                    created_at: out.release.created_at,
                    published_at: out.release.published_at,
                },
            }))
        }
    }
    pub fn authorize_download<'b>(
        &'b mut self,
        selection: DownloadSelection,
        operation: Option<&mut Operation<'_>>,
    ) -> Result<DownloadAuthorization<'b>, Error> {
        let op = raw_operation(operation)?;
        let mut out: RawAuthorization = unsafe { core::mem::zeroed() };
        check(unsafe {
            orbit_client_authorize_download(
                self.state,
                Slice::str(selection.release_id.as_str())?,
                Slice::str(selection.artifact_id.as_str())?,
                &op,
                &mut out,
            )
        })?;
        unsafe {
            Ok(DownloadAuthorization {
                artifact: artifact_view(&out.artifact)?,
                ticket: if out.ticket.length == 0 {
                    None
                } else {
                    Some(raw_str(out.ticket)?)
                },
                expires_at: if out.ticket.length == 0 {
                    None
                } else {
                    Some(out.expires_at)
                },
            })
        }
    }
}
/// A single verified HTTPS response. Header strings stay in the port until close.
pub struct DownloadResponse<'a> {
    pub status: u16,
    pub location: &'a str,
    pub content_encoding: &'a str,
    pub content_length: Option<u64>,
}
/// Maintain verified TLS with identity encoding and no cookies/global credentials.
/// open never redirects; a ticket is an Authorization bearer for that one request.
/// Every callback has a finite timeout. Stage separately; commit atomically only
/// on success, abort preserves an existing destination. Hash raw bytes unchanged.
pub trait DownloadIo {
    fn open<'a>(
        &'a mut self,
        url: &str,
        ticket: Option<&str>,
    ) -> Result<DownloadResponse<'a>, Error>;
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error>;
    fn close(&mut self);
    fn stage_begin(&mut self, replace_existing: bool) -> Result<(), Error>;
    fn stage_write(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn stage_commit(&mut self) -> Result<(), Error>;
    fn stage_abort(&mut self);
    fn hash_begin(&mut self) -> Result<(), Error>;
    fn hash_update(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn hash_finish(&mut self, digest: &mut [u8; 32]) -> Result<(), Error>;
    fn cancelled(&mut self) -> bool {
        false
    }
}
#[repr(C)]
struct RawDownloadResponse {
    location: Slice,
    encoding: Slice,
    length: u64,
    status: u16,
    has_length: u8,
}
#[repr(C)]
struct RawDownloadIo {
    context: *mut c_void,
    open: unsafe extern "C" fn(*mut c_void, Slice, Slice, *mut RawDownloadResponse) -> i32,
    read: unsafe extern "C" fn(*mut c_void, *mut u8, u32, *mut u32) -> i32,
    close: unsafe extern "C" fn(*mut c_void),
    stage_begin: unsafe extern "C" fn(*mut c_void, u8) -> i32,
    stage_write: unsafe extern "C" fn(*mut c_void, *const u8, u32) -> i32,
    stage_commit: unsafe extern "C" fn(*mut c_void) -> i32,
    stage_abort: unsafe extern "C" fn(*mut c_void),
    hash_begin: unsafe extern "C" fn(*mut c_void) -> i32,
    hash_update: unsafe extern "C" fn(*mut c_void, *const u8, u32) -> i32,
    hash_finish: unsafe extern "C" fn(*mut c_void, *mut u8) -> i32,
    cancelled: unsafe extern "C" fn(*mut c_void) -> i32,
}
unsafe extern "C" fn download_open<T: DownloadIo>(
    p: *mut c_void,
    url: Slice,
    ticket: Slice,
    out: *mut RawDownloadResponse,
) -> i32 {
    let result = (|| {
        let response = (&mut *p.cast::<T>()).open(
            raw_str(url)?,
            if ticket.length == 0 {
                None
            } else {
                Some(raw_str(ticket)?)
            },
        )?;
        *out = RawDownloadResponse {
            location: Slice::str(response.location)?,
            encoding: Slice::str(response.content_encoding)?,
            length: response.content_length.unwrap_or(0),
            status: response.status,
            has_length: u8::from(response.content_length.is_some()),
        };
        Ok(())
    })();
    code(result)
}
unsafe extern "C" fn download_read<T: DownloadIo>(
    p: *mut c_void,
    b: *mut u8,
    n: u32,
    out: *mut u32,
) -> i32 {
    match (&mut *p.cast::<T>()).read(core::slice::from_raw_parts_mut(b, n as usize)) {
        Ok(m) if m <= n as usize => {
            *out = m as u32;
            0
        }
        Ok(_) => 19,
        Err(e) => e.0,
    }
}
unsafe extern "C" fn download_close<T: DownloadIo>(p: *mut c_void) {
    (&mut *p.cast::<T>()).close()
}
unsafe extern "C" fn stage_begin<T: DownloadIo>(p: *mut c_void, replace: u8) -> i32 {
    code((&mut *p.cast::<T>()).stage_begin(replace != 0))
}
unsafe extern "C" fn stage_write<T: DownloadIo>(p: *mut c_void, b: *const u8, n: u32) -> i32 {
    code((&mut *p.cast::<T>()).stage_write(bytes(b, n)))
}
unsafe extern "C" fn stage_commit<T: DownloadIo>(p: *mut c_void) -> i32 {
    code((&mut *p.cast::<T>()).stage_commit())
}
unsafe extern "C" fn stage_abort<T: DownloadIo>(p: *mut c_void) {
    (&mut *p.cast::<T>()).stage_abort()
}
unsafe extern "C" fn hash_begin<T: DownloadIo>(p: *mut c_void) -> i32 {
    code((&mut *p.cast::<T>()).hash_begin())
}
unsafe extern "C" fn hash_update<T: DownloadIo>(p: *mut c_void, b: *const u8, n: u32) -> i32 {
    code((&mut *p.cast::<T>()).hash_update(bytes(b, n)))
}
unsafe extern "C" fn hash_finish<T: DownloadIo>(p: *mut c_void, d: *mut u8) -> i32 {
    let mut digest = [0; 32];
    match (&mut *p.cast::<T>()).hash_finish(&mut digest) {
        Ok(()) => {
            core::ptr::copy_nonoverlapping(digest.as_ptr(), d, 32);
            0
        }
        Err(e) => e.0,
    }
}
unsafe extern "C" fn download_cancelled<T: DownloadIo>(p: *mut c_void) -> i32 {
    i32::from((&mut *p.cast::<T>()).cancelled())
}
impl DownloadAuthorization<'_> {
    /// Scratch needs at least 2304 bytes. Nothing is executed or unpacked.
    pub fn stream<T: DownloadIo>(
        &self,
        io: &mut T,
        maximum_bytes: u64,
        replace_existing: bool,
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        let auth = RawAuthorization {
            artifact: raw_artifact(&self.artifact)?,
            ticket: Slice::str(self.ticket.unwrap_or(""))?,
            expires_at: self.expires_at.unwrap_or(0),
        };
        let callbacks = RawDownloadIo {
            context: (io as *mut T).cast(),
            open: download_open::<T>,
            read: download_read::<T>,
            close: download_close::<T>,
            stage_begin: stage_begin::<T>,
            stage_write: stage_write::<T>,
            stage_commit: stage_commit::<T>,
            stage_abort: stage_abort::<T>,
            hash_begin: hash_begin::<T>,
            hash_update: hash_update::<T>,
            hash_finish: hash_finish::<T>,
            cancelled: download_cancelled::<T>,
        };
        check(unsafe {
            orbit_download_stream(
                &auth,
                maximum_bytes,
                u8::from(replace_existing),
                &callbacks,
                scratch.as_mut_ptr(),
                u32::try_from(scratch.len()).map_err(|_| Error::ARGUMENT)?,
            )
        })
    }
}
extern "C" {
    fn orbit_client_check_for_updates(
        c: *mut State,
        installed: u64,
        channel: Slice,
        platform: Slice,
        architecture: Slice,
        op: *const RawOperation,
        out: *mut RawUpdate,
    ) -> i32;
    fn orbit_client_authorize_download(
        c: *mut State,
        release: Slice,
        artifact: Slice,
        op: *const RawOperation,
        out: *mut RawAuthorization,
    ) -> i32;
    fn orbit_download_stream(
        auth: *const RawAuthorization,
        maximum: u64,
        replace: u8,
        io: *const RawDownloadIo,
        scratch: *mut u8,
        capacity: u32,
    ) -> i32;
}

impl core::fmt::Debug for Artifact<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Artifact")
            .field("id", &self.id)
            .field("byte_length", &self.byte_length)
            .field("protected_delivery", &self.protected_delivery)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Debug for DownloadAuthorization<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DownloadAuthorization")
            .field("artifact", &self.artifact)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl DownloadAuthorization<'_> {
    pub fn artifact(&self) -> &Artifact<'_> {
        &self.artifact
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_abi() {
        extern "C" {
            fn orbit_rust_layout(index: u32) -> usize;
        }
        assert!(unsafe { orbit_rust_layout(9) } <= EXTENSION_BYTES);
        let layouts = [
            core::mem::size_of::<Counter>(),
            core::mem::size_of::<LimitResult>(),
            core::mem::size_of::<Session>(),
            core::mem::size_of::<RawArtifact>(),
            core::mem::size_of::<RawRelease>(),
            core::mem::size_of::<RawUpdate>(),
            core::mem::size_of::<RawAuthorization>(),
            core::mem::size_of::<RawOperation>(),
            core::mem::size_of::<RawDownloadIo>(),
            core::mem::size_of::<RawDownloadResponse>(),
        ];
        for (i, size) in layouts.into_iter().enumerate() {
            assert_eq!(unsafe { orbit_rust_layout(i as u32 + 10) }, size);
        }
        #[cfg(feature = "offline")]
        {
            assert_eq!(
                unsafe { orbit_rust_layout(20) },
                core::mem::size_of::<RawOffline>()
            );
            assert_eq!(core::mem::size_of::<Transaction<4096>>(), 5120);
            assert_eq!(core::mem::offset_of!(Transaction<4096>, file), 1024);
        }
    }
    #[cfg(feature = "offline")]
    #[test]
    fn transaction_pointer_covers_both_fields() {
        let mut transaction = Transaction::<4096> {
            metadata: [0; 1024],
            file: [0; 4096],
        };
        // Match the complete slice constructed by the Rust storage callback
        // from the transaction pointer that open_offline passes through C.
        let bytes = unsafe { core::slice::from_raw_parts_mut(transaction.as_mut_ptr(), 5120) };
        bytes[1023] = 1;
        bytes[1024] = 2;
        bytes[5119] = 3;
        assert_eq!(transaction.metadata[1023], 1);
        assert_eq!(transaction.file[0], 2);
        assert_eq!(transaction.file[4095], 3);
    }
    #[test]
    fn owned_selection_and_cancellation() {
        assert!(Id::new("../artifact").is_err());
        assert!(Id::new("artifact_1").is_ok());
        let mut checks = 0;
        let mut cancel = || {
            checks += 1;
            true
        };
        let mut op = Operation {
            id: Some("job_1"),
            cancelled: Some(&mut cancel),
        };
        let raw = raw_operation(Some(&mut op)).unwrap();
        assert_eq!(unsafe { raw.cancelled.unwrap()(raw.context) }, 1);
        assert_eq!(checks, 1);
    }
}
