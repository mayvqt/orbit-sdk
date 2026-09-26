#![no_std]
//! One owner, no allocation or background work. Construct [`Client`] with
//! caller-owned [`Buffers`], a [`Platform`], and borrowed configuration strings.
//! Call `tick` regularly, `activate` once when needed, and `require_access`
//! immediately before a protected operation. A reboot always validates online.
//!
//! The platform sends the complete request before returning its response status;
//! subsequent response reads may reuse the request memory in the C client.
//! No platform method may retain borrowed arguments or reenter this client.
use core::{ffi::c_void, marker::PhantomData};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(i32);
impl Error {
    pub const fn from_code(code: i32) -> Option<Self> {
        if code == 0 {
            None
        } else {
            Some(Self(code))
        }
    }
    pub const fn code(self) -> i32 {
        self.0
    }
    pub const STORAGE: Self = Self(11);
    pub const UNTRUSTED: Self = Self(12);
    pub const TRANSIENT: Self = Self(13);
    pub const DENIED: Self = Self(14);
    pub const ACTIVATION_REQUIRED: Self = Self(15);
    pub const CLOCK: Self = Self(16);
    pub const PENDING: Self = Self(17);
    pub const NOT_FOUND: Self = Self(20);
}
fn check(n: i32) -> Result<(), Error> {
    if n == 0 {
        Ok(())
    } else {
        Err(Error(n))
    }
}
fn code(r: Result<(), Error>) -> i32 {
    r.err().map_or(0, |e| e.0)
}

pub struct Request<'a> {
    pub origin: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
    pub post: bool,
}
/// Security-sensitive operations supplied by your maintained platform libraries.
/// TLS must verify the certificate chain, hostname and dates. Return TRANSIENT
/// only for a network timeout/unavailability. Commit is atomic, durable, compares
/// generation, and never restores older authority after a torn newer write.
/// This owner exclusively controls its storage for the entire client's lifetime.
pub trait Platform {
    fn begin_request(&mut self, request: Request<'_>) -> Result<u16, Error>;
    fn read_response(&mut self, bytes: &mut [u8]) -> Result<usize, Error>;
    fn end_response(&mut self);
    fn clock(&mut self) -> Result<(i64, u64), Error>;
    fn entropy(&mut self, bytes: &mut [u8]) -> Result<(), Error>;
    fn load(&mut self, bytes: &mut [u8]) -> Result<usize, Error>;
    fn commit(&mut self, previous_generation: u64, record: &[u8]) -> Result<(), Error>;
    fn validate_p256(&mut self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), Error>;
    fn sha256(&mut self, input: &[u8], digest: &mut [u8; 32]) -> Result<(), Error>;
    /// Verify the supplied SHA-256 digest directly. Do not hash it again.
    fn verify_es256(
        &mut self,
        x: &[u8; 32],
        y: &[u8; 32],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), Error>;
}
pub struct Config<'a> {
    pub api_origin: &'a str,
    pub issuer: &'a str,
    pub application_id: &'a str,
    pub environment_id: &'a str,
    pub fingerprint: &'a str,
    pub fingerprint_provider: &'a str,
}
#[repr(C, align(8))]
struct State([u8; 6960]);
/// Place in a static or another stable caller-owned allocation; contains 41,776
/// bytes on all supported targets. The borrow prevents moving it while active.
pub struct Buffers {
    state: State,
    arena: [u8; 32768],
    scratch: [u8; 2048],
}
impl Buffers {
    pub const fn new() -> Self {
        Self {
            state: State([0; 6960]),
            arena: [0; 32768],
            scratch: [0; 2048],
        }
    }
}
impl Default for Buffers {
    fn default() -> Self {
        Self::new()
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Snapshot {
    pub expires_at: i64,
    pub refresh_after: i64,
    pub credential_expires_at: i64,
    pub policy_version: u32,
    allowed: u8,
    offline: u8,
    has_credential_expiry: u8,
    activation_required: u8,
    pending: u8,
}
impl Snapshot {
    pub fn allowed(&self) -> bool {
        self.allowed != 0
    }
    pub fn offline(&self) -> bool {
        self.offline != 0
    }
    pub fn has_credential_expiry(&self) -> bool {
        self.has_credential_expiry != 0
    }
    pub fn activation_required(&self) -> bool {
        self.activation_required != 0
    }
    pub fn pending(&self) -> bool {
        self.pending != 0
    }
}
/// The buffers and platform stay exclusively borrowed until the client is dropped.
/// ```compile_fail
/// use orbit_embedded::{Buffers, Client, Config, Platform};
/// fn cannot_reuse<P: Platform>(b: &mut Buffers, p: &mut P, cfg: Config<'_>) {
///     let mut client = Client::new(b, p, cfg).unwrap();
///     let moved = b;
///     client.tick().unwrap();
/// }
/// ```
pub struct Client<'a, P: Platform> {
    state: *mut State,
    _borrow: PhantomData<(&'a mut Buffers, &'a mut P, &'a Config<'a>)>,
}
impl<'a, P: Platform> Client<'a, P> {
    pub fn new(
        buffers: &'a mut Buffers,
        platform: &'a mut P,
        config: Config<'a>,
    ) -> Result<Self, Error> {
        let raw = RawConfig {
            origin: Slice::str(config.api_origin)?,
            issuer: Slice::str(config.issuer)?,
            application: Slice::str(config.application_id)?,
            environment: Slice::str(config.environment_id)?,
            fingerprint: Slice::str(config.fingerprint)?,
            provider: Slice::str(config.fingerprint_provider)?,
        };
        let p = platform as *mut P as *mut c_void;
        let services = Services {
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
        };
        let state = &mut buffers.state as *mut State;
        // SAFETY: all caller buffers and the platform are exclusively borrowed
        // until Drop; configuration strings outlive the same borrow. C copies
        // config/services and retains only those stable buffer/string pointers.
        check(unsafe {
            orbit_client_init(
                state,
                &raw,
                &services,
                buffers.arena.as_mut_ptr(),
                32768,
                buffers.scratch.as_mut_ptr().cast(),
                2048,
            )
        })?;
        Ok(Self {
            state,
            _borrow: PhantomData,
        })
    }
    pub fn tick(&mut self) -> Result<(), Error> {
        check(unsafe { orbit_client_tick(self.state) })
    }
    pub fn activate(&mut self, key: &str) -> Result<(), Error> {
        check(unsafe { orbit_client_activate(self.state, Slice::str(key)?) })
    }
    pub fn require_access(&mut self, entitlement: &str) -> Result<(), Error> {
        check(unsafe { orbit_client_require_access(self.state, Slice::str(entitlement)?) })
    }
    pub fn snapshot(&mut self) -> Result<Snapshot, Error> {
        let mut s = Snapshot::default();
        check(unsafe { orbit_client_snapshot(self.state, &mut s) })?;
        Ok(s)
    }
    pub fn deactivate(&mut self) -> Result<(), Error> {
        check(unsafe { orbit_client_deactivate(self.state) })
    }
    pub fn invalidate(&mut self) -> Result<(), Error> {
        check(unsafe { orbit_client_invalidate(self.state) })
    }
    pub fn clock_lost(&mut self) -> Result<(), Error> {
        check(unsafe { orbit_client_clock_lost(self.state) })
    }
}
impl<P: Platform> Drop for Client<'_, P> {
    fn drop(&mut self) {
        unsafe { orbit_client_destroy(self.state) }
    }
}

// All FFI and intermediate grant state remain private. Safe Rust cannot construct
// a pending grant, access its mutable arena, copy a live client, or extend a view.
#[repr(C)]
#[derive(Clone, Copy)]
struct Slice {
    data: *const u8,
    length: u32,
}
impl Slice {
    fn str(s: &str) -> Result<Self, Error> {
        Ok(Self {
            data: s.as_ptr(),
            length: u32::try_from(s.len()).map_err(|_| Error(10))?,
        })
    }
}
#[repr(C)]
struct RawConfig {
    origin: Slice,
    issuer: Slice,
    application: Slice,
    environment: Slice,
    fingerprint: Slice,
    provider: Slice,
}
#[repr(C)]
struct RawRequest {
    origin: Slice,
    path: Slice,
    body: Slice,
    post: u8,
}
type Receive = unsafe extern "C" fn(*mut c_void, *const u8, u32) -> i32;
#[repr(C)]
struct Crypto {
    context: *mut c_void,
    validate: unsafe extern "C" fn(*mut c_void, *const u8, *const u8) -> i32,
    sha256: unsafe extern "C" fn(*mut c_void, *const u8, u32, *mut u8) -> i32,
    verify: unsafe extern "C" fn(*mut c_void, *const u8, *const u8, *const u8, *const u8) -> i32,
}
#[repr(C)]
struct Services {
    context: *mut c_void,
    exchange:
        unsafe extern "C" fn(*mut c_void, *const RawRequest, *mut u16, Receive, *mut c_void) -> i32,
    clock: unsafe extern "C" fn(*mut c_void, *mut i64, *mut u64) -> i32,
    entropy: unsafe extern "C" fn(*mut c_void, *mut u8, u32) -> i32,
    load: unsafe extern "C" fn(*mut c_void, *mut u8, u32, *mut u32) -> i32,
    commit: unsafe extern "C" fn(*mut c_void, u64, *const u8, u32) -> i32,
    crypto: Crypto,
}
unsafe fn bytes<'a>(p: *const u8, n: u32) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(p, n as usize)
    }
}
unsafe extern "C" fn exchange<P: Platform>(
    p: *mut c_void,
    q: *const RawRequest,
    status: *mut u16,
    receive: Receive,
    ctx: *mut c_void,
) -> i32 {
    let q = &*q;
    let origin = match core::str::from_utf8(bytes(q.origin.data, q.origin.length)) {
        Ok(v) => v,
        Err(_) => return 12,
    };
    let path = match core::str::from_utf8(bytes(q.path.data, q.path.length)) {
        Ok(v) => v,
        Err(_) => return 12,
    };
    // The request borrow ends before receive can overwrite the C transaction arena.
    let started = (&mut *p.cast::<P>()).begin_request(Request {
        origin,
        path,
        body: bytes(q.body.data, q.body.length),
        post: q.post != 0,
    });
    let mut result = 0;
    match started {
        Err(e) => result = e.0,
        Ok(s) => {
            *status = s;
            let mut buffer = [0u8; 512];
            loop {
                // The short platform borrow ends before the C receiver can
                // invoke a crypto callback on this same platform (JWKS import).
                match (&mut *p.cast::<P>()).read_response(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) if n <= buffer.len() => {
                        result = receive(ctx, buffer.as_ptr(), n as u32);
                        if result != 0 {
                            break;
                        }
                    }
                    Ok(_) => {
                        result = 19;
                        break;
                    }
                    Err(e) => {
                        result = e.0;
                        break;
                    }
                }
            }
        }
    }
    (&mut *p.cast::<P>()).end_response();
    result
}
unsafe extern "C" fn clock<P: Platform>(p: *mut c_void, u: *mut i64, t: *mut u64) -> i32 {
    match (&mut *p.cast::<P>()).clock() {
        Ok((a, b)) => {
            *u = a;
            *t = b;
            0
        }
        Err(e) => e.0,
    }
}
unsafe extern "C" fn entropy<P: Platform>(p: *mut c_void, b: *mut u8, n: u32) -> i32 {
    // C output memory may be uninitialized. Safe Rust sees initialized bytes.
    let mut output = [0u8; 16];
    if n as usize > output.len() {
        return 19;
    }
    match (&mut *p.cast::<P>()).entropy(&mut output[..n as usize]) {
        Ok(()) => {
            core::ptr::copy_nonoverlapping(output.as_ptr(), b, n as usize);
            0
        }
        Err(e) => e.0,
    }
}
unsafe extern "C" fn load<P: Platform>(p: *mut c_void, b: *mut u8, n: u32, out: *mut u32) -> i32 {
    match (&mut *p.cast::<P>()).load(core::slice::from_raw_parts_mut(b, n as usize)) {
        Ok(m) if m <= n as usize => {
            *out = m as u32;
            0
        }
        Ok(_) => 11,
        Err(e) => e.0,
    }
}
unsafe extern "C" fn commit<P: Platform>(p: *mut c_void, g: u64, b: *const u8, n: u32) -> i32 {
    code((&mut *p.cast::<P>()).commit(g, bytes(b, n)))
}
unsafe extern "C" fn validate<P: Platform>(p: *mut c_void, x: *const u8, y: *const u8) -> i32 {
    code((&mut *p.cast::<P>()).validate_p256(&*x.cast(), &*y.cast()))
}
unsafe extern "C" fn sha256<P: Platform>(p: *mut c_void, b: *const u8, n: u32, d: *mut u8) -> i32 {
    let mut digest = [0u8; 32];
    match (&mut *p.cast::<P>()).sha256(bytes(b, n), &mut digest) {
        Ok(()) => {
            core::ptr::copy_nonoverlapping(digest.as_ptr(), d, 32);
            0
        }
        Err(e) => e.0,
    }
}
unsafe extern "C" fn verify<P: Platform>(
    p: *mut c_void,
    x: *const u8,
    y: *const u8,
    d: *const u8,
    s: *const u8,
) -> i32 {
    code((&mut *p.cast::<P>()).verify_es256(&*x.cast(), &*y.cast(), &*d.cast(), &*s.cast()))
}
extern "C" {
    fn orbit_client_init(
        c: *mut State,
        cfg: *const RawConfig,
        svc: *const Services,
        a: *mut u8,
        n: u32,
        w: *mut c_void,
        wn: u32,
    ) -> i32;
    fn orbit_client_tick(c: *mut State) -> i32;
    fn orbit_client_activate(c: *mut State, key: Slice) -> i32;
    fn orbit_client_require_access(c: *mut State, feature: Slice) -> i32;
    fn orbit_client_snapshot(c: *mut State, s: *mut Snapshot) -> i32;
    fn orbit_client_deactivate(c: *mut State) -> i32;
    fn orbit_client_invalidate(c: *mut State) -> i32;
    fn orbit_client_clock_lost(c: *mut State) -> i32;
    fn orbit_client_destroy(c: *mut State);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout() {
        extern "C" {
            fn orbit_rust_layout(index: u32) -> usize;
        }
        let expected = [
            core::mem::size_of::<State>(),
            core::mem::align_of::<State>(),
            core::mem::size_of::<RawConfig>(),
            core::mem::size_of::<Services>(),
            core::mem::size_of::<RawRequest>(),
            core::mem::size_of::<Snapshot>(),
            core::mem::offset_of!(Services, crypto),
            core::mem::offset_of!(RawRequest, post),
            core::mem::offset_of!(Snapshot, allowed),
        ];
        for (index, value) in expected.into_iter().enumerate() {
            assert_eq!(unsafe { orbit_rust_layout(index as u32) }, value);
        }
        assert_eq!(core::mem::size_of::<State>(), 6960);
        assert_eq!(core::mem::align_of::<State>(), 8);
        assert_eq!(core::mem::size_of::<Buffers>(), 41776);
        assert_eq!(core::mem::size_of::<Snapshot>(), 40);
        assert_eq!(
            core::mem::size_of::<Crypto>(),
            4 * core::mem::size_of::<usize>()
        );
    }

    struct Host {
        record: [u8; 1024],
        length: usize,
        commits: u32,
        posts: u32,
    }
    impl Platform for Host {
        fn begin_request(&mut self, _: Request<'_>) -> Result<u16, Error> {
            self.posts += 1;
            Err(Error::TRANSIENT)
        }
        fn read_response(&mut self, _: &mut [u8]) -> Result<usize, Error> {
            Ok(0)
        }
        fn end_response(&mut self) {}
        fn clock(&mut self) -> Result<(i64, u64), Error> {
            Ok((1800000000, 1000))
        }
        fn entropy(&mut self, b: &mut [u8]) -> Result<(), Error> {
            b.fill(42);
            Ok(())
        }
        fn load(&mut self, b: &mut [u8]) -> Result<usize, Error> {
            if self.length == 0 {
                return Err(Error::NOT_FOUND);
            }
            b[..self.length].copy_from_slice(&self.record[..self.length]);
            Ok(self.length)
        }
        fn commit(&mut self, g: u64, b: &[u8]) -> Result<(), Error> {
            assert_eq!(g, self.commits as u64);
            self.commits += 1;
            self.length = b.len();
            self.record[..b.len()].copy_from_slice(b);
            Ok(())
        }
        fn validate_p256(&mut self, _: &[u8; 32], _: &[u8; 32]) -> Result<(), Error> {
            Err(Error::UNTRUSTED)
        }
        // No grant is accepted in this callback/lifetime test; real crypto is
        // exercised by the shared C corpus and lifecycle tests.
        fn sha256(&mut self, _: &[u8], d: &mut [u8; 32]) -> Result<(), Error> {
            d.fill(7);
            Ok(())
        }
        fn verify_es256(
            &mut self,
            _: &[u8; 32],
            _: &[u8; 32],
            _: &[u8; 32],
            _: &[u8; 64],
        ) -> Result<(), Error> {
            Err(Error::UNTRUSTED)
        }
    }
    fn config() -> Config<'static> {
        Config {
            api_origin: "https://example.com",
            issuer: "https://example.com",
            application_id: "app",
            environment_id: "env",
            fingerprint: "",
            fingerprint_provider: "",
        }
    }
    #[test]
    fn lifecycle_callbacks_and_drop() {
        let mut b = Buffers::new();
        let mut p = Host {
            record: [0; 1024],
            length: 0,
            commits: 0,
            posts: 0,
        };
        {
            let mut c = Client::new(&mut b, &mut p, config()).unwrap();
            assert_eq!(c.tick(), Err(Error::ACTIVATION_REQUIRED));
            assert_eq!(c.activate("example-key"), Err(Error::TRANSIENT));
            assert!(!c.snapshot().unwrap().allowed());
        }
        assert!(b.state.0.iter().all(|b| *b == 0));
        assert_eq!(p.commits, 2);
        assert_eq!(p.posts, 1);
        let mut c = Client::new(&mut b, &mut p, config()).unwrap();
        assert_eq!(c.tick(), Err(Error::PENDING));
        assert_eq!(c.activate("example-key"), Err(Error::TRANSIENT));
        c.invalidate().unwrap();
        assert_eq!(c.tick(), Err(Error::ACTIVATION_REQUIRED));
    }
}
