//! macOS identity, sleep-inclusive clock, and full-flush operations.
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::OnceLock,
    time::Duration,
};

const UTF8_ENCODING: u32 = 0x0800_0100;
const F_FULLFSYNC: c_int = 51;

#[repr(C)]
struct Timebase {
    numerator: u32,
    denominator: u32,
}

#[link(name = "System")]
unsafe extern "C" {
    fn mach_timebase_info(info: *mut Timebase) -> c_int;
    fn mach_continuous_time() -> u64;
    fn mach_absolute_time() -> u64;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
}

type CFType = *const c_void;
type CFMutableDictionary = *mut c_void;
type IoService = u32;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOServiceMatching(name: *const c_char) -> CFMutableDictionary;
    fn IOServiceGetMatchingService(master_port: u32, matching: CFMutableDictionary) -> IoService;
    fn IORegistryEntryCreateCFProperty(
        entry: IoService,
        key: CFType,
        allocator: CFType,
        options: u32,
    ) -> CFType;
    fn IOObjectRelease(object: IoService) -> c_int;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(allocator: CFType, text: *const c_char, encoding: u32) -> CFType;
    fn CFStringGetTypeID() -> usize;
    fn CFGetTypeID(value: CFType) -> usize;
    fn CFStringGetLength(value: CFType) -> isize;
    fn CFStringGetCString(value: CFType, buffer: *mut c_char, capacity: isize, encoding: u32)
    -> u8;
    fn CFRelease(value: CFType);
}

static TIMEBASE: OnceLock<Option<(u32, u32)>> = OnceLock::new();

fn timebase() -> Option<(u32, u32)> {
    *TIMEBASE.get_or_init(|| {
        let mut value = Timebase {
            numerator: 0,
            denominator: 0,
        };
        // SAFETY: value is writable and remains live through the synchronous
        // Mach call. Success initializes both fields.
        if unsafe { mach_timebase_info(&mut value) } != 0
            || value.numerator == 0
            || value.denominator == 0
        {
            None
        } else {
            Some((value.numerator, value.denominator))
        }
    })
}

pub fn elapsed_clock() -> Option<Duration> {
    let (numerator, denominator) = timebase()?;
    // SAFETY: This argument-free Mach clock returns one scalar sample.
    let ticks = unsafe { mach_continuous_time() };
    crate::checked_mach_duration(ticks, numerator, denominator)
}

pub fn awake_clock() -> Duration {
    let (numerator, denominator) = timebase().expect("Mach timebase unavailable");
    // SAFETY: This argument-free Mach clock returns one scalar sample.
    let ticks = unsafe { mach_absolute_time() };
    crate::checked_mach_duration(ticks, numerator, denominator)
        .expect("awake clock conversion overflow")
}

pub fn full_fsync(file: &File) -> io::Result<()> {
    // SAFETY: F_FULLFSYNC takes no variadic argument; the borrowed descriptor
    // remains open for the synchronous call.
    if unsafe { fcntl(file.as_raw_fd(), F_FULLFSYNC) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct Service(IoService);
impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: This guard owns the service reference returned by IOKit.
        unsafe {
            IOObjectRelease(self.0);
        }
    }
}

struct CfOwned(CFType);
impl Drop for CfOwned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: This guard owns the CoreFoundation reference it releases.
            unsafe {
                CFRelease(self.0);
            }
        }
    }
}

pub fn platform_uuid() -> Option<String> {
    let matching_name = b"IOPlatformExpertDevice\0";
    // SAFETY: The matching class name is a static NUL-terminated C string.
    let matching = unsafe { IOServiceMatching(matching_name.as_ptr().cast()) };
    if matching.is_null() {
        return None;
    }
    // SAFETY: IOKit consumes the matching dictionary, even when no service is found.
    let service = unsafe { IOServiceGetMatchingService(0, matching) };
    if service == 0 {
        return None;
    }
    let service = Service(service);
    let key_name = b"IOPlatformUUID\0";
    // SAFETY: The property name is static UTF-8 and the default allocator is null.
    let key = unsafe {
        CFStringCreateWithCString(std::ptr::null(), key_name.as_ptr().cast(), UTF8_ENCODING)
    };
    if key.is_null() {
        return None;
    }
    let key = CfOwned(key);
    // SAFETY: The service and key guards retain valid references during lookup.
    let value = unsafe { IORegistryEntryCreateCFProperty(service.0, key.0, std::ptr::null(), 0) };
    if value.is_null() {
        return None;
    }
    let value = CfOwned(value);
    // SAFETY: value is a live CF object.
    if unsafe { CFGetTypeID(value.0) } != unsafe { CFStringGetTypeID() } {
        return None;
    }
    // SAFETY: value is known to be a CFString.
    let length = unsafe { CFStringGetLength(value.0) };
    if !(1..=256).contains(&length) {
        return None;
    }
    let mut buffer = [0 as c_char; 257];
    // SAFETY: buffer is writable for its full capacity and the source string
    // remains owned by value for the synchronous conversion.
    if unsafe {
        CFStringGetCString(
            value.0,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            UTF8_ENCODING,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: CoreFoundation guarantees NUL termination on successful conversion.
    let bytes = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_bytes();
    crate::normalize_macos_platform_uuid(bytes, length as usize)
}
