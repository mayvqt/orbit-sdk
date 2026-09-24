//! Narrow native OS boundary for the otherwise safe Orbit SDK.

#[cfg(target_os = "windows")]
mod data_protection;
#[cfg(target_os = "windows")]
pub use data_protection::{protect_user_data, unprotect_user_data};

#[cfg(target_os = "windows")]
mod storage;
#[cfg(target_os = "windows")]
pub use storage::{STORAGE_CIPHERTEXT_FILE, is_local_storage_drive, replace_storage_ciphertext};

#[cfg(any(target_os = "windows", test))]
mod firmware;
#[cfg(target_os = "windows")]
pub use firmware::machine_uuid;

#[cfg(target_os = "windows")]
pub fn elapsed_clock() -> std::time::Duration {
    let mut ticks = 0_u64;
    // SAFETY: Windows 11 provides this function. The aligned, writable u64
    // remains valid for the synchronous call, which always initializes it.
    // Biased interrupt time includes sleep/hibernate; never substitute QPC or
    // QueryUnbiasedInterruptTime here. Ticks are 100 ns, not nanoseconds.
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::QueryInterruptTimePrecise(&mut ticks);
    }
    std::time::Duration::new(ticks / 10_000_000, ((ticks % 10_000_000) * 100) as u32)
}

/// Native awake time for explicit suspend-validation fixtures. Access decisions
/// must use `elapsed_clock`, which includes sleep and hibernation.
#[cfg(target_os = "windows")]
pub fn awake_clock() -> std::time::Duration {
    let mut ticks = 0_u64;
    // SAFETY: Windows 11 provides this function. The aligned, writable u64
    // remains valid for the synchronous call, which initializes the output.
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTimePrecise(
            &mut ticks,
        );
    }
    std::time::Duration::new(ticks / 10_000_000, ((ticks % 10_000_000) * 100) as u32)
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::time::Duration;

    #[test]
    #[ignore = "requires actual Windows S3/S4 sleep; see validation guide"]
    fn native_suspend_advances_the_sdk_clock() {
        let awake = awake_clock();
        let elapsed = elapsed_clock();
        println!("READY: suspend/hibernate for at least two seconds, then press Enter.");
        io::stdout().flush().unwrap();
        assert!(io::stdin().read_line(&mut String::new()).unwrap() > 0);
        let slept = elapsed_clock().checked_sub(elapsed).unwrap();
        let active = awake_clock().checked_sub(awake).unwrap();
        assert!(slept.saturating_sub(active) >= Duration::from_secs(1));
        println!("SDK elapsed={slept:?}, active elapsed={active:?}");
    }
}
