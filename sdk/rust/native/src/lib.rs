//! Narrow native OS boundary for the otherwise safe Orbit SDK.

#[cfg(target_os = "windows")]
mod data_protection;
#[cfg(target_os = "windows")]
pub use data_protection::{protect_user_data, unprotect_user_data};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{awake_clock, elapsed_clock, full_fsync, platform_uuid};

#[cfg(any(target_os = "macos", test))]
pub(crate) fn normalize_macos_platform_uuid(value: &[u8], source_length: usize) -> Option<String> {
    if !(1..=256).contains(&source_length)
        || value.len() != source_length
        || !value.is_ascii()
        || value.contains(&0)
    {
        return None;
    }
    let value = std::str::from_utf8(value).ok()?;
    Some(
        value
            .trim_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}'])
            .to_owned(),
    )
}

pub fn checked_mach_duration(
    ticks: u64,
    numerator: u32,
    denominator: u32,
) -> Option<std::time::Duration> {
    if numerator == 0 || denominator == 0 {
        return None;
    }
    let nanoseconds = (ticks as u128).checked_mul(numerator as u128)? / denominator as u128;
    let seconds = u64::try_from(nanoseconds / 1_000_000_000).ok()?;
    Some(std::time::Duration::new(
        seconds,
        (nanoseconds % 1_000_000_000) as u32,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn mach_conversion_checks_timebase_and_duration_overflow() {
        assert_eq!(
            super::checked_mach_duration(3, 125, 3),
            Some(std::time::Duration::from_nanos(125))
        );
        assert!(super::checked_mach_duration(1, 0, 1).is_none());
        assert!(super::checked_mach_duration(1, 1, 0).is_none());
        assert!(super::checked_mach_duration(u64::MAX, u32::MAX, 1).is_none());
    }

    #[test]
    fn macos_platform_uuid_requires_complete_bounded_ascii() {
        let padded = b" \t00112233-4455-6677-8899-AABBCCDDEEFF\r\n";
        assert_eq!(
            super::normalize_macos_platform_uuid(padded, padded.len()).as_deref(),
            Some("00112233-4455-6677-8899-AABBCCDDEEFF")
        );
        let embedded_nul = b"00112233\0-4455-6677-8899-AABBCCDDEEFF";
        assert!(super::normalize_macos_platform_uuid(embedded_nul, embedded_nul.len()).is_none());
        let non_ascii = b"00112233-4455-6677-8899-AABBCCDDEEF\xc3\xa9";
        assert!(super::normalize_macos_platform_uuid(non_ascii, non_ascii.len()).is_none());
        assert!(super::normalize_macos_platform_uuid(b"short", 4).is_none());
        assert!(super::normalize_macos_platform_uuid(&vec![b'a'; 257], 257).is_none());
    }
}

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
mod windows_tests {
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

#[cfg(target_os = "windows")]
mod private_storage;
#[cfg(target_os = "windows")]
pub use private_storage::{
    create_private_storage_directory, create_private_storage_file, private_storage_object,
    process_user_context, storage_file_single_link,
};
