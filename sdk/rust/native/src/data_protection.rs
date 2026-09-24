//! Current-user DPAPI protection; no plaintext persistence or diagnostic output.

use std::sync::atomic::{Ordering, compiler_fence};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    },
};

const MAX_PLAINTEXT_BYTES: usize = 32 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_ENTROPY_BYTES: usize = 1024;

/// Protect bytes for the current Windows user, requiring caller-supplied scope entropy.
pub fn protect_user_data(plaintext: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES || !(1..=MAX_ENTROPY_BYTES).contains(&entropy.len()) {
        return None;
    }
    let input = input_blob(plaintext)?;
    let entropy = input_blob(entropy)?;
    let mut output = OwnedBlob::default();
    // SAFETY: Both input blobs borrow initialized slices for this synchronous
    // call. DPAPI documents these parameters as input-only. Output is initialized
    // and uniquely writable; its allocation is owned by the guard on every path.
    // Null description/prompt/reserved parameters request no additional output
    // or UI. Omitting LOCAL_MACHINE keeps protection in the current user's scope.
    let success = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };
    if success == 0 {
        return None;
    }
    output.copy_bounded(MAX_CIPHERTEXT_BYTES)
}

/// Unprotect bytes with the same current-user context and scope entropy.
pub fn unprotect_user_data(ciphertext: &[u8], entropy: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES || !(1..=MAX_ENTROPY_BYTES).contains(&entropy.len())
    {
        return None;
    }
    let input = input_blob(ciphertext)?;
    let entropy = input_blob(entropy)?;
    let mut output = OwnedBlob::default();
    // SAFETY: The input-only blobs borrow live initialized slices, and the
    // synchronous call receives a unique initialized output blob. A null
    // description-output pointer prevents a second native allocation. The guard
    // wipes and frees any returned output, including on failure or rejection.
    let success = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    };
    if success == 0 {
        return None;
    }
    output.copy_bounded(MAX_PLAINTEXT_BYTES)
}

fn input_blob(bytes: &[u8]) -> Option<CRYPT_INTEGER_BLOB> {
    Some(CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into().ok()?,
        // DATA_BLOB historically contains a mutable pointer, but DPAPI accepts
        // this blob only as an input parameter. Never write through this pointer
        // or retain the blob beyond the synchronous call and its borrowed slice.
        pbData: bytes.as_ptr().cast_mut(),
    })
}

#[derive(Default)]
struct OwnedBlob(CRYPT_INTEGER_BLOB);

impl OwnedBlob {
    fn copy_bounded(&self, maximum: usize) -> Option<Vec<u8>> {
        let length = self.0.cbData as usize;
        if length > maximum {
            return None;
        }
        if length == 0 {
            return Some(Vec::new());
        }
        if self.0.pbData.is_null() {
            return None;
        }
        // SAFETY: A successful DPAPI call supplies an initialized allocation of
        // cbData bytes. The live guard owns it exclusively; the checked limit
        // also keeps this slice below isize::MAX on supported Windows targets.
        Some(unsafe { std::slice::from_raw_parts(self.0.pbData, length) }.to_vec())
    }
}

impl Drop for OwnedBlob {
    fn drop(&mut self) {
        if self.0.pbData.is_null() {
            return;
        }
        // SecureZeroMemory/RtlSecureZeroMemory is a Windows header-inline
        // routine, not an exported windows-sys function. Volatile byte stores
        // plus the compiler fence provide the equivalent non-elidable wipe.
        // SAFETY: DPAPI owns allocation/length consistency even when it reports
        // an error. This guard alone owns the returned allocation until LocalFree.
        // Wipe the entire native blob, including one rejected by our size limits.
        unsafe {
            for index in 0..self.0.cbData as usize {
                self.0.pbData.add(index).write_volatile(0);
            }
            compiler_fence(Ordering::SeqCst);
            let _ = LocalFree(self.0.pbData.cast());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8] = b"orbit-dpapi-test\napp\ntest\ninstallation";

    #[test]
    fn dpapi_current_user_round_trip_and_input_bounds() {
        for plaintext in [
            Vec::new(),
            b"synthetic credential bytes\0\xff".to_vec(),
            vec![0x5a; MAX_PLAINTEXT_BYTES],
        ] {
            let ciphertext = protect_user_data(&plaintext, ENTROPY)
                .expect("DPAPI requires an available Windows user profile");
            assert!(!ciphertext.is_empty());
            assert!(ciphertext.len() <= MAX_CIPHERTEXT_BYTES);
            assert_eq!(
                unprotect_user_data(&ciphertext, ENTROPY).unwrap(),
                plaintext
            );
        }
        let maximum_entropy = vec![0x6b; MAX_ENTROPY_BYTES];
        let ciphertext = protect_user_data(b"synthetic", &maximum_entropy).unwrap();
        assert_eq!(
            unprotect_user_data(&ciphertext, &maximum_entropy).unwrap(),
            b"synthetic"
        );
        for entropy in [Vec::new(), vec![0x6b; MAX_ENTROPY_BYTES + 1]] {
            assert!(protect_user_data(b"synthetic", &entropy).is_none());
            assert!(unprotect_user_data(&ciphertext, &entropy).is_none());
        }
        assert!(protect_user_data(&vec![0; MAX_PLAINTEXT_BYTES + 1], ENTROPY).is_none());
        assert!(unprotect_user_data(&vec![0; MAX_CIPHERTEXT_BYTES + 1], ENTROPY).is_none());
    }

    #[test]
    fn dpapi_rejects_wrong_entropy_and_corrupted_ciphertext() {
        let ciphertext = protect_user_data(b"synthetic credential", ENTROPY).unwrap();
        assert!(unprotect_user_data(&ciphertext, b"different scope entropy").is_none());
        assert!(unprotect_user_data(&ciphertext[..1], ENTROPY).is_none());
        let mut corrupted = ciphertext;
        // Flip the final integrity byte, matching the Go fixture. Arbitrary
        // opaque header mutations are not guaranteed to be rejected by DPAPI.
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(unprotect_user_data(&corrupted, ENTROPY).is_none());
    }

    #[test]
    fn dpapi_rejects_oversized_native_plaintext_output() {
        // Create a valid external blob just above this SDK's plaintext limit.
        // This raw test call intentionally bypasses the public protect limit.
        let plaintext = vec![0x5a; MAX_PLAINTEXT_BYTES + 1];
        let input = input_blob(&plaintext).unwrap();
        let entropy = input_blob(ENTROPY).unwrap();
        let mut output = OwnedBlob::default();
        // SAFETY: Same live input-only slices and uniquely guarded output as the
        // production call; only the test's input length differs by one byte.
        let success = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        };
        assert_ne!(
            success, 0,
            "DPAPI requires an available Windows user profile"
        );
        let ciphertext = output.copy_bounded(MAX_CIPHERTEXT_BYTES).unwrap();
        assert!(unprotect_user_data(&ciphertext, ENTROPY).is_none());
    }
}
