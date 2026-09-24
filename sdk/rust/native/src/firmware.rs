//! Bounded SMBIOS identity extraction; OS buffers and raw UUIDs stay internal.

#[cfg(test)]
#[path = "firmware_fuzz.rs"]
mod fuzz;

const MAX_RAW_TABLE_BYTES: usize = 1024 * 1024;

#[cfg(target_os = "windows")]
pub fn machine_uuid() -> Option<String> {
    use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

    // SAFETY: The documented size query takes a null pointer with zero capacity
    // and does not write through it. RSMB/table 0 selects the raw SMBIOS table.
    let required = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) };
    if !(8..=MAX_RAW_TABLE_BYTES).contains(&(required as usize)) {
        return None;
    }
    let mut raw = vec![0_u8; required as usize];
    // SAFETY: `raw` is initialized and writable for exactly `required` bytes,
    // remains alive for this synchronous call, and is not resized or aliased.
    let read = unsafe { GetSystemFirmwareTable(RSMB, 0, raw.as_mut_ptr(), required) };
    if read != required {
        return None;
    }
    parse_uuid(&raw)
}

fn parse_uuid(raw: &[u8]) -> Option<String> {
    if !(8..=MAX_RAW_TABLE_BYTES).contains(&raw.len()) || (raw[1], raw[2]) < (2, 6) {
        return None;
    }
    let declared = u32::from_le_bytes(raw[4..8].try_into().ok()?) as usize;
    let payload = &raw[8..];
    if declared != payload.len() {
        return None;
    }
    let mut cursor = 0;
    let mut identity = None;
    while cursor < payload.len() {
        let header = payload.get(cursor..cursor + 4)?;
        let length = usize::from(header[1]);
        if length < 4 {
            return None;
        }
        let formatted_end = cursor + length;
        let record = payload.get(cursor..formatted_end)?;
        let strings = payload.get(formatted_end..)?;
        let terminated = strings.windows(2).position(|bytes| bytes == [0, 0])?;
        cursor = formatted_end + terminated + 2;
        match header[0] {
            1 => {
                if identity.is_some() || length < 25 {
                    return None;
                }
                let mut uuid: [u8; 16] = record[8..24].try_into().ok()?;
                if uuid.iter().all(|byte| *byte == 0) || uuid.iter().all(|byte| *byte == 255) {
                    return None;
                }
                uuid[..4].reverse();
                uuid[4..6].reverse();
                uuid[6..8].reverse();
                let mut canonical = String::with_capacity(36);
                for (index, byte) in uuid.iter().enumerate() {
                    use std::fmt::Write;
                    if matches!(index, 4 | 6 | 8 | 10) {
                        canonical.push('-');
                    }
                    write!(&mut canonical, "{byte:02x}").ok()?;
                }
                identity = Some(canonical);
            }
            127 => return identity,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const END: [u8; 6] = [127, 4, 0xff, 0xff, 0, 0];

    fn system_record() -> Vec<u8> {
        let mut record = vec![1, 25, 0, 0, 1, 2, 3, 4];
        record.extend_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        record.push(6);
        record.extend_from_slice(b"manufacturer\0product\0version\0serial\0\0");
        record
    }

    fn table(payload: &[u8]) -> Vec<u8> {
        let mut raw = vec![0, 3, 8, 0];
        raw.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        raw.extend_from_slice(payload);
        raw
    }

    fn valid_payload() -> Vec<u8> {
        let mut payload = system_record();
        payload.extend_from_slice(&END);
        payload
    }

    #[test]
    fn smbios_uuid_byte_order_and_record_boundaries() {
        let expected = Some("00112233-4455-6677-8899-aabbccddeeff".into());
        let mut raw = table(&valid_payload());
        assert_eq!(parse_uuid(&raw), expected);
        raw[1] = 2;
        raw[2] = 6;
        assert_eq!(parse_uuid(&raw), expected);

        let mut payload = vec![0, 5, 0, 0, 7, b'x', 0, 0];
        payload.extend_from_slice(&system_record());
        payload.extend_from_slice(&[42, 4, 1, 0, 0, 0]);
        payload.extend_from_slice(&END);
        // Firmware padding after the end marker has no record meaning.
        payload.extend_from_slice(&[1, 0xff, 0]);
        assert_eq!(parse_uuid(&table(&payload)), expected);
    }

    #[test]
    fn smbios_rejects_header_version_length_and_size_errors() {
        let valid = table(&valid_payload());
        for length in 0..8 {
            assert!(parse_uuid(&valid[..length]).is_none());
        }
        for version in [(0, 0), (1, 255), (2, 5)] {
            let mut raw = valid.clone();
            raw[1] = version.0;
            raw[2] = version.1;
            assert!(parse_uuid(&raw).is_none());
        }
        for delta in [-1_i32, 1] {
            let mut raw = valid.clone();
            let length = (raw.len() as i32 - 8 + delta) as u32;
            raw[4..8].copy_from_slice(&length.to_le_bytes());
            assert!(parse_uuid(&raw).is_none());
        }
        assert!(parse_uuid(&vec![0; MAX_RAW_TABLE_BYTES + 1]).is_none());
    }

    #[test]
    fn smbios_rejects_truncated_records_and_missing_string_terminators() {
        let payload = valid_payload();
        for length in 0..payload.len() {
            assert!(parse_uuid(&table(&payload[..length])).is_none());
        }
        for length in [0, 1, 2, 3, 24, 255] {
            let mut payload = valid_payload();
            payload[1] = length;
            assert!(parse_uuid(&table(&payload)).is_none());
        }
        let mut unterminated = system_record();
        unterminated.pop();
        unterminated.extend_from_slice(&END);
        assert!(parse_uuid(&table(&unterminated)).is_none());
    }

    #[test]
    fn smbios_requires_one_identity_before_a_complete_end_record() {
        assert!(parse_uuid(&table(&END)).is_none());
        assert!(parse_uuid(&table(&system_record())).is_none());
        let mut duplicate = system_record();
        duplicate.extend_from_slice(&system_record());
        duplicate.extend_from_slice(&END);
        assert!(parse_uuid(&table(&duplicate)).is_none());
        for unavailable in [0, 255] {
            let mut payload = valid_payload();
            payload[8..24].fill(unavailable);
            assert!(parse_uuid(&table(&payload)).is_none());
        }
    }

    fn assert_canonical(uuid: &str) {
        assert_eq!(uuid.len(), 36);
        for (index, byte) in uuid.bytes().enumerate() {
            if matches!(index, 8 | 13 | 18 | 23) {
                assert_eq!(byte, b'-');
            } else {
                assert!(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            }
        }
    }

    fn next_byte(state: &mut u32) -> u8 {
        *state ^= *state << 13;
        *state ^= *state >> 17;
        *state ^= *state << 5;
        (*state >> 24) as u8
    }

    #[test]
    fn smbios_mutation_truncations_cover_raw_and_declared_record_boundaries() {
        let mut surrounded = vec![42, 4, 0, 0, b'x', 0, 0];
        surrounded.extend_from_slice(&system_record());
        surrounded.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
        surrounded.extend_from_slice(&END);
        for payload in [valid_payload(), surrounded] {
            let raw = table(&payload);
            assert_canonical(&parse_uuid(&raw).unwrap());
            for end in 0..raw.len() {
                assert!(parse_uuid(&raw[..end]).is_none(), "raw cut {end}");
            }
            // Repair the outer byte count so every inner record/string/end
            // truncation also reaches the actual table walker.
            for end in 0..payload.len() {
                assert!(
                    parse_uuid(&table(&payload[..end])).is_none(),
                    "table cut {end}"
                );
            }
        }
    }

    #[test]
    fn smbios_mutation_structure_preserves_only_the_known_system_identity() {
        let raw = table(&valid_payload());
        let expected = parse_uuid(&raw).unwrap();
        let end_record = raw.len() - END.len();
        let system_terminator = 8 + system_record().len() - 2;
        // 14 independently mutated bytes, all 256 values: 3,584 cases.
        let fields = [
            1,
            2,
            4,
            5,
            6,
            7,
            8,
            9,
            end_record,
            end_record + 1,
            system_terminator,
            system_terminator + 1,
            raw.len() - 2,
            raw.len() - 1,
        ];
        for offset in fields {
            for byte in 0..=u8::MAX {
                let mut changed = raw.clone();
                changed[offset] = byte;
                let parsed = parse_uuid(&changed);
                if let Some(uuid) = &parsed {
                    assert_canonical(uuid);
                    assert_eq!(uuid, &expected, "structural offset {offset}, byte {byte}");
                }
                if offset == 1 || offset == 2 {
                    assert_eq!(parsed.is_some(), (changed[1], changed[2]) >= (2, 6));
                } else if offset != 9 {
                    assert_eq!(
                        parsed.is_some(),
                        byte == raw[offset],
                        "structural offset {offset}, byte {byte}"
                    );
                } else if byte < 25 {
                    assert!(parsed.is_none());
                }
            }
        }
    }

    #[test]
    fn smbios_mutation_uuid_bytes_match_the_known_record() {
        let raw = table(&valid_payload());
        let expected = "00112233-4455-6677-8899-aabbccddeeff";
        // Text positions of the 16 firmware bytes after SMBIOS 2.6 ordering.
        let positions = [6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];
        for (index, position) in positions.into_iter().enumerate() {
            for byte in 0..=u8::MAX {
                let mut changed = raw.clone();
                changed[16 + index] = byte;
                let mut known = expected.to_owned();
                known.replace_range(position..position + 2, &format!("{byte:02x}"));
                let parsed = parse_uuid(&changed).unwrap();
                assert_canonical(&parsed);
                assert_eq!(parsed, known, "UUID byte {index}, value {byte}");
            }
        }
    }

    #[test]
    fn smbios_mutation_bounded_arbitrary_tables_do_not_panic() {
        const CASES: usize = 4096;
        const MAX_BYTES: usize = 4096;
        let mut state = 0x6f72_6269_u32;
        for case in 0..CASES {
            let length = case * 2053 % (MAX_BYTES + 1);
            let mut raw: Vec<_> = (0..length).map(|_| next_byte(&mut state)).collect();
            // Half the corpus has a valid wrapper, so rejection must proceed
            // through record lengths and terminators rather than only headers.
            if case % 2 == 0 && raw.len() >= 8 {
                raw[1..3].copy_from_slice(&[2, 6]);
                raw[4..8].copy_from_slice(&((length - 8) as u32).to_le_bytes());
            }
            if let Some(uuid) = parse_uuid(&raw) {
                assert_canonical(&uuid);
            }
        }
    }
}
