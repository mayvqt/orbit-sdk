//! The table walker is platform independent; Windows acquisition is a separate gate.
use std::io::{BufReader, Read};

#[test]
#[ignore = "requires a bounded ORBIT_PARSER_FUZZ_INPUT corpus"]
fn bounded_parser_fuzz() {
    let input = std::env::var_os("ORBIT_PARSER_FUZZ_INPUT").expect("explicit corpus required");
    let mut reader = BufReader::new(std::fs::File::open(input).unwrap());
    let mut count = 0_u64;
    let mut accepted = 0_u64;
    let mut longest = std::time::Duration::ZERO;
    loop {
        let mut mode = [0_u8];
        if reader.read(&mut mode).unwrap() == 0 {
            break;
        }
        let mut frame = [0_u8; 5];
        reader.read_exact(&mut frame).unwrap();
        let length = u32::from_le_bytes(frame[1..].try_into().unwrap()) as usize;
        assert!(length <= super::MAX_RAW_TABLE_BYTES + 1 && mode[0] <= 1 && frame[0] <= 2);
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).unwrap();
        let (identity, raw) = if mode[0] == 1 {
            bytes.split_at(36)
        } else {
            (&[][..], bytes.as_slice())
        };
        let started = std::time::Instant::now();
        let result = std::panic::catch_unwind(|| {
            let result = super::parse_uuid(raw);
            if let Some(uuid) = &result {
                assert!((8..=super::MAX_RAW_TABLE_BYTES).contains(&raw.len()));
                assert!((raw[1], raw[2]) >= (2, 6));
                assert_eq!(
                    u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize,
                    raw.len() - 8
                );
                assert_eq!(uuid.len(), 36);
                for (offset, byte) in uuid.bytes().enumerate() {
                    if matches!(offset, 8 | 13 | 18 | 23) {
                        assert_eq!(byte, b'-');
                    } else {
                        assert!(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                    }
                }
                if mode[0] == 1 {
                    assert_eq!(uuid.as_bytes(), identity);
                }
            }
            if frame[0] != 2 {
                assert_eq!(result.is_some(), frame[0] == 1);
            }
            result.is_some()
        })
        .unwrap_or_else(|_| panic!("reproducer record {count}"));
        let elapsed = started.elapsed();
        longest = longest.max(elapsed);
        assert!(elapsed.as_secs() < 2, "slow record {count}");
        count += 1;
        accepted += u64::from(result);
    }
    assert!(count > 0 && accepted > 0, "incomplete corpus");
    println!(
        "ORBIT_FUZZ_RESULT cases={count} accepted={accepted} max_case_us={}",
        longest.as_micros()
    );
}
