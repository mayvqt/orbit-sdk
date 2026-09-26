use crate::{Error, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn elapsed_clock() -> Result<Duration> {
    #[cfg(target_os = "linux")]
    {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        if now.tv_sec < 0 || now.tv_nsec < 0 {
            return Err(Error::ClockUncertain);
        }
        Ok(Duration::new(now.tv_sec as u64, now.tv_nsec as u32))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(orbit_sdk_native::elapsed_clock())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(Error::ClockUncertain)
    }
}
pub fn wall() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::ClockUncertain)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| Error::ClockUncertain)
}
pub struct Start {
    elapsed: Duration,
    wall: i64,
}
impl Start {
    pub fn capture() -> Result<Self> {
        Ok(Self {
            elapsed: elapsed_clock()?,
            wall: wall()?,
        })
    }
}
#[derive(Clone)]
pub struct Anchor {
    server: i64,
    elapsed: Duration,
    wall: i64,
}
impl Anchor {
    pub fn from_request(server: i64, start: Start) -> Self {
        Self {
            server,
            elapsed: start.elapsed,
            wall: start.wall,
        }
    }
    pub(crate) fn receipt(&self) -> (i64, i64) {
        (self.server, self.wall)
    }
    pub(crate) fn restored(server: i64, wall: i64) -> Result<Self> {
        Ok(Self {
            server,
            wall,
            elapsed: elapsed_clock()?,
        })
    }
    pub fn now(&self) -> Result<i64> {
        let elapsed = elapsed_clock()?
            .checked_sub(self.elapsed)
            .ok_or(Error::ClockUncertain)?;
        let seconds = i64::try_from(elapsed.as_secs()).map_err(|_| Error::ClockUncertain)?;
        let expected = self
            .wall
            .checked_add(seconds)
            .ok_or(Error::ClockUncertain)?;
        if wall()?.abs_diff(expected) > 30 {
            return Err(Error::ClockUncertain);
        }
        self.server
            .checked_add(seconds)
            .ok_or(Error::ClockUncertain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "manual native suspend/hibernate check; see docs/development/validation.md"]
    fn native_suspend_advances_the_sdk_clock() {
        use std::io::{self, Write};
        let monotonic = || {
            let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
            Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
        };
        let active_start = monotonic();
        let sdk_start = elapsed_clock().unwrap();
        print!(
            "Manually suspend or hibernate for at least two seconds, resume, then press Enter. This test never suspends the machine.\n> "
        );
        io::stdout().flush().unwrap();
        assert!(
            io::stdin().read_line(&mut String::new()).unwrap() > 0,
            "No acknowledgement"
        );
        let elapsed = elapsed_clock().unwrap().checked_sub(sdk_start).unwrap();
        let active = monotonic().checked_sub(active_start).unwrap();
        assert!(
            elapsed.saturating_sub(active) >= Duration::from_secs(1),
            "No suspend interval observed; evidence incomplete"
        );
        println!("SDK elapsed={elapsed:?}, active elapsed={active:?}");
    }

    #[test]
    fn elapsed_resume_time_is_not_fresh_offline_time() {
        let elapsed = elapsed_clock().unwrap();
        if let Some(start) = elapsed.checked_sub(Duration::from_secs(3600)) {
            let anchor = Anchor {
                server: 1_800_000_000,
                elapsed: start,
                wall: wall().unwrap() - 3600,
            };
            assert!(anchor.now().unwrap() >= 1_800_003_600);
        } else {
            // A short-uptime host still verifies a future/invalid native anchor fails closed.
            let anchor = Anchor {
                server: 1_800_000_000,
                elapsed: elapsed + Duration::from_secs(3600),
                wall: wall().unwrap(),
            };
            assert!(anchor.now().is_err());
        }
        let rollback = Anchor {
            server: 1_800_000_000,
            elapsed,
            wall: wall().unwrap() + 60,
        };
        assert!(rollback.now().is_err());
    }
}
