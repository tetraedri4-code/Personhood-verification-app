//! The time a holder app goes by for its like windows: not the device's clock, which may be far off,
//! but the middle of the times the issuer, the directory and the relay state in their answers. Taking
//! one server's word would let that server give some clients another time and then recognise their
//! likes by when they arrive (outside everyone else's windows); one lying server cannot move the middle
//! of three. With no relay there are two servers, and the device's clock is the third vote.
//!
//! The device's clock is only a stopwatch: the clock keeps how far each server was from it when its
//! answer came.
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Issuer = 0,
    Directory = 1,
    Relay = 2,
}

#[derive(Default)]
pub struct Clock {
    /// each source's time minus the device's, in milliseconds
    offsets: Mutex<[Option<i64>; 3]>,
}

fn device_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Clock {
    pub fn new() -> Self {
        Self::default()
    }

    /// An answer from `src` said it was `unix_secs` (an HTTP date, whole seconds: taken as the middle of
    /// that second).
    pub fn observe(&self, src: Source, unix_secs: u64) {
        self.observe_ms(src, unix_secs as i64 * 1000 + 500, device_ms());
    }

    /// The HTTP `Date` header value of an answer from `src`, if it parses.
    pub fn observe_http_date(&self, src: Source, value: &str) {
        if let Ok(t) = httpdate::parse_http_date(value.trim()) {
            if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                self.observe(src, d.as_secs());
            }
        }
    }

    fn observe_ms(&self, src: Source, server_ms: i64, device: i64) {
        self.offsets.lock().unwrap()[src as usize] = Some(server_ms - device);
    }

    /// How far to move the device's clock: the middle of the servers' offsets, with the device's own
    /// (0) as a vote when fewer than three servers have answered; with two votes, their average.
    pub fn offset_ms(&self) -> i64 {
        let mut v: Vec<i64> = self.offsets.lock().unwrap().iter().flatten().copied().collect();
        if v.len() < 3 {
            v.push(0);
        }
        median(v)
    }

    /// The sources that have answered so far.
    pub fn sources(&self) -> Vec<Source> {
        let o = self.offsets.lock().unwrap();
        [Source::Issuer, Source::Directory, Source::Relay].into_iter().filter(|s| o[*s as usize].is_some()).collect()
    }

    /// Now, in Unix milliseconds, by this clock.
    pub fn now_ms(&self) -> u64 {
        (device_ms() + self.offset_ms()).max(0) as u64
    }
}

fn median(mut v: Vec<i64>) -> i64 {
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        // n is 2 here (three servers never give an even count with the device's vote)
        (v[n / 2 - 1] + v[n / 2]) / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_lying_server_does_not_move_the_clock() {
        let c = Clock::new();
        assert_eq!(c.offset_ms(), 0, "no answers yet: the device's clock");
        // the device is an hour slow; the issuer and the relay agree, the directory lies by ten minutes
        c.observe_ms(Source::Issuer, 3_600_000, 0);
        c.observe_ms(Source::Relay, 3_600_400, 0);
        c.observe_ms(Source::Directory, 4_200_000, 0);
        assert_eq!(c.offset_ms(), 3_600_400);
        // a lie in the other direction does not move it either
        c.observe_ms(Source::Directory, -10_000_000, 0);
        assert_eq!(c.offset_ms(), 3_600_000);
    }

    #[test]
    fn without_a_relay_the_device_votes() {
        let c = Clock::new();
        c.observe_ms(Source::Issuer, 1_000, 0);
        c.observe_ms(Source::Directory, 1_200, 0);
        assert_eq!(c.offset_ms(), 1_000, "middle of 0, 1000 and 1200");
        let c = Clock::new();
        c.observe_ms(Source::Issuer, 600, 0);
        assert_eq!(c.offset_ms(), 300, "one server and the device: their average");
    }

    #[test]
    fn http_dates_parse() {
        let c = Clock::new();
        let later = SystemTime::now() + std::time::Duration::from_secs(3600);
        c.observe_http_date(Source::Issuer, &httpdate::fmt_http_date(later));
        let off = c.offsets.lock().unwrap()[0].unwrap();
        assert!((off - 3_600_000).abs() < 2_000, "{off}");
        c.observe_http_date(Source::Directory, "garbage");
        assert!(c.offsets.lock().unwrap()[1].is_none());
    }
}
