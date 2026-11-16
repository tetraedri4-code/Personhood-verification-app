//! Scheme dates. A `Day` counts days since the scheme epoch, 1 January 2026 (UTC). Every date attribute
//! in a credential is a Day, which keeps all range proofs inside 16 bits until the year 2205.
//! Quarters are calendar quarters, numbered from 0 = 2026 Q1.

pub type Day = u32;

/// Unix time of the scheme epoch, 2026-01-01T00:00:00Z.
pub const EPOCH_UNIX: i64 = 1_767_225_600;

/// Lease length of a badge, nine months (design §4.5), in days.
pub const LEASE_DAYS: u32 = 274;
/// Probation: a fresh secret is not counted for nine months (design §4.5).
pub const PROBATION_DAYS: u32 = 274;
/// Re-check period, 24 months (design §4.6), in days.
pub const RECHECK_DAYS: u32 = 730;
/// A credential that expired less than 12 months ago can still renew (design §4.6).
pub const RENEW_GRACE_DAYS: u32 = 365;

pub fn day_from_unix(secs: i64) -> Day {
    ((secs - EPOCH_UNIX).div_euclid(86_400)).max(0) as Day
}

pub fn today() -> Day {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(EPOCH_UNIX);
    day_from_unix(now)
}

/// Civil date (year, month 1-12, day 1-31) of a scheme day (H. Hinnant's algorithm).
pub fn civil(day: Day) -> (i32, u32, u32) {
    let z = day as i64 + 20_454 + 719_468; // days since 1970-01-01, shifted to 0000-03-01
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((y + if m <= 2 { 1 } else { 0 }) as i32, m, d)
}

/// Scheme day of a civil date.
pub fn from_civil(y: i32, m: u32, d: u32) -> Day {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_1970 = era * 146_097 + doe - 719_468;
    (days_1970 - 20_454).max(0) as Day
}

/// Calendar quarter index of a day (0 = 2026 Q1).
pub fn quarter_of(day: Day) -> u32 {
    let (y, m, _) = civil(day);
    ((y - 2026) * 4) as u32 + (m - 1) / 3
}

pub fn quarter_start(q: u32) -> Day {
    from_civil(2026 + (q / 4) as i32, (q % 4) * 3 + 1, 1)
}

pub fn quarter_end(q: u32) -> Day {
    quarter_start(q + 1) - 1
}

pub fn month_start(day: Day) -> Day {
    let (y, m, _) = civil(day);
    from_civil(y, m, 1)
}

/// The calendar quarters a lease starting on `from` touches: always four, so the statement shape is fixed.
pub fn lease_quarters(from: Day) -> [u32; 4] {
    let q = quarter_of(from);
    [q, q + 1, q + 2, q + 3]
}

pub fn fmt_day(day: Day) -> String {
    let (y, m, d) = civil(day);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calendar() {
        assert_eq!(civil(0), (2026, 1, 1));
        assert_eq!(from_civil(2026, 11, 15), 318);
        assert_eq!(civil(318), (2026, 11, 15));
        assert_eq!(quarter_of(318), 3);
        assert_eq!(quarter_start(4), from_civil(2027, 1, 1));
        assert_eq!(quarter_end(3), from_civil(2026, 12, 31));
        assert_eq!(day_from_unix(EPOCH_UNIX + 86_400 * 318 + 5), 318);
        for d in [0u32, 59, 60, 365, 1000, 20000] {
            let (y, m, dd) = civil(d);
            assert_eq!(from_civil(y, m, dd), d);
        }
    }
}
