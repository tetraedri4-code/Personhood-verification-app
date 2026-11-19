//! The issuer's policy: every number the scheme's rules chose for replacement, theft reports, the alarm,
//! revocation and backups, as settings of one deployment (`IssuerConfig::policy`, the `policy` section
//! of the issuer's configuration file). The defaults are the values agreed for the prototype
//! (docs/recovery.md); `GET /v1/policy` publishes the settings in force, so that anyone can check the
//! rules a deployment applies.
//!
//! Not here, because they are part of the proof statement every holder and verifier checks, and changing
//! them means new proving keys for everyone: the two-year re-check (`dates::RECHECK_DAYS`) and the
//! twelve months an expired credential can still renew (`dates::RENEW_GRACE_DAYS`). The badge lease is a
//! setting of the directory (`DirectoryConfig::lease_days`).
use crate::reports::AlarmRule;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Replacement without the old guardian key: days the request waits, during which a re-check with
    /// the old app cancels it.
    pub replace_wait_days: u32,
    /// Days after the wait in which the replacement must be collected.
    pub claim_window_days: u32,
    /// A person can replace the secret at most this often (each replacement adds a handle to the
    /// revocation list for good).
    pub replace_min_interval_days: u32,
    /// Probation of a replaced secret, from the Monday of the week it is issued. A whole number of
    /// weeks, so that the date it counts from is a Monday and tells only the week.
    pub probation_days: u32,
    /// Probation of the new secret after the first theft report in the allowance period; rounded up to
    /// a Monday.
    pub report_probation_days: u32,
    /// Days in which the replaced secret can block a replacement made after a theft report.
    pub contest_days: u32,
    /// One quick replacement after a theft report per person in this many days.
    pub fresh_replacement_interval_days: u32,
    /// One theft report per person counts in the public weekly totals in this many days.
    pub report_count_interval_days: u32,
    /// When theft reports raise the alarm.
    pub alarm: AlarmRule,
    /// Seconds for which proofs against the revocation root before the latest change are still taken.
    pub previous_root_grace_secs: u64,
    /// Largest encrypted backup accepted, in base64 characters.
    pub max_backup_chars: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            replace_wait_days: 90,
            claim_window_days: 90,
            replace_min_interval_days: 30,
            probation_days: 280,
            report_probation_days: 7,
            contest_days: 90,
            fresh_replacement_interval_days: 730,
            report_count_interval_days: 30,
            alarm: AlarmRule::default(),
            previous_root_grace_secs: 120,
            max_backup_chars: 44_000,
        }
    }
}

impl Policy {
    /// Refuse settings that would break a rule rather than only change a number.
    pub fn validate(&self) -> Result<(), String> {
        let positive = [
            ("replace_wait_days", self.replace_wait_days),
            ("claim_window_days", self.claim_window_days),
            ("replace_min_interval_days", self.replace_min_interval_days),
            ("report_probation_days", self.report_probation_days),
            ("contest_days", self.contest_days),
            ("fresh_replacement_interval_days", self.fresh_replacement_interval_days),
            ("report_count_interval_days", self.report_count_interval_days),
        ];
        for (name, v) in positive.into_iter().chain([("probation_days", self.probation_days)]) {
            // dates are 16-bit day numbers in the proofs, and sums of these must not overflow
            if v == 0 || v > 3650 {
                return Err(format!("policy.{name} must be between 1 and 3650 days"));
            }
        }
        if !self.probation_days.is_multiple_of(7) {
            return Err("policy.probation_days must be a whole number of weeks (a multiple of 7)".into());
        }
        if self.report_probation_days > self.probation_days {
            return Err("policy.report_probation_days cannot be longer than policy.probation_days".into());
        }
        // A thief's quick replacement must stay blockable at least until it counts.
        if self.contest_days <= self.report_probation_days {
            return Err("policy.contest_days must be longer than policy.report_probation_days".into());
        }
        // Otherwise a thief who keeps the eID could get a quick replacement again before the owner's
        // block of the last one has run out.
        if self.fresh_replacement_interval_days < self.contest_days {
            return Err("policy.fresh_replacement_interval_days cannot be shorter than policy.contest_days".into());
        }
        if !(1..=600).contains(&self.previous_root_grace_secs) {
            return Err("policy.previous_root_grace_secs must be between 1 and 600: a revoked secret keeps proving for that long".into());
        }
        if !(1_000..=1_000_000).contains(&self.max_backup_chars) {
            return Err("policy.max_backup_chars must be between 1000 and 1000000".into());
        }
        self.alarm.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_a_file_can_set_any_part() {
        Policy::default().validate().unwrap();
        let p: Policy = serde_json::from_str(r#"{"contest_days": 60, "alarm": {"min_reports": 50}}"#).unwrap();
        assert_eq!(p.contest_days, 60);
        assert_eq!(p.alarm.min_reports, 50);
        assert_eq!(p.alarm.factor, AlarmRule::default().factor);
        assert_eq!(p.replace_wait_days, 90);
        p.validate().unwrap();
        assert!(serde_json::from_str::<Policy>(r#"{"contest_dayz": 60}"#).is_err(), "a misspelt setting is an error, not a default");
    }

    #[test]
    fn settings_that_break_a_rule_are_refused() {
        let bad = |f: fn(&mut Policy)| {
            let mut p = Policy::default();
            f(&mut p);
            p.validate().is_err()
        };
        assert!(bad(|p| p.probation_days = 270));
        assert!(bad(|p| p.contest_days = 7));
        assert!(bad(|p| p.fresh_replacement_interval_days = 30));
        assert!(bad(|p| p.replace_wait_days = 0));
        assert!(bad(|p| p.fresh_replacement_interval_days = u32::MAX));
        assert!(bad(|p| p.probation_days = 7 * 1000));
        assert!(bad(|p| p.previous_root_grace_secs = 86_400));
        assert!(bad(|p| p.alarm.factor = 0));
        assert!(bad(|p| p.alarm.baseline_weeks = 0));
    }
}
