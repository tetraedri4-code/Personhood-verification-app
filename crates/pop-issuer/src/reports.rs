//! "It wasn't me" reports and the alarm they raise (docs/recovery.md §5).
//!
//! A person whose enrolment is refused because their identity is already enrolled, and who did not
//! enrol it, says so when they ask for a replacement. The issuer counts these reports per week and
//! publishes the counts (`GET /v1/reports`). When a week has clearly more than usual, the alarm is on:
//! the public cutoff moves back to four weeks before that week, and secrets that count from after the
//! cutoff (fresh enrolments, mostly) stop counting until the alarm ends. The rule is fixed and the
//! counts are public, so anyone can recompute the alarm.
use crate::service::{ApiErr, St};
use axum::{extract::State, Json};
use pop_crypto::{dates, Day};
use pop_protocol::api::Reports;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

pub(crate) const T_REPORTS: &str = "theft_reports";
/// Weeks shown in `GET /v1/reports`.
const SHOWN_WEEKS: u32 = 26;

/// The rule (part of [`crate::Policy`]). A week is high if its count is at least `min_reports` and
/// at least `factor` times the median of the `baseline_weeks` weeks before it. While any of the latest
/// `alarm_weeks` weeks is high, the cutoff is `reach_days` before the Monday of the earliest of them.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AlarmRule {
    pub min_reports: u64,
    pub factor: u64,
    /// the weeks before a week that set what "usual" is
    pub baseline_weeks: u32,
    /// the alarm stays on while any of this many latest weeks (the current one included) was high
    pub alarm_weeks: u32,
    /// how far before the first high week enrolments stop counting
    pub reach_days: u32,
}

impl Default for AlarmRule {
    fn default() -> Self {
        AlarmRule { min_reports: 20, factor: 3, baseline_weeks: 12, alarm_weeks: 4, reach_days: 28 }
    }
}

impl AlarmRule {
    pub fn validate(&self) -> Result<(), String> {
        if self.min_reports == 0 || self.factor == 0 {
            return Err("policy.alarm.min_reports and policy.alarm.factor must be at least 1".into());
        }
        if !(1..=104).contains(&self.baseline_weeks) || !(1..=52).contains(&self.alarm_weeks) {
            return Err("policy.alarm.baseline_weeks must be 1 to 104, and policy.alarm.alarm_weeks 1 to 52".into());
        }
        if self.reach_days > 366 {
            return Err("policy.alarm.reach_days must be at most 366".into());
        }
        Ok(())
    }

    pub fn describe(&self) -> String {
        format!(
            "A week is high if its count is at least {} and at least {} times the median of the {} weeks before it. \
             While any of the latest {} weeks is high, the cutoff is {} days before the Monday of the earliest of them.",
            self.min_reports, self.factor, self.baseline_weeks, self.alarm_weeks, self.reach_days
        )
    }

    /// The alarm cutoff on `today`, from weekly counts keyed by Monday.
    pub fn cutoff(&self, counts: &BTreeMap<Day, u64>, today: Day) -> Option<Day> {
        let this_week = dates::week_start(today);
        let count = |w: Day| counts.get(&w).copied().unwrap_or(0);
        let high = |w: Day| {
            let mut before: Vec<u64> = (1..=self.baseline_weeks).map(|i| w.checked_sub(7 * i).map_or(0, count)).collect();
            before.sort_unstable();
            let median = before[before.len() / 2];
            count(w) >= self.min_reports.max(self.factor.saturating_mul(median))
        };
        (0..self.alarm_weeks)
            .rev()
            .filter_map(|i| this_week.checked_sub(7 * i))
            .find(|w| high(*w))
            .map(|w| w.saturating_sub(self.reach_days))
    }
}

impl crate::service::Issuer {
    pub(crate) fn alarm_cutoff(&self) -> Option<Day> {
        self.cfg.policy.alarm.cutoff(&self.reports.read().unwrap(), self.today())
    }

    /// Count one report in this week. Called with the records lock held.
    pub(crate) async fn count_report(&self) -> anyhow::Result<()> {
        let w = dates::week_start(self.today());
        let n = self.reports.read().unwrap().get(&w).copied().unwrap_or(0) + 1;
        self.store.put(T_REPORTS, &w.to_string(), json!(n)).await?;
        self.reports.write().unwrap().insert(w, n);
        Ok(())
    }
}

pub(crate) async fn reports(State(s): State<St>) -> Result<Json<Reports>, ApiErr> {
    let this_week = dates::week_start(s.today());
    let counts = s.reports.read().unwrap().clone();
    let weeks = (0..SHOWN_WEEKS)
        .rev()
        .filter_map(|i| this_week.checked_sub(7 * i))
        .map(|w| (w, counts.get(&w).copied().unwrap_or(0)))
        .collect();
    Ok(Json(Reports { weeks, alarm_cutoff: s.alarm_cutoff(), rule: s.cfg.policy.alarm.describe() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule() {
        let r = AlarmRule { min_reports: 5, factor: 3, ..Default::default() };
        let today = dates::week_start(400) + 2;
        let w = dates::week_start(today);
        let mut c = BTreeMap::new();
        // a steady 4 a week: never high (below 3 x 4, and the minimum)
        for i in 0..20 {
            c.insert(w - 7 * i, 4);
        }
        assert_eq!(r.cutoff(&c, today), None);
        // a week with 12 (3 x the median) two weeks ago: cutoff 28 days before that Monday
        c.insert(w - 14, 12);
        assert_eq!(r.cutoff(&c, today), Some(w - 14 - 28));
        // still on with a later high week; the earliest high week in the window decides
        c.insert(w, 40);
        assert_eq!(r.cutoff(&c, today), Some(w - 14 - 28));
        // four weeks on, both have left the window and the 40 has raised the baseline only a little
        assert_eq!(r.cutoff(&c, today + 28), None);
        // with no history the minimum alone decides
        let mut fresh = BTreeMap::new();
        fresh.insert(w, 4);
        assert_eq!(r.cutoff(&fresh, today), None);
        fresh.insert(w, 5);
        assert_eq!(r.cutoff(&fresh, today), Some(w - 28));
    }
}
