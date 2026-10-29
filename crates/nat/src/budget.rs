//! The ADR-0017 time limits on a relayed upgrade, shared by both DCUtR
//! machines: the circuit dialer's [`ConnectAttempt`](crate::attempt) and
//! the reservation holder's [`InboundCircuit`](crate::inbound). Each machine
//! keeps its role's work (waiting for the holder's first round, or opening
//! rounds and blasting UDP); the budget only says how long each step may
//! take and which limit ran out.

use crate::config::{MAX_DCUTR_ROUNDS, NatConfig};
use crate::types::UpgradeStop;

/// One relayed upgrade's limits, armed once the Relayed path is usable.
///
/// Capping rule: the overall deadline is `upgrade_timeout_ms` from arming,
/// capped by the caller's outer cap (the attempt's deadline, when it has
/// one), and every other limit (the start wait, each exchange, each punch
/// window) is capped by that overall deadline. No step outlives the
/// upgrade.
///
/// Precedence: the limit that expired first names the [`UpgradeStop`]. A
/// start wait or exchange the overall deadline cut short ends at the same
/// instant as the upgrade, and reports [`UpgradeStop::UpgradeTimeout`]: it
/// never got its own budget.
#[derive(Clone, Debug)]
pub(crate) struct UpgradeBudget {
    /// When the Relayed path became usable; overall and start budgets count
    /// from it.
    armed_at: u64,
    /// The whole upgrade ends then.
    deadline: u64,
    /// Waiting for the holder's first round ends then (circuit dialer only).
    start_deadline: Option<u64>,
    /// The current exchange: when it started and when it must finish.
    exchange: Option<(u64, u64)>,
    /// DCUtR rounds begun.
    rounds: u32,
    exchange_timeout_ms: u64,
    punch_deadline_ms: u64,
}

impl UpgradeBudget {
    /// Arms the budget at `now`, capping the overall deadline at `cap`.
    pub(crate) fn arm(now: u64, config: &NatConfig, cap: Option<u64>) -> Self {
        let end = now.saturating_add(config.upgrade_timeout_ms);
        Self {
            armed_at: now,
            deadline: cap.map_or(end, |cap| cap.min(end)),
            start_deadline: None,
            exchange: None,
            rounds: 0,
            exchange_timeout_ms: config.dcutr_exchange_timeout_ms,
            punch_deadline_ms: config.punch_deadline_ms,
        }
    }

    /// Also bounds the wait for the remote's first round by
    /// `dcutr_start_timeout_ms`, for the side that waits for it.
    pub(crate) fn awaiting_start(mut self, config: &NatConfig) -> Self {
        self.start_deadline =
            Some(self.cap(self.armed_at.saturating_add(config.dcutr_start_timeout_ms)));
        self
    }

    /// The overall upgrade deadline.
    pub(crate) fn deadline(&self) -> u64 {
        self.deadline
    }

    /// DCUtR rounds begun so far.
    pub(crate) fn rounds(&self) -> u32 {
        self.rounds
    }

    /// Whether the round cap still allows another round.
    pub(crate) fn rounds_left(&self) -> bool {
        self.rounds < MAX_DCUTR_ROUNDS
    }

    /// Still waiting for the remote's first round.
    pub(crate) fn awaiting_first_round(&self) -> bool {
        self.start_deadline.is_some()
    }

    /// Begins a round at `now` when the round cap and the overall deadline
    /// allow one: ends the start wait and starts the round's exchange
    /// budget. Returns whether the round began.
    pub(crate) fn begin_round(&mut self, now: u64) -> bool {
        if !self.rounds_left() || now >= self.deadline {
            return false;
        }
        self.rounds += 1;
        self.start_deadline = None;
        let end = self.cap(now.saturating_add(self.exchange_timeout_ms));
        self.exchange = Some((now, end));
        true
    }

    /// The current exchange finished (or failed); only the punch window, if
    /// any, bounds the rest of the round.
    pub(crate) fn end_exchange(&mut self) {
        self.exchange = None;
    }

    /// End of a punch window opening at `start`.
    pub(crate) fn punch_window_end(&self, start: u64) -> u64 {
        self.cap(start.saturating_add(self.punch_deadline_ms))
    }

    /// The limit that ran out by `now`, per the precedence above.
    pub(crate) fn due(&self, now: u64) -> Option<UpgradeStop> {
        // At most one stage limit is armed: a round ends the start wait.
        let stage = match (self.start_deadline, self.exchange) {
            (Some(at), _) if now >= at && at < self.deadline => Some(UpgradeStop::StartTimeout {
                budget_ms: at - self.armed_at,
            }),
            (_, Some((started, at))) if now >= at && at < self.deadline => {
                Some(UpgradeStop::ExchangeTimeout {
                    round: self.rounds,
                    budget_ms: at - started,
                })
            }
            _ => None,
        };
        stage.or_else(|| {
            (now >= self.deadline).then(|| UpgradeStop::UpgradeTimeout {
                budget_ms: self.deadline.saturating_sub(self.armed_at),
            })
        })
    }

    /// Earliest limit still armed, for the driver's timer.
    pub(crate) fn next_deadline(&self) -> u64 {
        [self.start_deadline, self.exchange.map(|(_, at)| at)]
            .into_iter()
            .flatten()
            .fold(self.deadline, u64::min)
    }

    fn cap(&self, at: u64) -> u64 {
        at.min(self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NatConfig {
        NatConfig {
            upgrade_timeout_ms: 20_000,
            dcutr_start_timeout_ms: 10_000,
            dcutr_exchange_timeout_ms: 10_000,
            punch_deadline_ms: 3_000,
            ..NatConfig::default()
        }
    }

    #[test]
    fn the_outer_cap_bounds_the_whole_upgrade() {
        let budget = UpgradeBudget::arm(1_000, &config(), Some(6_000));
        assert_eq!(budget.deadline(), 6_000);
        assert_eq!(
            budget.due(6_000),
            Some(UpgradeStop::UpgradeTimeout { budget_ms: 5_000 })
        );
        assert_eq!(
            UpgradeBudget::arm(1_000, &config(), None).deadline(),
            21_000
        );
    }

    #[test]
    fn every_step_is_capped_at_the_overall_deadline() {
        let mut budget = UpgradeBudget::arm(0, &config(), Some(15_000)).awaiting_start(&config());
        assert_eq!(budget.next_deadline(), 10_000);
        assert!(budget.begin_round(8_000));
        // 8 s + 10 s exchange would run to 18 s.
        assert_eq!(budget.next_deadline(), 15_000);
        assert_eq!(budget.punch_window_end(13_000), 15_000);
        assert_eq!(budget.punch_window_end(1_000), 4_000);
    }

    #[test]
    fn an_exchange_the_overall_deadline_cut_short_reports_the_upgrade_timeout() {
        let mut budget = UpgradeBudget::arm(0, &config(), None);
        assert!(budget.begin_round(15_000));
        assert_eq!(budget.due(19_999), None);
        assert_eq!(
            budget.due(20_000),
            Some(UpgradeStop::UpgradeTimeout { budget_ms: 20_000 })
        );
    }

    #[test]
    fn a_start_wait_the_overall_deadline_cut_short_reports_the_upgrade_timeout() {
        let config = NatConfig {
            dcutr_start_timeout_ms: 30_000,
            ..config()
        };
        let budget = UpgradeBudget::arm(0, &config, None).awaiting_start(&config);
        assert_eq!(
            budget.due(20_000),
            Some(UpgradeStop::UpgradeTimeout { budget_ms: 20_000 })
        );
    }

    #[test]
    fn the_stage_that_expired_first_names_the_stop() {
        let mut budget = UpgradeBudget::arm(0, &config(), None).awaiting_start(&config());
        // Checked late, past both the start wait and the overall deadline.
        assert_eq!(
            budget.due(25_000),
            Some(UpgradeStop::StartTimeout { budget_ms: 10_000 })
        );
        assert!(budget.begin_round(2_000));
        assert_eq!(
            budget.due(25_000),
            Some(UpgradeStop::ExchangeTimeout {
                round: 1,
                budget_ms: 10_000
            })
        );
        budget.end_exchange();
        assert_eq!(
            budget.due(25_000),
            Some(UpgradeStop::UpgradeTimeout { budget_ms: 20_000 })
        );
    }

    #[test]
    fn rounds_stop_at_the_cap_and_at_the_overall_deadline() {
        let mut budget = UpgradeBudget::arm(0, &config(), None);
        for round in 1..=MAX_DCUTR_ROUNDS {
            assert!(budget.begin_round(u64::from(round)));
        }
        assert!(!budget.rounds_left());
        assert!(!budget.begin_round(100));
        assert_eq!(budget.rounds(), MAX_DCUTR_ROUNDS);

        let mut budget = UpgradeBudget::arm(0, &config(), None);
        assert!(!budget.begin_round(20_000));
        assert_eq!(budget.rounds(), 0);
    }
}
