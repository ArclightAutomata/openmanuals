//! When to fold: shortly after facts arrive (debounced), and on a fixed
//! interval as a safety net.
//!
//! Anything that accepts facts calls [`FoldTrigger::poke`]. The scheduler
//! folds `debounce` after the last poke, but never later than `max_delay`
//! after the first poke it has not yet folded, so a steady trickle of facts
//! still gets folded. Folds run one at a time on the scheduler task (and
//! `fold::fold_and_build` takes `fold_lock` as well, so a `fold` started
//! elsewhere in the process waits for it). A poke that arrives while a fold
//! is running is kept and starts a new debounce once the fold is done.

use std::future::Future;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

/// Wakes the fold scheduler. Lives in `State`.
#[derive(Default)]
pub struct FoldTrigger {
    notify: Notify,
}

impl FoldTrigger {
    /// Facts were accepted: fold soon.
    pub fn poke(&self) {
        // Stores a permit when the scheduler is busy, so no poke is lost.
        self.notify.notify_one();
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// Quiet time after the last poke before folding. Zero disables on-demand folds.
    pub debounce: Duration,
    /// Longest wait after the first unfolded poke.
    pub max_delay: Duration,
    /// Fold at least this often, pokes or not. Zero disables.
    pub interval: Duration,
    /// How often to look for facts another process (`openmanuals-server import`) added
    /// to the inbox. Zero disables.
    pub poll: Duration,
}

/// The debounce state: when the pending pokes started and when the last came.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Debounce {
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Debounce {
    pub fn poke(&mut self, now: Instant) {
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    /// When the pending pokes are due, if any.
    pub fn due(&self, debounce: Duration, max_delay: Duration) -> Option<Instant> {
        let (first, last) = (self.first?, self.last?);
        Some((last + debounce).min(first + max_delay.max(debounce)))
    }

    pub fn clear(&mut self) {
        *self = Debounce::default();
    }

    pub fn pending(&self) -> bool {
        self.first.is_some()
    }
}

/// Why a fold ran (for logs and tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Facts were accepted and the debounce elapsed.
    Facts,
    /// The safety-net interval.
    Interval,
}

/// Run the scheduler forever. `fold` is awaited to completion before the next
/// one may start; `external` reports facts added to the inbox by another
/// process (checked every `s.poll`).
pub async fn run<F, Fut>(trigger: &FoldTrigger, s: Schedule, mut external: impl FnMut() -> bool, mut fold: F)
where
    F: FnMut(Reason) -> Fut,
    Fut: Future<Output = ()>,
{
    let on_demand = !s.debounce.is_zero();
    let far = Duration::from_secs(86400 * 365);
    let mut deb = Debounce::default();
    let mut next_interval = (!s.interval.is_zero()).then(|| Instant::now() + s.interval);
    let mut next_poll = Instant::now() + if s.poll.is_zero() { far } else { s.poll };
    loop {
        let due = deb.due(s.debounce, s.max_delay);
        let wake = [due, next_interval, Some(next_poll)].into_iter().flatten().min().unwrap();
        tokio::select! {
            _ = trigger.notify.notified() => {
                if on_demand {
                    deb.poke(Instant::now());
                }
            }
            _ = tokio::time::sleep_until(wake) => {
                let now = Instant::now();
                if now >= next_poll {
                    next_poll = now + s.poll;
                    if on_demand && external() {
                        deb.poke(now);
                    }
                }
                let reason = if due.is_some_and(|d| now >= d) {
                    Some(Reason::Facts)
                } else if next_interval.is_some_and(|t| now >= t) {
                    Some(Reason::Interval)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    // Everything poked so far is folded by this run; pokes
                    // during it leave a permit and start the next debounce.
                    deb.clear();
                    fold(reason).await;
                    if !s.interval.is_zero() {
                        next_interval = Some(Instant::now() + s.interval);
                    }
                }
            }
        }
    }
}

/// The server's fold scheduler: [`run`] wired to `fold::fold_and_build` and
/// the inbox. Returns the task; it runs until the runtime shuts down.
pub fn spawn(state: crate::Shared, s: Schedule) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Facts left unfolded by a previous run (or imported while it was down).
        if state.inbox.has_unfolded().unwrap_or(false) {
            state.fold_trigger.poke();
        }
        let st = state.clone();
        let external = move || match st.inbox.changed_elsewhere() {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "checking the inbox for outside changes");
                false
            }
        };
        run(&state.fold_trigger, s, external, |reason| {
            let st = state.clone();
            async move {
                match crate::fold::fold_and_build(st).await {
                    Ok((n, built)) => tracing::info!(?reason, folded = n, rebuilt = built.is_some(), "fold"),
                    Err(e) => tracing::error!(?reason, error = %e, "fold failed"),
                }
            }
        })
        .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn debounce_due_is_min_of_quiet_and_max() {
        let t0 = Instant::now();
        let mut d = Debounce::default();
        assert_eq!(d.due(secs(5), secs(60)), None);
        d.poke(t0);
        assert_eq!(d.due(secs(5), secs(60)), Some(t0 + secs(5)));
        d.poke(t0 + secs(3));
        assert_eq!(d.due(secs(5), secs(60)), Some(t0 + secs(8)));
        d.poke(t0 + secs(58));
        assert_eq!(d.due(secs(5), secs(60)), Some(t0 + secs(60)), "capped at first + max_delay");
        d.clear();
        assert!(!d.pending());
        // max_delay shorter than the debounce never folds before the debounce.
        d.poke(t0);
        assert_eq!(d.due(secs(5), secs(1)), Some(t0 + secs(5)));
    }

    type Log = Arc<Mutex<Vec<(Duration, Reason)>>>;

    /// Spawn a scheduler whose folds take `fold_time` and log (elapsed, reason).
    fn spawn(s: Schedule, fold_time: Duration) -> (Arc<FoldTrigger>, Log, Instant) {
        let trigger = Arc::new(FoldTrigger::default());
        let log: Log = Arc::default();
        let t0 = Instant::now();
        let (tr, lg) = (trigger.clone(), log.clone());
        tokio::spawn(async move {
            run(&tr, s, || false, |r| {
                let lg = lg.clone();
                async move {
                    lg.lock().unwrap().push((t0.elapsed(), r));
                    tokio::time::sleep(fold_time).await;
                }
            })
            .await
        });
        (trigger, log, t0)
    }

    fn sched(debounce: u64, max: u64, interval: u64) -> Schedule {
        Schedule { debounce: secs(debounce), max_delay: secs(max), interval: secs(interval), poll: Duration::ZERO }
    }

    async fn at(t0: Instant, s: u64) {
        tokio::time::sleep_until(t0 + secs(s)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn folds_after_quiet_period() {
        let (tr, log, t0) = spawn(sched(5, 60, 0), Duration::ZERO);
        at(t0, 1).await;
        tr.poke();
        at(t0, 3).await;
        tr.poke();
        at(t0, 100).await;
        assert_eq!(*log.lock().unwrap(), vec![(secs(8), Reason::Facts)]);
    }

    #[tokio::test(start_paused = true)]
    async fn steady_trickle_is_capped_by_max_delay() {
        let (tr, log, t0) = spawn(sched(5, 19, 0), Duration::ZERO);
        // A poke every 2 s for 50 s: never 5 s quiet, so max_delay decides.
        for i in 0..25 {
            at(t0, 1 + 2 * i).await;
            tr.poke();
        }
        at(t0, 100).await;
        let got: Vec<u64> = log.lock().unwrap().iter().map(|(d, _)| d.as_secs()).collect();
        // First poke at 1 → fold at 20; next first poke at 21 → 40; last poke at 49 → 54.
        assert_eq!(got, vec![20, 40, 54]);
    }

    #[tokio::test(start_paused = true)]
    async fn poke_during_fold_starts_a_new_debounce() {
        let (tr, log, t0) = spawn(sched(5, 60, 0), secs(10));
        tr.poke();
        at(t0, 7).await; // the fold started at 5 and runs until 15
        tr.poke();
        at(t0, 100).await;
        let got: Vec<u64> = log.lock().unwrap().iter().map(|(d, _)| d.as_secs()).collect();
        assert_eq!(got, vec![5, 20], "the poke at 7 is seen when the fold ends at 15");
    }

    #[tokio::test(start_paused = true)]
    async fn interval_is_a_safety_net() {
        let (tr, log, t0) = spawn(sched(5, 60, 30), Duration::ZERO);
        at(t0, 40).await;
        tr.poke();
        at(t0, 80).await;
        let got: Vec<(u64, Reason)> = log.lock().unwrap().iter().map(|(d, r)| (d.as_secs(), *r)).collect();
        // Interval at 30, facts at 45, interval again 30 s after that fold.
        assert_eq!(got, vec![(30, Reason::Interval), (45, Reason::Facts), (75, Reason::Interval)]);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_debounce_disables_on_demand() {
        let (tr, log, t0) = spawn(sched(0, 60, 0), Duration::ZERO);
        tr.poke();
        at(t0, 1000).await;
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn external_inbox_changes_are_polled() {
        let trigger = Arc::new(FoldTrigger::default());
        let log: Log = Arc::default();
        let t0 = Instant::now();
        let (tr, lg) = (trigger.clone(), log.clone());
        let s = Schedule { poll: secs(2), ..sched(5, 60, 0) };
        tokio::spawn(async move {
            // Another process adds facts once, seen at the poll at 4 s.
            let mut n = 0;
            run(&tr, s, move || { n += 1; n == 2 }, |r| {
                let lg = lg.clone();
                async move { lg.lock().unwrap().push((t0.elapsed(), r)) }
            })
            .await
        });
        at(t0, 100).await;
        assert_eq!(*log.lock().unwrap(), vec![(secs(9), Reason::Facts)]);
    }
}
