use super::{io, profile_rebind};
use serde::{Deserialize, Serialize};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};

const GO_POLICY_HINT_TIME: Duration = Duration::from_secs(20 * 60);

struct Clock {
    epoch: String,
    started: Instant,
}

impl Clock {
    fn current() -> Option<&'static Self> {
        static CLOCK: OnceLock<Option<Clock>> = OnceLock::new();
        CLOCK
            .get_or_init(|| {
                Some(Clock {
                    epoch: nfqws2_store::new_id().ok()?,
                    started: Instant::now(),
                })
            })
            .as_ref()
    }

    fn elapsed_ms(&self) -> u64 {
        let elapsed = self.started.elapsed();
        #[cfg(test)]
        let elapsed = elapsed.saturating_add(TEST_CLOCK.with(std::cell::Cell::get));
        elapsed.as_millis().try_into().unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PositiveUntil {
    epoch: String,
    elapsed_ms: u64,
}

impl PositiveUntil {
    pub(super) fn capture() -> Option<Self> {
        let clock = Clock::current()?;
        Some(Self {
            epoch: clock.epoch.clone(),
            elapsed_ms: clock
                .elapsed_ms()
                .checked_add(GO_POLICY_HINT_TIME.as_millis() as u64)?,
        })
    }

    fn valid(&self) -> bool {
        self.epoch.len() == 12
            && self
                .epoch
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && self.elapsed_ms >= GO_POLICY_HINT_TIME.as_millis() as u64
    }

    fn expired(&self) -> bool {
        Clock::current()
            .is_some_and(|clock| clock.epoch == self.epoch && clock.elapsed_ms() >= self.elapsed_ms)
    }
}

/// This receipt delays a superseding negative response. It is not an
/// authorization to install an address or an extension of DNS wire TTL.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetryPositiveHint {
    until: PositiveUntil,
    stamp: String,
}

impl RetryPositiveHint {
    pub(super) fn seal(token: &str, until: PositiveUntil) -> io::Result<Self> {
        Ok(Self {
            stamp: profile_rebind::digest(&(token, &until))?,
            until,
        })
    }

    pub(super) fn valid(&self, token: &str) -> bool {
        self.until.valid()
            && profile_rebind::digest(&(token, &self.until))
                .is_ok_and(|digest| digest == self.stamp)
    }

    pub(super) fn expired(&self) -> bool {
        self.until.expired()
    }
}

/// The named answer was already negative in the original compensated attempt.
/// A future projection still requires another current NXDOMAIN for that name.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmedNegativeName {
    name: String,
    stamp: String,
}

impl ConfirmedNegativeName {
    pub(super) fn seal(token: &str, name: String) -> io::Result<Self> {
        Ok(Self {
            stamp: profile_rebind::digest(&(token, &name))?,
            name,
        })
    }

    pub(super) fn valid(&self, token: &str, names: &[String]) -> bool {
        names.len() == 2
            && names.contains(&self.name)
            && profile_rebind::digest(&(token, &self.name)).is_ok_and(|digest| digest == self.stamp)
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }
}

pub(super) struct NamedPositiveObservation {
    name: String,
    until: PositiveUntil,
}

impl NamedPositiveObservation {
    pub(super) fn capture(name: &str) -> Option<Self> {
        Some(Self {
            name: name.to_owned(),
            until: PositiveUntil::capture()?,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedPositiveHint {
    name: String,
    hint: RetryPositiveHint,
}

/// A pair of positive policy horizons recorded in the same compensated scope.
/// Updating one name leaves the other name's independent age unchanged.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct PairPositiveHints([NamedPositiveHint; 2]);

impl NamedPositiveHint {
    fn key(token: &str, name: &str) -> io::Result<String> {
        profile_rebind::digest(&(token, name))
    }

    fn seal(token: &str, observed: &NamedPositiveObservation) -> io::Result<Self> {
        Ok(Self {
            name: observed.name.clone(),
            hint: RetryPositiveHint::seal(
                &Self::key(token, &observed.name)?,
                observed.until.clone(),
            )?,
        })
    }

    fn valid(&self, token: &str) -> bool {
        Self::key(token, &self.name).is_ok_and(|key| self.hint.valid(&key))
    }
}

impl PairPositiveHints {
    pub(super) fn seal(
        token: &str,
        observed: &[NamedPositiveObservation],
    ) -> io::Result<Option<Self>> {
        let [first, second] = observed else {
            return Ok(None);
        };
        Ok(Some(Self([
            NamedPositiveHint::seal(token, first)?,
            NamedPositiveHint::seal(token, second)?,
        ])))
    }

    pub(super) fn valid(&self, token: &str, names: &[String]) -> bool {
        names.len() == self.0.len()
            && self
                .0
                .iter()
                .zip(names)
                .all(|(note, name)| &note.name == name && note.valid(token))
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|note| note.name == name)
    }

    pub(super) fn expired(&self, name: &str) -> bool {
        self.0
            .iter()
            .any(|note| note.name == name && note.hint.expired())
    }

    pub(super) fn refresh(
        &mut self,
        token: &str,
        observations: &[NamedPositiveObservation],
    ) -> io::Result<bool> {
        let mut changed = false;
        for note in &mut self.0 {
            if let Some(observed) = observations.iter().find(|item| item.name == note.name) {
                *note = NamedPositiveHint::seal(token, observed)?;
                changed = true;
            }
        }
        Ok(changed)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_CLOCK: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
}

#[cfg(test)]
pub(in crate::kernel) fn age_for_test(advance: Duration) -> impl Drop {
    struct Restore(Duration);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_CLOCK.with(|clock| clock.set(self.0));
        }
    }
    Restore(TEST_CLOCK.with(|clock| clock.replace(advance)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_positive_policy_ages_expire_independently() {
        let names = [
            "first.scoped.test".to_owned(),
            "second.scoped.test".to_owned(),
        ];
        let original: Vec<_> = names
            .iter()
            .map(|name| NamedPositiveObservation::capture(name).unwrap())
            .collect();
        let mut hints = PairPositiveHints::seal("exact", &original)
            .unwrap()
            .unwrap();
        assert!(hints.valid("exact", &names));
        assert!(!hints.valid("different", &names));
        {
            let _time = age_for_test(Duration::from_secs(19 * 60));
            let update = NamedPositiveObservation::capture(&names[0]).unwrap();
            assert!(hints.refresh("exact", &[update]).unwrap());
        }
        let _time = age_for_test(Duration::from_secs(21 * 60));
        assert!(!hints.expired(&names[0]));
        assert!(hints.expired(&names[1]));
        assert!(!hints.expired("unmatched.scoped.test"));
    }

    #[test]
    fn only_the_same_expired_monotonic_hint_and_scope_qualify() {
        let until = PositiveUntil::capture().unwrap();
        let hint = RetryPositiveHint::seal("sealed scope", until.clone()).unwrap();
        assert!(hint.valid("sealed scope"));
        assert!(!hint.valid("another scope"));
        assert!(!hint.expired());
        let _clock = age_for_test(GO_POLICY_HINT_TIME + Duration::from_secs(1));
        assert!(hint.expired());
        let other_daemon = PositiveUntil {
            epoch: "000000000000".into(),
            ..until
        };
        assert!(!other_daemon.expired());
    }
}
