use std::{
    ops::Sub,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonotonicTime(Duration);

impl MonotonicTime {
    #[must_use]
    pub const fn from_duration(duration: Duration) -> Self {
        Self(duration)
    }

    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl Sub for MonotonicTime {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.saturating_sub(rhs.0)
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> MonotonicTime;
}

#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_duration(self.origin.elapsed())
    }
}
