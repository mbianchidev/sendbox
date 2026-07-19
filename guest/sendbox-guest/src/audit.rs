use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub code: String,
    pub subject: String,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct AuditLog {
    next_sequence: u64,
    events: Vec<AuditEvent>,
}

impl AuditLog {
    pub fn record(
        &mut self,
        code: impl Into<String>,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.events.push(AuditEvent {
            sequence: self.next_sequence,
            code: code.into(),
            subject: subject.into(),
            detail: detail.into(),
        });
        self.next_sequence = self.next_sequence.saturating_add(1);
    }

    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_deterministically_sequenced() {
        let mut log = AuditLog::default();
        log.record("state", "session", "one");
        log.record("state", "session", "two");
        assert_eq!(log.events()[0].sequence, 0);
        assert_eq!(log.events()[1].sequence, 1);
    }
}
