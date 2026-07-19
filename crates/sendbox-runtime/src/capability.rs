use std::collections::BTreeSet;

use sendbox_protocol::{Capability, CapabilitySet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeCapability {
    Lifecycle,
    Exec,
    StreamedIo,
    Signals,
    Mounts,
    Network,
    Mcp,
    Audit,
    Health,
    /// Runtime-local ability to provision the selected host/guest transport.
    ///
    /// This capability is deliberately not represented in `sendbox-protocol`.
    TransportProvisioning,
}

impl RuntimeCapability {
    #[must_use]
    pub const fn wire_capability(self) -> Option<Capability> {
        match self {
            Self::Lifecycle => Some(Capability::Lifecycle),
            Self::Exec => Some(Capability::Exec),
            Self::StreamedIo => Some(Capability::StreamedIo),
            Self::Signals => Some(Capability::Signals),
            Self::Mounts => Some(Capability::Mounts),
            Self::Network => Some(Capability::Network),
            Self::Mcp => Some(Capability::Mcp),
            Self::Audit => Some(Capability::Audit),
            Self::Health => Some(Capability::Health),
            Self::TransportProvisioning => None,
        }
    }
}

impl From<Capability> for RuntimeCapability {
    fn from(value: Capability) -> Self {
        match value {
            Capability::Lifecycle => Self::Lifecycle,
            Capability::Exec => Self::Exec,
            Capability::StreamedIo => Self::StreamedIo,
            Capability::Signals => Self::Signals,
            Capability::Mounts => Self::Mounts,
            Capability::Network => Self::Network,
            Capability::Mcp => Self::Mcp,
            Capability::Audit => Self::Audit,
            Capability::Health => Self::Health,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeCapabilities(BTreeSet<RuntimeCapability>);

impl RuntimeCapabilities {
    #[must_use]
    pub fn new(capabilities: impl IntoIterator<Item = RuntimeCapability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    #[must_use]
    pub fn contains(&self, capability: RuntimeCapability) -> bool {
        self.0.contains(&capability)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = RuntimeCapability> + '_ {
        self.0.iter().copied()
    }

    #[must_use]
    pub fn missing_from(&self, available: &Self) -> Self {
        Self(self.0.difference(&available.0).copied().collect())
    }

    #[must_use]
    pub fn to_wire(&self) -> CapabilitySet {
        CapabilitySet::new(
            self.0
                .iter()
                .filter_map(|capability| capability.wire_capability()),
        )
    }

    #[must_use]
    pub fn from_wire(capabilities: &CapabilitySet) -> Self {
        Self::new(capabilities.iter().map(RuntimeCapability::from))
    }
}

impl<const N: usize> From<[RuntimeCapability; N]> for RuntimeCapabilities {
    fn from(value: [RuntimeCapability; N]) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use sendbox_protocol::Capability;

    use super::{RuntimeCapabilities, RuntimeCapability};

    #[test]
    fn all_wire_capabilities_round_trip_and_transport_stays_local() {
        let wire = [
            Capability::Lifecycle,
            Capability::Exec,
            Capability::StreamedIo,
            Capability::Signals,
            Capability::Mounts,
            Capability::Network,
            Capability::Mcp,
            Capability::Audit,
            Capability::Health,
        ];
        let mut runtime = RuntimeCapabilities::from_wire(&wire.into());
        assert_eq!(runtime.to_wire(), wire.into());

        runtime.0.insert(RuntimeCapability::TransportProvisioning);
        assert_eq!(runtime.to_wire(), wire.into());
    }
}
