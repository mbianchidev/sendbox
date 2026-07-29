#![no_main]

use libfuzzer_sys::fuzz_target;
use sendbox_policy::{PackageRegistryPolicy, PackageSupplyChainPolicy};
use sendbox_registry::NpmAdapter;

fuzz_target!(|data: &[u8]| {
    let registry = PackageRegistryPolicy::default();
    let policy = PackageSupplyChainPolicy {
        enabled: true,
        registries: vec![registry.clone()],
        ..PackageSupplyChainPolicy::default()
    };
    let adapter = NpmAdapter::new(registry, policy, None).expect("static fuzz policy");
    let _ = adapter.parse_metadata(data, "fuzz");
});
