use std::path::Path;

use sendbox_qualification::{
    BenchmarkSpecification, ConformanceManifest, FeatureInventory, load_json, validate_all,
};

#[test]
fn checked_in_qualification_data_is_valid_and_deterministic() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root");
    let inventory: FeatureInventory =
        load_json(&root.join("Tests/qualification/inventory.v1.json")).expect("inventory");
    let conformance: ConformanceManifest =
        load_json(&root.join("Tests/qualification/conformance.v1.json")).expect("conformance");
    let benchmark: BenchmarkSpecification =
        load_json(&root.join("Tests/qualification/benchmark-spec.v1.json")).expect("benchmark");
    let first = validate_all(root, &inventory, &conformance, &benchmark);
    assert!(first.valid, "{:?}", first.errors);
    let first_json = serde_json::to_string(&first).expect("serialize report");
    let second_json =
        serde_json::to_string(&validate_all(root, &inventory, &conformance, &benchmark))
            .expect("serialize report");
    assert_eq!(first_json, second_json);
}
