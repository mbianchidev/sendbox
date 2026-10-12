use std::path::Path;

use sendbox_guest::service::{HealthCheck, ServiceId};
use sendbox_guest::trace::service_spec;

#[test]
fn requested_tracing_is_mandatory_and_starts_after_egress() {
    let service = service_spec(Path::new("/run/sendbox/test-session"), true);
    assert_eq!(service.id, ServiceId::Bpf);
    assert!(service.mandatory);
    assert_eq!(service.dependencies, [ServiceId::Egress]);
    assert!(
        matches!(service.health, HealthCheck::UnixSocket { path, .. }
        if path == Path::new("/run/sendbox/test-session/bpf-report.sock"))
    );
    assert!(
        service_spec(Path::new("/run/sendbox/test-session"), false)
            .dependencies
            .is_empty()
    );
}
