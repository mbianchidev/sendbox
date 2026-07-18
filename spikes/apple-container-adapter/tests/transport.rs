use apple_container_adapter_spike::transport::{SocketPublication, SocketPublicationError};
use std::fs;
use tempfile::tempdir;

#[test]
fn accepts_absolute_nonexistent_socket_paths() {
    let directory = tempdir().expect("temporary directory");
    let endpoint = SocketPublication::new(
        directory.path().join("control.sock"),
        "/run/sendbox/control.sock",
    )
    .expect("valid socket publication");
    assert!(
        endpoint
            .specification()
            .ends_with(":/run/sendbox/control.sock")
    );
}

#[test]
fn rejects_relative_parent_and_colon_paths() {
    assert!(matches!(
        SocketPublication::new("control.sock", "/run/sendbox/control.sock"),
        Err(SocketPublicationError::RelativePath { side: "host" })
    ));
    assert!(matches!(
        SocketPublication::new("/tmp/../control.sock", "/run/sendbox/control.sock"),
        Err(SocketPublicationError::ParentTraversal { side: "host" })
    ));
    assert!(matches!(
        SocketPublication::new("/tmp/control:sock", "/run/sendbox/control.sock"),
        Err(SocketPublicationError::InvalidCharacter { side: "host" })
    ));
}

#[test]
fn rejects_existing_host_path_before_apple_can_replace_it() {
    let directory = tempdir().expect("temporary directory");
    let host_path = directory.path().join("control.sock");
    fs::write(&host_path, b"do not delete").expect("write sentinel");
    assert!(matches!(
        SocketPublication::new(&host_path, "/run/sendbox/control.sock"),
        Err(SocketPublicationError::HostPathExists(path)) if path == host_path
    ));
    assert_eq!(
        fs::read(&host_path).expect("sentinel remains"),
        b"do not delete"
    );
}
