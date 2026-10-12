#![cfg(feature = "execution-broker")]

use sendbox_core::SessionId;
use sendbox_guest::broker::workload_environment;

#[test]
fn cli_agents_get_an_ephemeral_guest_home_and_standard_image_tool_paths() {
    let session = SessionId::from_bytes([5; 16]);
    let environment = workload_environment(session);
    let home = format!("/run/sendbox-workload/{session}");
    assert_eq!(environment["HOME"], home);
    assert_eq!(environment["XDG_CONFIG_HOME"], format!("{home}/.config"));
    assert_eq!(environment["XDG_DATA_HOME"], format!("{home}/.local/share"));
    assert_eq!(environment["XDG_CACHE_HOME"], format!("{home}/.cache"));
    assert_eq!(environment["PATH"], "/usr/local/bin:/usr/bin:/bin");
    assert_ne!(
        workload_environment(SessionId::from_bytes([6; 16]))["HOME"],
        environment["HOME"],
    );
}
