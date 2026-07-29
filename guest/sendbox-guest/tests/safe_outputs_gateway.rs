use std::os::unix::process::CommandExt;
use std::process::Command;

#[test]
fn argv0_spoofing_cannot_launch_the_safe_outputs_gateway() {
    let output = Command::new(env!("CARGO_BIN_EXE_sendbox-guest"))
        .arg0("safe-outputs-mcp")
        .output()
        .expect("run guest binary");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Safe Outputs MCP must be launched from")
    );
}
