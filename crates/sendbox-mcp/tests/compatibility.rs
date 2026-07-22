use sendbox_mcp::observation::{
    MessageKind, MethodCategory, ObservationParser, render_report, summarize,
};

#[test]
fn legacy_swift_trace_fixture_remains_readable() {
    let calls =
        ObservationParser::new(true).parse_log(include_str!("fixtures/legacy-swift-trace.log"));
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[1].method.as_deref(), Some("tools/call"));
    assert_eq!(calls[2].kind, MessageKind::Response);
    assert_eq!(calls[2].category, MethodCategory::Tools);
    assert_eq!(summarize(&calls).tool_call_count, 1);
}

#[test]
fn versioned_native_trace_fixture_has_deterministic_report() {
    let calls =
        ObservationParser::new(false).parse_log(include_str!("fixtures/native-events-v1.log"));
    assert_eq!(
        render_report(&summarize(&calls)),
        "MCP calls: 3\nTool calls: 1\nErrors: 1\ntool delete_file: 1\nserver: /usr/bin/node /srv/mcp-server.js\n"
    );
    assert!(calls.iter().all(|call| !call.raw.contains("/private")));
}
