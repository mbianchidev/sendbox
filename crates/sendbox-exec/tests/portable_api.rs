use std::time::Duration;

use sendbox_exec::{
    CancellationFlag, ContainmentProfile, CorrelationId, DescriptorPath, EnvironmentEntry,
    EventSink, ExecutionDecision, ExecutionRequest, ExecutionTimeout, KernelPrimitive,
    RelativePath, RootId, SemanticScope, SessionAuthentication, SessionId, TerminalState,
    UnsupportedExecutionBackend,
};
use sendbox_exec::{ExecutionBackend, RequestValidationError};

fn request() -> ExecutionRequest {
    ExecutionRequest {
        session_id: SessionId::from_bytes([1; 16]),
        authentication: SessionAuthentication::from_bytes([2; 32]),
        correlation_id: CorrelationId::new("portable-1").expect("correlation"),
        cancellation_id: None,
        executable: DescriptorPath {
            root: RootId::System,
            relative: RelativePath::new("usr/bin/tool").expect("executable"),
        },
        argv: vec![
            "tool".into(),
            "one argument with spaces".into(),
            "*.literal".into(),
        ],
        cwd: DescriptorPath {
            root: RootId::Workspace,
            relative: RelativePath::new(".").expect("cwd"),
        },
        environment: vec![EnvironmentEntry {
            name: "SAFE".into(),
            value: "value".into(),
        }],
        stdin: sendbox_exec::StandardInput::Null,
        timeout: ExecutionTimeout::new(Duration::from_secs(1)).expect("timeout"),
        containment: ContainmentProfile::default(),
    }
}

#[test]
fn portable_request_round_trip_preserves_exact_argv_boundaries() {
    let request = request();
    let encoded = serde_json::to_vec(&request).expect("encode");
    let decoded: ExecutionRequest = serde_json::from_slice(&encoded).expect("decode");
    assert_eq!(decoded.argv, request.argv);
    assert_eq!(decoded.argv.len(), 3);
}

#[test]
fn descriptor_paths_reject_absolute_and_parent_traversal() {
    assert!(matches!(
        RelativePath::new("/usr/bin/tool"),
        Err(RequestValidationError::AbsoluteDescriptorPath)
    ));
    assert!(matches!(
        RelativePath::new("../tool"),
        Err(RequestValidationError::ParentTraversal)
    ));
}

#[test]
fn unqualified_platform_backend_fails_closed_with_typed_primitive() {
    let backend = UnsupportedExecutionBackend::new(KernelPrimitive::Clone3IntoCgroup);
    let mut sink = NoEvents;
    let request = request();
    let decision = ExecutionDecision {
        session_id: request.session_id,
        correlation_id: request.correlation_id.clone(),
        disposition: sendbox_exec::AdmissionDisposition::Allow,
        matched_rule: None,
        semantic_scope: SemanticScope::TopLevelOnly,
    };
    let result = backend.execute(&request, &decision, &mut sink, &CancellationFlag::default());
    assert!(matches!(
        result.terminal,
        TerminalState::LaunchFailed(sendbox_exec::LaunchFailure::UnsupportedKernel(error))
            if error.primitive == KernelPrimitive::Clone3IntoCgroup
    ));
    assert!(result.cleanup.is_no_child());
}

struct NoEvents;

impl EventSink for NoEvents {
    fn emit(
        &mut self,
        _event: sendbox_exec::ExecutionEvent,
    ) -> Result<(), sendbox_exec::SinkError> {
        panic!("unsupported backend must not emit non-terminal events")
    }
}
