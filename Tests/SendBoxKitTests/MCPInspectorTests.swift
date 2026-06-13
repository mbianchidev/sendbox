import Testing
@testable import SendBoxKit

struct MCPInspectorTests {

    // MARK: - Helpers

    private typealias Config = ObservabilityConfig.MCPInspectionConfig

    private func makeInspector(
        transports: [Config.Transport] = [.stdio, .http],
        capturePayloads: Bool = true,
        maxPayloadBytes: Int = 16384
    ) -> MCPInspector {
        let config = Config(
            enabled: true,
            transports: transports,
            capturePayloads: capturePayloads,
            maxPayloadBytes: maxPayloadBytes,
            logPath: "/var/log/sendbox/mcp-trace.log",
            serverCommandPatterns: ["mcp-server", "modelcontextprotocol"]
        )
        return MCPInspector(config: config)
    }

    // MARK: - bpftrace program generation

    @Test func testProgramContainsMarkersAndShebang() {
        let program = makeInspector().generateBpftraceProgram()
        #expect(program.hasPrefix("#!/usr/bin/env bpftrace"))
        #expect(program.contains(MCPInspector.eventMarker))
        #expect(program.contains(MCPInspector.beginMarker))
        #expect(program.contains(MCPInspector.endMarker))
    }

    @Test func testProgramContainsStdioProbes() {
        let program = makeInspector(transports: [.stdio]).generateBpftraceProgram()
        #expect(program.contains("sys_enter_execve"))
        #expect(program.contains("sys_enter_write"))
        #expect(program.contains("sys_enter_read"))
        #expect(program.contains("sys_exit_read"))
        // Server argv patterns must appear in the spawn predicate.
        #expect(program.contains("mcp-server"))
    }

    @Test func testProgramContainsTLSProbesWhenHTTPEnabled() {
        let program = makeInspector(transports: [.http]).generateBpftraceProgram()
        #expect(program.contains("SSL_write"))
        #expect(program.contains("SSL_read"))
        #expect(program.contains("__SENDBOX_LIBSSL__"))
    }

    @Test func testTransportTogglesRemoveProbes() {
        let stdioOnly = makeInspector(transports: [.stdio]).generateBpftraceProgram()
        #expect(!stdioOnly.contains("SSL_write"))

        let httpOnly = makeInspector(transports: [.http]).generateBpftraceProgram()
        #expect(!httpOnly.contains("sys_enter_execve"))
    }

    @Test func testMaxPayloadBytesAppearsAsCap() {
        let program = makeInspector(transports: [.stdio], maxPayloadBytes: 512)
            .generateBpftraceProgram()
        #expect(program.contains("512"))
    }

    // MARK: - Startup script generation

    @Test func testStartupScriptHasShebangAndGracefulFallback() {
        let script = makeInspector().generateStartupScript()
        #expect(script.hasPrefix("#!/usr/bin/env bash"))
        #expect(script.contains("bpftrace"))
        // Fails gracefully without aborting guest boot.
        #expect(script.contains("exit 0"))
        #expect(script.contains("must run as root"))
    }

    @Test func testStartupScriptResolvesLibsslWhenHTTPEnabled() {
        let script = makeInspector(transports: [.http]).generateStartupScript()
        #expect(script.contains("libssl"))
        #expect(script.contains("__SENDBOX_LIBSSL__"))
    }

    @Test func testStartupScriptSkipsLibsslWhenHTTPDisabled() {
        let script = makeInspector(transports: [.stdio]).generateStartupScript()
        #expect(!script.contains("ldconfig"))
    }

    // MARK: - Classification

    @Test func testClassifyToolsMethod() {
        #expect(MCPInspector.classify(method: "tools/call") == .tools)
        #expect(MCPInspector.classify(method: "tools/list") == .tools)
    }

    @Test func testClassifyResourcesAndPrompts() {
        #expect(MCPInspector.classify(method: "resources/read") == .resources)
        #expect(MCPInspector.classify(method: "prompts/get") == .prompts)
    }

    @Test func testClassifyLifecycleAndNotification() {
        #expect(MCPInspector.classify(method: "initialize") == .lifecycle)
        #expect(MCPInspector.classify(method: "ping") == .lifecycle)
        #expect(MCPInspector.classify(method: "notifications/initialized") == .notification)
    }

    @Test func testClassifyUnknownAndNil() {
        #expect(MCPInspector.classify(method: "wat/unknown") == .other)
        #expect(MCPInspector.classify(method: nil) == .other)
    }

    // MARK: - Message parsing

    @Test func testParseToolCallRequestExtractsToolName() {
        let json = #"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file"}}"#
        let call = makeInspector().parseMessage(json, transport: .stdio)
        #expect(call != nil)
        #expect(call?.kind == .request)
        #expect(call?.category == .tools)
        #expect(call?.method == "tools/call")
        #expect(call?.subject == "read_file")
        #expect(call?.id == "7")
    }

    @Test func testParseResourceReadExtractsURI() {
        let json = #"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///x"}}"#
        let call = makeInspector().parseMessage(json, transport: .stdio)
        #expect(call?.category == .resources)
        #expect(call?.subject == "file:///x")
    }

    @Test func testParseNotification() {
        let json = #"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        let call = makeInspector().parseMessage(json, transport: .http)
        #expect(call?.kind == .notification)
        #expect(call?.category == .notification)
        #expect(call?.id == nil)
    }

    @Test func testParseErrorResponse() {
        let json = #"{"jsonrpc":"2.0","id":9,"error":{"code":-32601,"message":"Method not found"}}"#
        let call = makeInspector().parseMessage(json, transport: .stdio)
        #expect(call?.kind == .error)
        #expect(call?.errorCode == -32601)
        #expect(call?.errorMessage == "Method not found")
    }

    @Test func testParseRejectsNonJSONRPC() {
        let json = #"{"foo":"bar"}"#
        #expect(makeInspector().parseMessage(json, transport: .stdio) == nil)
    }

    // MARK: - Redaction

    @Test func testRedactionDropsPayloadValues() {
        let json = #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{"cmd":"rm -rf /"}}}"#
        let call = makeInspector(capturePayloads: false).parseMessage(json, transport: .stdio)
        #expect(call != nil)
        // Tool name retained as metadata, but sensitive arguments are gone.
        #expect(call?.subject == "exec")
        #expect(call?.raw.contains("_redacted") == true)
        #expect(call?.raw.contains("rm -rf") == false)
    }

    @Test func testCapturePayloadsKeepsRaw() {
        let json = #"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec"}}"#
        let call = makeInspector(capturePayloads: true).parseMessage(json, transport: .stdio)
        #expect(call?.raw.contains("\"method\":\"tools/call\"") == true)
    }

    // MARK: - JSON extraction

    @Test func testExtractJSONFromSSEDataLine() {
        let payload = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\n"
        let objects = MCPInspector.extractJSONObjects(from: payload)
        #expect(objects.count == 1)
        #expect(objects.first?.contains("ping") == true)
    }

    @Test func testExtractJSONFromHTTPBody() {
        let payload = "POST /mcp HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
            + "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"
        let objects = MCPInspector.extractJSONObjects(from: payload)
        #expect(objects.count == 1)
    }

    @Test func testExtractIgnoresNonJSONRPCObjects() {
        let payload = #"{"hello":"world"} {"jsonrpc":"2.0","method":"ping"}"#
        let objects = MCPInspector.extractJSONObjects(from: payload)
        #expect(objects.count == 1)
    }

    // MARK: - Event parsing & response correlation

    @Test func testParseEventsCorrelatesResponseToRequest() {
        let m = MCPInspector.eventMarker
        let log = [
            "\(m)\t100\t42\tnode\tstdio\tto_server\t{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\"}}",
            "\(m)\t200\t42\tnode\tstdio\tfrom_server\t{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}",
        ].joined(separator: "\n")

        let calls = makeInspector().parseEvents(from: log)
        #expect(calls.count == 2)
        let response = calls.last
        // The response carried only an id; it should inherit the request method.
        #expect(response?.kind == .response)
        #expect(response?.method == "tools/call")
        #expect(response?.category == .tools)
    }

    @Test func testParseEventsHandlesSpawn() {
        let m = MCPInspector.eventMarker
        let log = "\(m)\t100\t42\tnode\tstdio\tspawn\tnode mcp-server-fs /workspaces"
        let calls = makeInspector().parseEvents(from: log)
        #expect(calls.count == 1)
        #expect(calls.first?.kind == .spawn)
        #expect(calls.first?.subject == "node mcp-server-fs /workspaces")
    }

    @Test func testParseEventsIgnoresBeginEndMarkers() {
        let log = [
            MCPInspector.beginMarker + "\t100",
            MCPInspector.endMarker + "\t200",
        ].joined(separator: "\n")
        #expect(makeInspector().parseEvents(from: log).isEmpty)
    }

    // MARK: - Summary

    @Test func testSummarizeCountsCategoriesAndTools() {
        let m = MCPInspector.eventMarker
        let log = [
            "\(m)\t100\t1\tnode\tstdio\tspawn\tnode mcp-server-fs",
            "\(m)\t110\t1\tnode\tstdio\tto_server\t{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\"}}",
            "\(m)\t120\t1\tnode\tstdio\tto_server\t{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ls\"}}",
            "\(m)\t130\t1\tnode\tstdio\tfrom_server\t{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-1,\"message\":\"boom\"}}",
        ].joined(separator: "\n")

        let inspector = makeInspector()
        let summary = inspector.summarize(inspector.parseEvents(from: log))
        #expect(summary.toolCallCount == 2)
        #expect(summary.toolInvocations["ls"] == 2)
        #expect(summary.errorCount == 1)
        #expect(summary.servers.contains("node mcp-server-fs"))
        #expect(summary.byCategory[.tools] != nil)
    }

    // MARK: - Config wiring

    @Test func testDefaultObservabilityIsDisabled() {
        #expect(ObservabilityConfig.default.mcpInspection.enabled == false)
    }

    @Test func testSandboxConfigDefaultIncludesObservability() {
        let config = SandboxConfiguration.default(projectPath: "/tmp/x")
        #expect(config.observability != nil)
    }
}
