import XCTest
@testable import SecureAgentMenubar

/// Sendable box for the request bytes a test socket server captures.
private final class RequestCapture: @unchecked Sendable {
    var request: String?
}

final class DaemonClientTests: XCTestCase {
    func testDaemonClientErrorDescriptionsAreActionable() {
        // Regression: without LocalizedError every daemon failure surfaced as
        // "The operation could not be completed. (…DaemonClientError error 1.)"
        // — the "dismiss failed without reason" complaint.
        XCTAssertEqual(DaemonClientError.http(403).errorDescription,
                       "daemon refused the change (HTTP 403) — this client isn't allowed to change policy; restart Secure Agent if this persists")
        XCTAssertEqual(DaemonClientError.http(401).errorDescription,
                       "daemon refused the change (HTTP 401) — this client isn't allowed to change policy; restart Secure Agent if this persists")
        XCTAssertEqual(DaemonClientError.http(500).errorDescription,
                       "daemon answered HTTP 500")
        XCTAssertEqual(DaemonClientError.transport("connect timed out").errorDescription,
                       "daemon unreachable (connect timed out)")
        XCTAssertEqual(DaemonClientError.decode("bad json").errorDescription,
                       "daemon answered unexpectedly (bad json)")
    }

    func testNotifyRulesResponseDecoding() throws {
        let json = #"{"default_min_severity":3,"overrides":{"keychain-access":false,"tcc-tamper":true}}"#
            .data(using: .utf8)!
        let r = try JSONDecoder().decode(NotifyRulesResponse.self, from: json)
        XCTAssertEqual(r.defaultMinSeverity, 3)
        XCTAssertEqual(r.overrides["keychain-access"], false)
        XCTAssertEqual(r.overrides["tcc-tamper"], true)
        // Fallback for daemons predating /notify/rules.
        XCTAssertEqual(NotifyRulesResponse.fallback.defaultMinSeverity, 3)
        XCTAssertTrue(NotifyRulesResponse.fallback.overrides.isEmpty)
    }

    func testStatusDecodesAdvisorHealth() throws {
        let json = #"{"running":true,"uptime":"1m","active_agents":1,"advisor_health":{"enabled":true,"circuit_open":true,"last_error":"context deadline exceeded","queue_depth":2,"model":"qwen3:8b"}}"#
            .data(using: .utf8)!
        let s = try JSONDecoder().decode(StatusResponse.self, from: json)
        XCTAssertEqual(s.advisorHealth?.enabled, true)
        XCTAssertEqual(s.advisorHealth?.circuitOpen, true)
        XCTAssertEqual(s.advisorHealth?.lastError, "context deadline exceeded")
        XCTAssertEqual(s.advisorHealth?.queueDepth, 2)
        XCTAssertEqual(s.advisorHealth?.model, "qwen3:8b")
    }

    func testStatusDecodesOptionalProcessAndFamilyCPU() throws {
        let json = #"{"running":true,"uptime":"1m","active_agents":1,"agents":[{"pid":10,"name":"claude","cpu_percent":125.5},{"pid":11,"name":"claude"}],"trees":[{"root":{"pid":10,"name":"claude","cpu_percent":125.5},"children":[{"pid":11,"name":"claude"}],"cpu_percent":125.5}]}"#
            .data(using: .utf8)!
        let status = try JSONDecoder().decode(StatusResponse.self, from: json)

        XCTAssertEqual(status.agents?[0].cpuPercent, 125.5)
        XCTAssertNil(status.agents?[1].cpuPercent)
        XCTAssertEqual(status.trees?[0].cpuPercent, 125.5)
    }

    func testResourceSnapshotDecodesWholeMachinePressure() throws {
        let json = #"{"host":{"total_memory_bytes":17179869184,"available_memory_bytes":4294967296,"agent_memory_bytes":3221225472,"non_agent_memory_bytes":9663676416,"headroom_percent":25,"system_cpu_percent":75,"agent_cpu_percent":20,"non_agent_cpu_percent":55,"memory_pressure":"normal","thermal_state":"nominal","headroom_score":25,"capacity":"constrained"}}"#
            .data(using: .utf8)!
        let resources = try JSONDecoder().decode(ResourceSnapshotModel.self, from: json)
        XCTAssertEqual(resources.host?.availableMemoryBytes, 4 * 1024 * 1024 * 1024)
        XCTAssertEqual(resources.host?.nonAgentCPUPercent, 55)
        XCTAssertEqual(resources.host?.headroomScore, 25)
        XCTAssertEqual(resources.host?.capacity, "constrained")
    }

    func testAcknowledgedCopyPreservesIdentity() {
        let f = FlagModel(id: "x", rule: "keychain-access", severity: 1, ts: "t", pid: 9,
                          agent: "codex", evidence: ["e"], sessionId: "s1")
        let a = f.acknowledgedCopy()
        XCTAssertEqual(a.acknowledged, true)
        XCTAssertEqual(a.id, "x")
        XCTAssertEqual(a.rule, "keychain-access")
        XCTAssertEqual(a.sessionId, "s1")
        XCTAssertEqual(a.severity, 1)
    }

    func testModelDecoding() throws {
        let statusJSON = """
        {
            "running": true,
            "uptime": "10m",
            "active_agents": 2
        }
        """.data(using: .utf8)!

        let status = try JSONDecoder().decode(StatusResponse.self, from: statusJSON)
        XCTAssertTrue(status.running)
        XCTAssertEqual(status.uptime, "10m")
        XCTAssertEqual(status.activeAgents, 2)

        let flagsJSON = """
        [
            {
                "id": "f1",
                "rule": "sensitive-read-then-connect",
                "severity": 3,
                "ts": "2026-08-12T18:00:00Z",
                "pid": 500,
                "agent": "cursor",
                "evidence": ["cursor (pid 500) read .env"]
            }
        ]
        """.data(using: .utf8)!

        let flags = try JSONDecoder().decode([FlagModel].self, from: flagsJSON)
        XCTAssertEqual(flags.count, 1)
        XCTAssertEqual(flags[0].id, "f1")
        XCTAssertEqual(flags[0].severity, 3)
        XCTAssertEqual(flags[0].agent, "cursor")
    }

    func testNotificationTitleMapping() {
        let leak = FlagModel(id: "1", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 1, agent: "claude", evidence: [])
        XCTAssertEqual(NotificationManager.title(for: leak), "Secret leaving in agent traffic")
        let unknown = FlagModel(id: "2", rule: "novel-rule", severity: 1, ts: "", pid: 1, agent: "claude", evidence: [])
        XCTAssertEqual(NotificationManager.title(for: unknown), "novel-rule")
    }

    func testStatusDecodesFirewallStats() throws {
        let json = """
        {
            "running": true,
            "uptime": "5m",
            "active_agents": 1,
            "uninspected_egress": 3,
            "firewall_stats": { "aws-key": { "would_block": 2, "blocked": 1, "legit": 0, "suspect": 0 } }
        }
        """.data(using: .utf8)!

        let s = try JSONDecoder().decode(StatusResponse.self, from: json)
        XCTAssertEqual(s.uninspectedEgress, 3)
        XCTAssertEqual(s.firewallStats?["aws-key"]?.wouldBlock, 2)
        XCTAssertEqual(s.firewallStats?["aws-key"]?.blocked, 1)
    }

    func testClientConnectsToAbsentSocketFailsGracefully() async {
        let client = DaemonClient(socketPath: "/tmp/nonexistent-secure-agent-\(UUID().uuidString).sock")
        do {
            _ = try await client.fetchStatus()
            XCTFail("Expected fetchStatus to fail for absent socket")
        } catch {
            XCTAssertNotNil(error)
        }
    }

    /// Regression: fetchAudit built "/audit?limit=\(limit))" — a stray paren
    /// made the daemon ignore the limit and answer 100 rows. Stand up a real
    /// unix-socket listener and assert the exact request line.
    func testFetchAuditSendsExactRequestLine() async throws {
        let sockPath = "/tmp/secure-agent-test-\(UUID().uuidString).sock"
        defer { try? FileManager.default.removeItem(atPath: sockPath) }

        let serverFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(serverFD, 0)
        defer { Darwin.close(serverFD) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = sockPath.utf8CString
        _ = withUnsafeMutableBytes(of: &addr.sun_path) { ptr in
            pathBytes.withUnsafeBufferPointer { pathPtr in
                ptr.copyBytes(from: UnsafeRawBufferPointer(pathPtr))
            }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(serverFD, $0, addrLen)
            }
        }
        XCTAssertEqual(bindRes, 0)
        XCTAssertEqual(Darwin.listen(serverFD, 1), 0)

        let captured = RequestCapture()
        let server = Task.detached {
            let conn = Darwin.accept(serverFD, nil, nil)
            guard conn >= 0 else { return }
            var buf = [UInt8](repeating: 0, count: 4096)
            var data = Data()
            // One read is enough for a request this small; stop at the header
            // terminator so we don't block on the client closing.
            while data.range(of: Data("\r\n\r\n".utf8)) == nil {
                let n = Darwin.read(conn, &buf, buf.count)
                if n <= 0 { break }
                data.append(contentsOf: buf[0..<n])
            }
            captured.request = String(decoding: data, as: UTF8.self)
            let body = "[]"
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
            _ = resp.utf8.withContiguousStorageIfAvailable { Darwin.write(conn, $0.baseAddress!, $0.count) }
            Darwin.close(conn)
        }
        defer { server.cancel() }

        let client = DaemonClient(socketPath: sockPath)
        let rows = try await client.fetchAudit(limit: 42)
        XCTAssertEqual(rows.count, 0)
        let line = captured.request?.components(separatedBy: "\r\n").first ?? ""
        XCTAssertEqual(line, "GET /audit?limit=42 HTTP/1.1", "request line must carry a clean query string")
    }

    // MARK: - HTTP response parsing (the hand-rolled transport)

    func testParseHTTPResponseExtractsBody() throws {
        let raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        let body = try DaemonClient.parseHTTPResponse(Data(raw.utf8))
        XCTAssertEqual(String(data: body, encoding: .utf8), "{}")
    }

    func testParseHTTPResponseRejectsErrorStatus() {
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        XCTAssertThrowsError(try DaemonClient.parseHTTPResponse(Data(raw.utf8))) { err in
            guard let e = err as? DaemonClientError else {
                return XCTFail("wrong error type: \(err)")
            }
            XCTAssertEqual(e, DaemonClientError.http(404))
        }
    }

    func testParseHTTPResponseRejectsMalformed() {
        XCTAssertThrowsError(try DaemonClient.parseHTTPResponse(Data("garbage".utf8)))
    }

    func testParseHTTPResponseDechunks() throws {
        // Go's net/http chunk-encodes responses larger than its 2KB buffer even
        // over a unix socket — a client that can't dechunk corrupts the JSON.
        let payload = #"{"running":true}"#
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
            String(format: "%x\r\n", payload.utf8.count) + payload + "\r\n0\r\n\r\n"
        let body = try DaemonClient.parseHTTPResponse(Data(raw.utf8))
        XCTAssertEqual(String(data: body, encoding: .utf8), payload)
    }

    func testDechunkHandlesSplitChunks() throws {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        let body = try DaemonClient.parseHTTPResponse(Data(raw.utf8))
        XCTAssertEqual(String(data: body, encoding: .utf8), "hello world")
    }

    // MARK: - request-line safety

    func testURLQueryEscapeNeutralizesInjection() {
        XCTAssertEqual(DaemonClient.urlQueryEscape("a&b=c"), "a%26b%3Dc")
        XCTAssertEqual(DaemonClient.urlQueryEscape("x y"), "x%20y")
        // CR/LF in a daemon-supplied id must not inject headers into the
        // hand-written request line.
        let evil = DaemonClient.urlQueryEscape("x\r\nX-Injected: y")
        XCTAssertFalse(evil.contains("\r"))
        XCTAssertFalse(evil.contains("\n"))
        XCTAssertEqual(DaemonClient.urlQueryEscape("plain-id_1.2"), "plain-id_1.2")
    }

    // MARK: - notification body redaction

    func testNotificationBodyIsRedacted() {
        // Lock-screen banners must not carry paths/hostnames from evidence.
        let flag = FlagModel(id: "1", rule: "proxy-secret-leak", severity: 3, ts: "", pid: 1,
                             agent: "claude",
                             evidence: ["anthropic-key detected in request body to logs.example.com"])
        let body = NotificationManager.redactedBody(for: flag)
        XCTAssertFalse(body.contains("logs.example.com"))
        XCTAssertFalse(body.contains("anthropic-key"))
    }
}

// Regression: list endpoints with zero rows answered `null` (nil-slice
// encoding), crashing the strict array decode — the process transcript sheet
// showed "The data couldn't be read because it is missing". null must decode
// as an empty array; garbage must still error.
final class NullListDecodeTests: XCTestCase {
    func testNullDecodesAsEmptyArray() throws {
        let events = try DaemonClient.decodeBody([EventModel].self, path: "/events?pid=1", body: Data("null".utf8))
        XCTAssertEqual(events.count, 0)
        let flags = try DaemonClient.decodeBody([FlagModel].self, path: "/flags", body: Data("null\n".utf8))
        XCTAssertEqual(flags.count, 0)
    }

    func testGarbageStillErrors() {
        XCTAssertThrowsError(try DaemonClient.decodeBody([EventModel].self, path: "/events", body: Data("nope".utf8))) { err in
            XCTAssertTrue(err.localizedDescription.contains("/events"), "error must name the path: \(err)")
        }
    }

    func testRealArrayStillDecodes() throws {
        let body = Data(#"[{"kind":5,"ts":"2026-09-15T01:00:00Z","pid":42}]"#.utf8)
        let events = try DaemonClient.decodeBody([EventModel].self, path: "/events", body: body)
        XCTAssertEqual(events.first?.pid, 42)
    }
}
