import XCTest
@testable import SecureAgentMenubar

final class DaemonClientTests: XCTestCase {
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

    func testClientConnectsToAbsentSocketFailsGracefully() async {
        let client = DaemonClient(socketPath: "/tmp/nonexistent-secure-agent-\(UUID().uuidString).sock")
        do {
            _ = try await client.fetchStatus()
            XCTFail("Expected fetchStatus to fail for absent socket")
        } catch {
            XCTAssertNotNil(error)
        }
    }
}
