import XCTest
import Darwin
@testable import SecureAgentMenubar

final class EventStreamTests: XCTestCase {

    // MARK: - frame parser

    func testParserSplitsFramesOnBlankLines() {
        var p = SSEParser()
        let frames = p.append(Data("event: conn-open\ndata: {\"a\":1}\n\nevent: guard-prompt\ndata: {\"b\":2}\n\n".utf8))
        XCTAssertEqual(frames, [
            SSEFrame(event: "conn-open", data: "{\"a\":1}"),
            SSEFrame(event: "guard-prompt", data: "{\"b\":2}"),
        ])
    }

    func testParserHandlesPartialChunks() {
        var p = SSEParser()
        XCTAssertEqual(p.append(Data("event: conn".utf8)), [])
        XCTAssertEqual(p.append(Data("-open\ndata: {\"a\"".utf8)), [])
        let frames = p.append(Data(":1}\n\n".utf8))
        XCTAssertEqual(frames, [SSEFrame(event: "conn-open", data: "{\"a\":1}")])
    }

    func testParserIgnoresCommentsAndHeartbeats() {
        var p = SSEParser()
        let frames = p.append(Data(": secure-agent event stream\n\n: ping\n\nevent: x\ndata: y\n\n".utf8))
        XCTAssertEqual(frames, [SSEFrame(event: "x", data: "y")])
    }

    func testParserJoinsMultilineData() {
        var p = SSEParser()
        let frames = p.append(Data("data: line1\ndata: line2\n\n".utf8))
        XCTAssertEqual(frames, [SSEFrame(event: "message", data: "line1\nline2")])
    }

    func testParserCapsUnboundedBuffer() {
        var p = SSEParser()
        // 2 MiB with no frame boundary must not accumulate.
        _ = p.append(Data(repeating: 0x41, count: 2 << 20))
        // After the cap reset, a valid frame parses cleanly.
        let frames = p.append(Data("event: x\ndata: y\n\n".utf8))
        XCTAssertEqual(frames, [SSEFrame(event: "x", data: "y")])
    }

    // MARK: - live stream over a real unix socket

    /// Spin up a minimal SSE server on a temp unix socket and verify the
    /// client parses status line, headers, frames across chunk splits, and
    /// delivers them in order.
    func testStreamEventsDeliversFrames() async throws {
        let sockPath = "/tmp/sa-sse-test-\(UUID().uuidString).sock"
        defer { try? FileManager.default.removeItem(atPath: sockPath) }

        let serverFD = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(serverFD, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = sockPath.utf8CString
        pathBytes.withUnsafeBufferPointer { pathPtr in
            withUnsafeMutableBytes(of: &addr.sun_path) { ptr in
                ptr.copyBytes(from: UnsafeRawBufferPointer(pathPtr))
            }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let bindRes = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(serverFD, $0, addrLen) }
        }
        XCTAssertEqual(bindRes, 0)
        XCTAssertEqual(Darwin.listen(serverFD, 1), 0)

        // Server: accept, send headers, then two frames split across writes,
        // then a heartbeat, then close.
        Thread.detachNewThread {
            var clientAddr = sockaddr()
            var len = socklen_t(MemoryLayout<sockaddr>.size)
            let conn = Darwin.accept(serverFD, &clientAddr, &len)
            guard conn >= 0 else { return }
            // read the request (ignore contents)
            var buf = [UInt8](repeating: 0, count: 1024)
            _ = Darwin.read(conn, &buf, buf.count)
            let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n: preamble\n\n"
            _ = head.withCString { Darwin.write(conn, $0, strlen($0)) }
            usleep(100_000)
            let part1 = "event: conn-open\ndata: {\"part\""
            _ = part1.withCString { Darwin.write(conn, $0, strlen($0)) }
            usleep(100_000)
            let part2 = ":1}\n\nevent: guard-prompt\ndata: {}\n\n: ping\n\n"
            _ = part2.withCString { Darwin.write(conn, $0, strlen($0)) }
            usleep(100_000)
            Darwin.close(conn)
            Darwin.close(serverFD)
        }

        let client = DaemonClient(socketPath: sockPath)
        let collected = OSAllocatedUnfairLock<[SSEFrame]>(initialState: [])
        do {
            try await client.streamEvents { frame in
                collected.withLock { $0.append(frame) }
            }
            XCTFail("stream should end with an error when the server closes")
        } catch {
            // server close surfaces as a transport error — expected
        }
        let frames = collected.withLock { $0 }
        XCTAssertEqual(frames, [
            SSEFrame(event: "conn-open", data: "{\"part\":1}"),
            SSEFrame(event: "guard-prompt", data: "{}"),
        ])
    }
}

/// Tiny lock box (avoids importing os.lock free functions into test noise).
final class OSAllocatedUnfairLock<State>: @unchecked Sendable {
    private var lock = NSLock()
    private var state: State
    init(initialState: State) { state = initialState }
    func withLock<R>(_ body: (inout State) -> R) -> R {
        lock.lock()
        defer { lock.unlock() }
        return body(&state)
    }
}
