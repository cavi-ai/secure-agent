import Foundation
import Darwin

/// One parsed Server-Sent-Events frame (`event:` + `data:`). Comment lines
/// (`: ping` heartbeats) never surface as frames.
public struct SSEFrame: Equatable, Sendable {
    public let event: String
    public let data: String
}

/// Incremental SSE frame parser. Feed it arbitrary read() chunks; it returns
/// every frame completed by those bytes. A frame boundary is a blank line;
/// multi-line `data:` fields are joined with "\n" per RFC 9112 §9.2.6.
public struct SSEParser {
    private var buffer = Data()
    /// Defensive cap: a peer that never terminates a frame must not grow the
    /// buffer without bound. The daemon's frames are small JSON objects.
    private static let maxBufferedBytes = 1 << 20

    public init() {}

    public mutating func append(_ chunk: Data) -> [SSEFrame] {
        buffer.append(chunk)
        if buffer.count > Self.maxBufferedBytes {
            buffer.removeAll(keepingCapacity: false)
            return []
        }
        var frames: [SSEFrame] = []
        let separator = Data("\n\n".utf8)
        while let range = buffer.range(of: separator) {
            let block = buffer.subdata(in: 0..<range.lowerBound)
            buffer.removeSubrange(0..<range.upperBound)
            if let frame = Self.parse(block) {
                frames.append(frame)
            }
        }
        return frames
    }

    static func parse(_ block: Data) -> SSEFrame? {
        var event = "message"
        var dataLines: [String] = []
        for lineBytes in block.split(separator: 0x0A, omittingEmptySubsequences: false) {
            guard let line = String(data: Data(lineBytes), encoding: .utf8) else { continue }
            if line.hasPrefix(":") { continue } // comment / heartbeat
            if let v = line.dropPrefix("event:") {
                event = v
            } else if let v = line.dropPrefix("data:") {
                dataLines.append(v)
            }
        }
        guard !dataLines.isEmpty else { return nil }
        return SSEFrame(event: event, data: dataLines.joined(separator: "\n"))
    }
}

private extension String {
    /// SSE field syntax: "field:value" or "field: value" (one leading space
    /// is stripped per spec).
    func dropPrefix(_ field: String) -> String? {
        guard hasPrefix(field) else { return nil }
        var v = String(dropFirst(field.count))
        if v.hasPrefix(" ") { v.removeFirst() }
        return v
    }
}

/// Box holding the stream socket fd so task cancellation can close it and
/// unblock a parked read().
final class FDBox: @unchecked Sendable {
    private var lock = NSLock()
    private var fd: Int32 = -1

    func set(_ newFD: Int32) {
        lock.lock()
        fd = newFD
        lock.unlock()
    }

    /// Close exactly once; safe from any thread. After close, read() on the
    /// old fd fails with EBADF and the read loop exits.
    func close() {
        lock.lock()
        let old = fd
        fd = -1
        lock.unlock()
        if old >= 0 { Darwin.close(old) }
    }
}

public extension DaemonClient {

    /// Idle limit for the event stream. The daemon emits a heartbeat comment
    /// every 15s, so 45s of silence means the connection is dead even if the
    /// socket hasn't noticed.
    static let streamIdleTimeoutSeconds: Int = 45

    /// Consume `/events/stream` until the stream ends, errors, or the task is
    /// cancelled. Each parsed frame is delivered to `onEvent` (called on the
    /// detached task's context; hop to MainActor in the handler as needed).
    ///
    /// Throws DaemonClientError on transport failure or non-2xx status — the
    /// caller owns reconnect/backoff policy. Cancellation closes the socket,
    /// which breaks the blocking read loop.
    func streamEvents(onEvent: @escaping @Sendable (SSEFrame) -> Void) async throws {
        let socketPath = self.socketPath
        let fdBox = FDBox()
        try await withTaskCancellationHandler {
            try await Task.detached {
                let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
                guard fd >= 0 else { throw DaemonClientError.transport("failed to create socket") }
                fdBox.set(fd)
                defer { fdBox.close() }

                // Recv timeout implements the idle watchdog: heartbeats reset it.
                var tv = timeval(tv_sec: DaemonClient.streamIdleTimeoutSeconds, tv_usec: 0)
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

                var addr = sockaddr_un()
                addr.sun_family = sa_family_t(AF_UNIX)
                let pathBytes = socketPath.utf8CString
                guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
                    throw DaemonClientError.transport("socket path too long")
                }
                pathBytes.withUnsafeBufferPointer { pathPtr in
                    withUnsafeMutableBytes(of: &addr.sun_path) { ptr in
                        ptr.copyBytes(from: UnsafeRawBufferPointer(pathPtr))
                    }
                }
                let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
                let connRes = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(fd, $0, addrLen)
                    }
                }
                guard connRes == 0 else {
                    throw DaemonClientError.transport("connect failed: \(String(cString: strerror(errno)))")
                }

                let requestString = "GET /events/stream HTTP/1.1\r\nHost: localhost\r\nAccept: text/event-stream\r\n\r\n"
                var reqData = Data(requestString.utf8)
                try reqData.withUnsafeBytes { ptr in
                    var written = 0
                    while written < reqData.count {
                        let res = Darwin.write(fd, ptr.baseAddress! + written, reqData.count - written)
                        guard res > 0 else {
                            throw DaemonClientError.transport("write error: \(String(cString: strerror(errno)))")
                        }
                        written += res
                    }
                }
                reqData = Data()

                var parser = SSEParser()
                // Headers can split across reads; buffer until the terminator
                // before treating anything as stream data.
                var headerBuf = Data()
                var headersDone = false
                var buffer = [UInt8](repeating: 0, count: 4096)
                while true {
                    let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                    if n == 0 {
                        throw DaemonClientError.transport("stream closed by daemon")
                    }
                    if n < 0 {
                        if errno == EINTR { continue }
                        if errno == EAGAIN || errno == EWOULDBLOCK {
                            throw DaemonClientError.transport("stream idle timeout (no heartbeat)")
                        }
                        if errno == EBADF { throw CancellationError() } // cancelled
                        throw DaemonClientError.transport("read error: \(String(cString: strerror(errno)))")
                    }
                    let chunk = Data(buffer[0..<n])
                    if !headersDone {
                        headerBuf.append(chunk)
                        guard let headerEnd = headerBuf.range(of: Data("\r\n\r\n".utf8)) else {
                            if headerBuf.count > 64 * 1024 {
                                throw DaemonClientError.transport("headers never terminated")
                            }
                            continue
                        }
                        headersDone = true
                        let head = String(data: headerBuf.subdata(in: 0..<headerEnd.lowerBound), encoding: .utf8) ?? ""
                        guard head.hasPrefix("HTTP/1.1 200") else {
                            // Surface 503 etc. so the caller can fall back to polling.
                            let parts = head.split(separator: " ")
                            let code = parts.count >= 2 ? Int(parts[1]) ?? 0 : 0
                            throw DaemonClientError.http(code)
                        }
                        let rest = headerBuf.subdata(in: headerEnd.upperBound..<headerBuf.count)
                        if rest.isEmpty { continue }
                        for frame in parser.append(rest) { onEvent(frame) }
                        continue
                    }
                    for frame in parser.append(chunk) { onEvent(frame) }
                }
            }.value
        } onCancel: {
            fdBox.close()
        }
    }
}
