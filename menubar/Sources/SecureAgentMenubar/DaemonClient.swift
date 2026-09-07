import Foundation
import Darwin

/// Errors from the daemon transport. The distinction matters: a transport
/// failure means "daemon unreachable" (flip the UI to disconnected), while a
/// decode failure means "daemon answered but spoke something unexpected" —
/// the daemon is up and the UI must not claim otherwise.
public enum DaemonClientError: Error, Equatable {
    case transport(String)
    case http(Int)
    case decode(String)
}

/// The surface AppState (and tests) use. DaemonClient conforms; tests stub it.
public protocol DaemonClientProtocol: Sendable {
    func fetchStatus() async throws -> StatusResponse
    func fetchFlags(limit: Int) async throws -> [FlagModel]
    func fetchIncidents(limit: Int) async throws -> [IncidentReportModel]
    func fetchGuardRules() async throws -> [GuardRuleModel]
    func fetchGuardPending() async throws -> [GuardPending]
    func resolveGuard(_ req: GuardResolveRequest) async throws
    func killProcess(pid: Int32) async throws -> Bool
    func deleteGuardRule(agent: String, ruleID: String) async throws
    func setFirewallMode(rule: String, mode: String) async throws
    func streamEvents(onEvent: @escaping @Sendable (SSEFrame) -> Void) async throws
}

extension DaemonClient: DaemonClientProtocol {}

public final class DaemonClient: Sendable {
    public let socketPath: String

    /// Every socket op (connect, write, read) is bounded by this. The daemon
    /// is local; if it hasn't answered in 3s it is wedged, and the UI must
    /// degrade instead of parking a cooperative-pool thread forever.
    public static let ioTimeoutSeconds: Int = 3

    public init(socketPath: String? = nil) {
        if let path = socketPath {
            self.socketPath = (path as NSString).expandingTildeInPath
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.socketPath = "\(home)/.config/secure-agent/daemon.sock"
        }
    }

    public func fetchStatus() async throws -> StatusResponse {
        try await getDecodable("/status")
    }

    public func fetchFlags(limit: Int = 20) async throws -> [FlagModel] {
        try await getDecodable("/flags?limit=\(limit)")
    }

    public func fetchEvents(limit: Int = 50) async throws -> [EventModel] {
        try await getDecodable("/events?limit=\(limit)")
    }

    public func fetchIncidents(limit: Int = 20) async throws -> [IncidentReportModel] {
        try await getDecodable("/incidents?limit=\(limit)")
    }

    public func fetchIncidentMarkdown(id: String) async throws -> String {
        let body = try await request(method: "GET", path: "/incidents?id=\(Self.urlQueryEscape(id))&format=markdown")
        return String(data: body, encoding: .utf8) ?? ""
    }

    /// Returns true only when the daemon's JSON response actually says
    /// `"status":"ok"` — substring matching treated error text containing
    /// "ok" (e.g. "booking conflict") as a successful kill.
    public func killProcess(pid: Int32) async throws -> Bool {
        let payload = ["pid": pid]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        let body = try await request(method: "POST", path: "/kill", body: jsonData)
        struct KillResp: Decodable { let status: String? }
        guard let resp = try? JSONDecoder().decode(KillResp.self, from: body) else {
            return false
        }
        return resp.status == "ok"
    }

    public func registerSecrets() async throws -> [String] {
        let body = try await request(method: "POST", path: "/firewall/fingerprints/ingest")
        struct Resp: Decodable { let registered: [String]? }
        let r = try JSONDecoder().decode(Resp.self, from: body)
        return r.registered ?? []
    }

    public func setFirewallMode(rule: String, mode: String) async throws {
        let payload: [String: String] = ["rule": rule, "mode": mode]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        _ = try await request(method: "POST", path: "/firewall/mode", body: jsonData)
    }

    // Guard endpoints decode STRICTLY. A malformed /guard/pending response that
    // silently decodes to [] suppresses the Allow/Deny prompt — a fail-open on
    // the security-critical path. Throwing lets the UI surface an error state
    // instead of pretending there is nothing to approve.
    public func fetchGuardPending() async throws -> [GuardPending] {
        try await getDecodable("/guard/pending")
    }

    public func resolveGuard(_ req: GuardResolveRequest) async throws {
        let data = try JSONEncoder().encode(req)
        _ = try await request(method: "POST", path: "/guard/resolve", body: data)
    }

    public func fetchGuardRules() async throws -> [GuardRuleModel] {
        try await getDecodable("/guard/rules")
    }

    public func deleteGuardRule(agent: String, ruleID: String) async throws {
        _ = try await request(method: "DELETE",
                              path: "/guard/rules?agent=\(Self.urlQueryEscape(agent))&rule_id=\(Self.urlQueryEscape(ruleID))")
    }

    /// Percent-encode a value bound for the request line's query string. These
    /// values come from daemon-supplied JSON; a raw `&`, `?`, space, or CR/LF
    /// would corrupt or inject into the hand-written HTTP request.
    static func urlQueryEscape(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private func getDecodable<T: Decodable>(_ path: String) async throws -> T {
        let body = try await request(method: "GET", path: path)
        do {
            return try JSONDecoder().decode(T.self, from: body)
        } catch {
            throw DaemonClientError.decode("\(path): \(error.localizedDescription)")
        }
    }

    private func request(method: String, path: String, body: Data? = nil) async throws -> Data {
        let socketPath = self.socketPath
        return try await Task.detached {
            let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else {
                throw DaemonClientError.transport("failed to create socket")
            }
            defer { Darwin.close(fd) }

            // Send/recv timeouts: a wedged daemon that accepts but never answers
            // must not block this thread forever.
            var tv = timeval(tv_sec: DaemonClient.ioTimeoutSeconds, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

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

            // Bounded connect: a listener with a full backlog can block connect
            // indefinitely; go non-blocking, select with a deadline, then
            // restore blocking mode (SO_RCVTIMEO/SO_SNDTIMEO cover the rest).
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            let connRes = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, addrLen)
                }
            }
            if connRes != 0 && errno != EINPROGRESS {
                throw DaemonClientError.transport("connect failed: \(String(cString: strerror(errno)))")
            }
            if connRes != 0 {
                var wset = fd_set()
                self.fdZero(&wset)
                self.fdSet(fd, &wset)
                var ctv = timeval(tv_sec: DaemonClient.ioTimeoutSeconds, tv_usec: 0)
                let sel = select(fd + 1, nil, &wset, nil, &ctv)
                guard sel > 0 else {
                    throw DaemonClientError.transport("connect timed out")
                }
                var soErr: Int32 = 0
                var soLen = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &soLen)
                guard soErr == 0 else {
                    throw DaemonClientError.transport("connect failed: \(String(cString: strerror(soErr)))")
                }
            }
            _ = fcntl(fd, F_SETFL, flags)

            var requestString = "\(method) \(path) HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            if let bodyData = body {
                requestString += "Content-Type: application/json\r\nContent-Length: \(bodyData.count)\r\n\r\n"
            } else {
                requestString += "\r\n"
            }

            guard let reqData = requestString.data(using: .utf8) else {
                throw DaemonClientError.transport("invalid request string")
            }

            try self.writeAll(fd: fd, data: reqData)
            if let bodyData = body {
                try self.writeAll(fd: fd, data: bodyData)
            }

            var responseData = Data()
            let bufferSize = 4096
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
            defer { buffer.deallocate() }

            while true {
                let bytesRead = Darwin.read(fd, buffer, bufferSize)
                if bytesRead > 0 {
                    responseData.append(buffer, count: bytesRead)
                } else if bytesRead == 0 {
                    break
                } else {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        throw DaemonClientError.transport("read timed out waiting for daemon response")
                    }
                    throw DaemonClientError.transport("read error: \(String(cString: strerror(errno)))")
                }
            }

            return try Self.parseHTTPResponse(responseData)
        }.value
    }

    private func writeAll(fd: Int32, data: Data) throws {
        var written = 0
        try data.withUnsafeBytes { ptr in
            while written < data.count {
                let res = Darwin.write(fd, ptr.baseAddress! + written, data.count - written)
                if res <= 0 {
                    if errno == EINTR { continue }
                    if errno == EAGAIN || errno == EWOULDBLOCK {
                        throw DaemonClientError.transport("write timed out")
                    }
                    throw DaemonClientError.transport("write error: \(String(cString: strerror(errno)))")
                }
                written += res
            }
        }
    }

    /// Parse the raw response: status line must be 2xx; body is taken after
    /// the header terminator, with a minimal dechunker for
    /// `Transfer-Encoding: chunked` (Go's net/http chunk-encodes responses
    /// larger than its 2KB buffer even over a unix socket).
    static func parseHTTPResponse(_ data: Data) throws -> Data {
        guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else {
            throw DaemonClientError.transport("malformed HTTP response (no header terminator)")
        }
        let head = data.subdata(in: 0..<headerEnd.upperBound)
        guard let statusLineEnd = head.range(of: Data("\r\n".utf8)),
              let statusLine = String(data: head.subdata(in: 0..<statusLineEnd.lowerBound), encoding: .utf8) else {
            throw DaemonClientError.transport("malformed HTTP status line")
        }
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let code = Int(parts[1]) else {
            throw DaemonClientError.transport("unparseable HTTP status line: \(statusLine)")
        }
        var body = data.subdata(in: headerEnd.upperBound..<data.count)
        let headText = String(data: head, encoding: .utf8)?.lowercased() ?? ""
        if headText.contains("transfer-encoding:") && headText.contains("chunked") {
            body = try dechunk(body)
        }
        guard (200..<300).contains(code) else {
            throw DaemonClientError.http(code)
        }
        return body
    }

    /// Minimal RFC 9112 chunked-body decoder: hex-size lines until a 0 chunk;
    /// trailers ignored. A malformed chunk stream is a transport error, never
    /// silently half-decoded JSON.
    static func dechunk(_ data: Data) throws -> Data {
        var out = Data()
        var i = data.startIndex
        while i < data.endIndex {
            guard let lineEnd = data.range(of: Data("\r\n".utf8), in: i..<data.endIndex) else {
                throw DaemonClientError.transport("malformed chunk (no size line)")
            }
            let sizeStr = String(data: data.subdata(in: i..<lineEnd.lowerBound), encoding: .utf8) ?? ""
            // strip optional chunk extensions ("ff;foo=bar")
            let hexPart = sizeStr.split(separator: ";").first.map(String.init) ?? ""
            guard let size = Int(hexPart.trimmingCharacters(in: .whitespaces), radix: 16) else {
                throw DaemonClientError.transport("malformed chunk size: \(sizeStr)")
            }
            if size == 0 { break }
            let start = lineEnd.upperBound
            let end = data.index(start, offsetBy: size, limitedBy: data.endIndex) ?? data.endIndex
            guard end == data.index(start, offsetBy: size, limitedBy: data.endIndex) else {
                throw DaemonClientError.transport("truncated chunk")
            }
            out.append(data.subdata(in: start..<end))
            // skip the chunk data + trailing CRLF
            let after = data.index(end, offsetBy: 2, limitedBy: data.endIndex) ?? data.endIndex
            i = after
        }
        return out
    }

    // fd_set helpers (Darwin's fd_set is a fixed-size struct, not a set type).
    private func fdZero(_ set: inout fd_set) {
        set.fds_bits = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    private func fdSet(_ fd: Int32, _ set: inout fd_set) {
        let int32Count = MemoryLayout<fd_set>.size / MemoryLayout<Int32>.size
        withUnsafeMutableBytes(of: &set) { ptr in
            let words = ptr.baseAddress!.assumingMemoryBound(to: Int32.self)
            let idx = Int(fd) / 32
            if idx < int32Count {
                words[idx] |= Int32(1) << (Int32(fd) % 32)
            }
        }
    }
}
