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
    /// A served action whose method or path cannot go on the request line.
    case invalidAction(String)
}

/// Human-readable failure reasons. Without this, every daemon error surfaced
/// as "The operation could not be completed. (…DaemonClientError error 1.)"
/// — the "dismiss failed without reason" complaint.
extension DaemonClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .transport(let detail):
            return "daemon unreachable (\(detail))"
        case .http(let code):
            if code == 401 || code == 403 {
                return "daemon refused the change (HTTP \(code)) — this client isn't allowed to change policy; restart Secure Agent if this persists"
            }
            return "daemon answered HTTP \(code)"
        case .decode(let detail):
            return "daemon answered unexpectedly (\(detail))"
        case .invalidAction(let detail):
            return "action not sent (\(detail))"
        }
    }
}

/// The surface AppState (and tests) use. DaemonClient conforms; tests stub it.
public protocol DaemonClientProtocol: Sendable {
    func fetchStatus() async throws -> StatusResponse
    func fetchResources() async throws -> ResourceSnapshotModel
    func fetchFlags(limit: Int) async throws -> [FlagModel]
    func fetchIncidents(limit: Int) async throws -> [IncidentReportModel]
    func fetchPosture() async throws -> PostureModel
    func fetchIncidentMarkdown(id: String) async throws -> String
    func fetchEvents(limit: Int) async throws -> [EventModel]
    func fetchEventsFor(pid: Int32, limit: Int) async throws -> [EventModel]
    /// POST /incidents/status — transition open → acknowledged → resolved.
    func setIncidentStatus(id: String, status: String, note: String?) async throws
    func fetchGuardRules() async throws -> [GuardRuleModel]
    func fetchGuardPending() async throws -> [GuardPending]
    func resolveGuard(_ req: GuardResolveRequest) async throws
    func killProcess(pid: Int32) async throws -> Bool
    func deleteGuardRule(agent: String, ruleID: String) async throws
    func setFirewallMode(rule: String, mode: String) async throws
    func promoteFirewallType(_ secretType: String, mode: String) async throws
    func fetchAdvisorDiscover() async throws -> AdvisorDiscovery
    func fetchRollup(hours: Int) async throws -> [RollupPointModel]
    func fetchAudit(limit: Int) async throws -> [AuditEntryModel]
    /// POST /allowlist — approve one host for one agent (stops flagging the
    /// pair; audited daemon-side as "allowlist-add").
    /// POST /advisor/retriage — re-run the advisor on an existing flag.
    /// Idempotent server-side (30s cooldown per flag); queued=false means
    /// "already in flight or recent" and is treated as success.
    /// POST /flags/acknowledge — mark a flag acted-upon (idempotent).
    func acknowledgeFlag(id: String) async throws
    func retriageFlag(id: String) async throws
    func allowlistAdd(agent: String, host: String) async throws
    /// POST /mute — suppress one rule+host pair (noise control; monitoring
    /// of the host continues).
    func muteAdd(rule: String, host: String) async throws
    /// GET /mute — persisted dispositions (the "ignore" ledger); title is
    /// the daemon's rule title.
    func fetchMutes() async throws -> [(rule: String, host: String, title: String?)]
    /// DELETE /mute — remove one disposition.
    func muteRemove(rule: String, host: String) async throws
    /// GET /notify/rules — notification policy: default severity bar +
    /// per-rule overrides (true = always page, false = never).
    func fetchNotifyRules() async throws -> NotifyRulesResponse
    /// POST /notify/rules — set (true/false) or clear (nil) one rule's
    /// override; nil returns the rule to the default policy.
    func setNotifyRule(rule: String, notify: Bool?) async throws
    /// POST /guard/path-allow — allow ONE path (and descendants) for one
    /// agent under one rule, without widening the rule itself.
    func guardPathAllowAdd(agent: String, ruleID: String, path: String) async throws
    func fetchGuardPathAllows() async throws -> [GuardPathAllowModel]
    func deleteGuardPathAllow(agent: String, ruleID: String, path: String) async throws
    func streamEvents(onEvent: @escaping @Sendable (SSEFrame) -> Void) async throws
    /// Send one served flag action (`explain.actions[]`) exactly as served:
    /// its method, path and JSON body.
    func perform(_ action: FlagExplainAction) async throws
}

extension DaemonClient: DaemonClientProtocol {}

public final class DaemonClient: Sendable {
    public let socketPath: String

    /// Every socket op (connect, write, read) is bounded by this. The daemon
    /// is local, but /status joins last-activity for every live pid and
    /// measured 2–4s with ~400 tracked processes — a 3s timeout made the
    /// healthy-but-slow daemon flap to "Disconnected" every poll. 10s
    /// tolerates the slow join; a genuinely wedged daemon still fails fast
    /// enough that the next poll retires it.
    public static let ioTimeoutSeconds: Int = 10

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

    public func fetchResources() async throws -> ResourceSnapshotModel {
        try await getDecodable("/resources")
    }

    public func fetchFlags(limit: Int = 20) async throws -> [FlagModel] {
        try await getDecodable("/flags?limit=\(limit)")
    }

    public func fetchEvents(limit: Int = 50) async throws -> [EventModel] {
        try await getDecodable("/events?limit=\(limit)")
    }

    /// Per-process transcript: events attributed to one pid. The daemon
    /// filters server-side (/events?pid=), so this stays cheap even for
    /// chatty processes.
    public func fetchEventsFor(pid: Int32, limit: Int = 300) async throws -> [EventModel] {
        try await getDecodable("/events?pid=\(pid)&limit=\(limit)")
    }

    public func fetchIncidents(limit: Int = 20) async throws -> [IncidentReportModel] {
        try await getDecodable("/incidents?limit=\(limit)")
    }

    /// /posture headline; attention derives from it, never locally.
    public func fetchPosture() async throws -> PostureModel {
        try await getDecodable("/posture")
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

    public func promoteFirewallType(_ secretType: String, mode: String) async throws {
        let payload: [String: String] = ["type": secretType, "mode": mode]
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

    public func setIncidentStatus(id: String, status: String, note: String?) async throws {
        var body: [String: Any] = ["id": id, "status": status]
        if let note, !note.isEmpty { body["note"] = note }
        let data = try JSONSerialization.data(withJSONObject: body)
        _ = try await request(method: "POST", path: "/incidents/status", body: data)
    }

    public func fetchGuardRules() async throws -> [GuardRuleModel] {
        try await getDecodable("/guard/rules")
    }

    /// Loopback model servers the user could link + the curated managed list.
    /// Older daemons (pre-discovery) don't have the route — degrade to an
    /// empty discovery rather than an error so the settings pane still opens.
    public func fetchAdvisorDiscover() async throws -> AdvisorDiscovery {
        do {
            return try await getDecodable("/advisor/discover")
        } catch DaemonClientError.http(404) {
            return AdvisorDiscovery(servers: [], managedModels: [])
        }
    }

    /// Hourly rollup counters (24h/7d trend views, weekly digest).
    public func fetchRollup(hours: Int) async throws -> [RollupPointModel] {
        do {
            return try await getDecodable("/stats/rollup?hours=\(hours)")
        } catch DaemonClientError.http(404) {
            return []
        }
    }

    /// Policy-change audit rows (digest counts allowlist approvals).
    public func fetchAudit(limit: Int = 50) async throws -> [AuditEntryModel] {
        try await getDecodable("/audit?limit=\(limit)")
    }

    public func acknowledgeFlag(id: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["flag_id": id])
        _ = try await request(method: "POST", path: "/flags/acknowledge", body: body)
    }

    public func retriageFlag(id: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["flag_id": id])
        _ = try await request(method: "POST", path: "/advisor/retriage", body: body)
    }

    public func allowlistAdd(agent: String, host: String) async throws {
        try await postJSON("/allowlist", payload: ["agent": agent, "host": host])
    }

    public func guardPathAllowAdd(agent: String, ruleID: String, path: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: [
            "agent": agent, "rule_id": ruleID, "path": path,
        ])
        _ = try await request(method: "POST", path: "/guard/path-allow", body: body)
    }

    public func fetchGuardPathAllows() async throws -> [GuardPathAllowModel] {
        try await getDecodable("/guard/path-allow")
    }

    public func deleteGuardPathAllow(agent: String, ruleID: String, path: String) async throws {
        let pathQ = "/guard/path-allow?agent=\(Self.urlQueryEscape(agent))&rule_id=\(Self.urlQueryEscape(ruleID))&path=\(Self.urlQueryEscape(path))"
        _ = try await request(method: "DELETE", path: pathQ)
    }

    public func fetchMutes() async throws -> [(rule: String, host: String, title: String?)] {
        let data = try await request(method: "GET", path: "/mute")
        guard let arr = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return [] }
        return arr.compactMap { d in
            guard let rule = d["rule"] as? String, let host = d["host"] as? String else { return nil }
            return (rule, host, d["title"] as? String)
        }
    }

    public func perform(_ action: FlagExplainAction) async throws {
        try Self.validate(action)
        let body = try action.body.map { try JSONEncoder().encode($0) }
        _ = try await request(method: action.method, path: action.path, body: body)
    }

    /// The exact method, path and required body keys for each in-place
    /// action id (AppState.inPlaceActionIDs) — read off the requests
    /// explain.go serves for each id.
    private struct ActionShape {
        let method: String
        let path: String
        let requiredBodyKeys: Set<String>
    }

    private static let actionShapes: [String: ActionShape] = [
        "allow-host": ActionShape(method: "POST", path: "/allowlist", requiredBodyKeys: ["agent", "host"]),
        "allow-path": ActionShape(method: "POST", path: "/guard/path-allow", requiredBodyKeys: ["agent", "rule_id", "path"]),
        "mute-rule-host": ActionShape(method: "POST", path: "/mute", requiredBodyKeys: ["rule", "host"]),
        "mute-class": ActionShape(method: "POST", path: "/mute", requiredBodyKeys: ["rule", "host"]),
        "dismiss": ActionShape(method: "POST", path: "/flags/acknowledge", requiredBodyKeys: []),
    ]

    /// A served action id runs with exactly the method/path/body keys the
    /// daemon serves for that id — never whatever method/path/body happens
    /// to arrive on the FlagExplainAction. Without this, a malformed or
    /// tampered action could carry any syntactically valid method and path
    /// for an otherwise-allowed id (e.g. `dismiss` pointed at `/kill`), and
    /// the pinned UI would send it as a confused deputy.
    static func validate(_ action: FlagExplainAction) throws {
        guard let shape = actionShapes[action.id] else {
            throw DaemonClientError.invalidAction("id \(action.id)")
        }
        guard action.method == shape.method, action.path == shape.path else {
            throw DaemonClientError.invalidAction("\(action.id) must be \(shape.method) \(shape.path)")
        }
        let keys: Set<String> = action.body.map { Set($0.keys) } ?? []
        if action.id == "dismiss" {
            guard keys.contains("flag_id") || keys.contains("flag_ids") else {
                throw DaemonClientError.invalidAction("dismiss missing flag_id or flag_ids")
            }
        } else {
            guard shape.requiredBodyKeys.isSubset(of: keys) else {
                throw DaemonClientError.invalidAction("\(action.id) missing required body keys")
            }
        }
    }

    public func muteRemove(rule: String, host: String) async throws {
        let q = "?rule=\(Self.urlQueryEscape(rule))&host=\(Self.urlQueryEscape(host))"
        _ = try await request(method: "DELETE", path: "/mute\(q)")
    }

    public func muteAdd(rule: String, host: String) async throws {
        try await postJSON("/mute", payload: ["rule": rule, "host": host])
    }

    /// Older daemons (pre-/notify/rules) answer 404 — degrade to the shipped
    /// default (severity >= 3 notifies, no overrides) so alerts still flow.
    public func fetchNotifyRules() async throws -> NotifyRulesResponse {
        do {
            return try await getDecodable("/notify/rules")
        } catch DaemonClientError.http(404) {
            return .fallback
        }
    }

    public func setNotifyRule(rule: String, notify: Bool?) async throws {
        var payload: [String: Any] = ["rule": rule]
        if let notify { payload["notify"] = notify }
        let body = try JSONSerialization.data(withJSONObject: payload)
        _ = try await request(method: "POST", path: "/notify/rules", body: body)
    }

    /// Shared POST-with-dict helper for the small disposition endpoints;
    /// both endpoints answer {"status":"ok",...} on success.
    private func postJSON(_ path: String, payload: [String: String]) async throws {
        let body = try JSONSerialization.data(withJSONObject: payload)
        _ = try await request(method: "POST", path: path, body: body)
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
        return try Self.decodeBody(T.self, path: path, body: body)
    }

    /// Decode one response body. Static and pure for tests. A list endpoint
    /// with zero rows may answer `null` (older daemons encoded a nil slice);
    /// for array responses that is [] in disguise — decode it as such
    /// instead of surfacing a bogus "daemon answered unexpectedly" (the
    /// process-transcript failure).
    static func decodeBody<T: Decodable>(_ type: T.Type, path: String, body: Data) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: body)
        } catch {
            if String(decoding: body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == "null",
               let empty = try? JSONDecoder().decode(T.self, from: Data("[]".utf8)) {
                return empty
            }
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
