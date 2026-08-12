import Foundation

public struct StatusResponse: Codable, Sendable {
    public let running: Bool
    public let uptime: String
    public let activeAgents: Int

    enum CodingKeys: String, CodingKey {
        case running
        case uptime
        case activeAgents = "active_agents"
    }

    public init(running: Bool, uptime: String, activeAgents: Int) {
        self.running = running
        self.uptime = uptime
        self.activeAgents = activeAgents
    }
}

public struct FlagModel: Codable, Identifiable, Sendable {
    public let id: String
    public let rule: String
    public let severity: Int
    public let ts: String
    public let pid: Int32
    public let agent: String
    public let evidence: [String]

    public init(id: String, rule: String, severity: Int, ts: String, pid: Int32, agent: String, evidence: [String]) {
        self.id = id
        self.rule = rule
        self.severity = severity
        self.ts = ts
        self.pid = pid
        self.agent = agent
        self.evidence = evidence
    }
}

public struct EventModel: Codable, Identifiable, Sendable {
    public var id: String { "\(kind)-\(pid)-\(ts)" }
    public let kind: Int
    public let ts: String
    public let pid: Int32
    public let exePath: String?
    public let path: String?
    public let remoteHost: String?
    public let remotePort: Int?
    public let detail: String?

    enum CodingKeys: String, CodingKey {
        case kind
        case ts
        case pid
        case exePath = "exe_path"
        case path
        case remoteHost = "remote_host"
        case remotePort = "remote_port"
        case detail
    }

    public init(kind: Int, ts: String, pid: Int32, exePath: String? = nil, path: String? = nil, remoteHost: String? = nil, remotePort: Int? = nil, detail: String? = nil) {
        self.kind = kind
        self.ts = ts
        self.pid = pid
        self.exePath = exePath
        self.path = path
        self.remoteHost = remoteHost
        self.remotePort = remotePort
        self.detail = detail
    }
}
