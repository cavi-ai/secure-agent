import Foundation
import Darwin

public final class DaemonClient: Sendable {
    public let socketPath: String

    public init(socketPath: String? = nil) {
        if let path = socketPath {
            self.socketPath = (path as NSString).expandingTildeInPath
        } else {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            self.socketPath = "\(home)/.config/secure-agent/daemon.sock"
        }
    }

    public func fetchStatus() async throws -> StatusResponse {
        let body = try await request(method: "GET", path: "/status")
        return try JSONDecoder().decode(StatusResponse.self, from: body)
    }

    public func fetchFlags(limit: Int = 20) async throws -> [FlagModel] {
        let body = try await request(method: "GET", path: "/flags?limit=\(limit)")
        return try JSONDecoder().decode([FlagModel].self, from: body)
    }

    public func fetchEvents(limit: Int = 50) async throws -> [EventModel] {
        let body = try await request(method: "GET", path: "/events?limit=\(limit)")
        return try JSONDecoder().decode([EventModel].self, from: body)
    }

    public func fetchIncidents(limit: Int = 20) async throws -> [IncidentReportModel] {
        let body = try await request(method: "GET", path: "/incidents?limit=\(limit)")
        return try JSONDecoder().decode([IncidentReportModel].self, from: body)
    }

    public func fetchIncidentMarkdown(id: String) async throws -> String {
        let body = try await request(method: "GET", path: "/incidents?id=\(id)&format=markdown")
        return String(data: body, encoding: .utf8) ?? ""
    }

    public func killProcess(pid: Int32) async throws -> Bool {
        let payload = ["pid": pid]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        let body = try await request(method: "POST", path: "/kill", body: jsonData)
        if let str = String(data: body, encoding: .utf8), str.contains("ok") {
            return true
        }
        return false
    }

    public func setFirewallMode(rule: String, mode: String) async throws {
        let payload: [String: String] = ["rule": rule, "mode": mode]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        _ = try await request(method: "POST", path: "/firewall/mode", body: jsonData)
    }

    public func executeRotation(incidentId: String, itemId: String) async throws -> String {
        let payload: [String: String] = ["incident_id": incidentId, "item_id": itemId]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        let body = try await request(method: "POST", path: "/rotate", body: jsonData)
        if let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
           let msg = json["message"] as? String {
            return msg
        }
        return "Rotation action executed."
    }

    private func request(method: String, path: String, body: Data? = nil) async throws -> Data {
        let socketPath = self.socketPath
        return try await Task.detached {
            let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
            guard fd >= 0 else {
                throw NSError(domain: "DaemonClient", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create socket"])
            }
            defer { Darwin.close(fd) }

            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)

            let pathBytes = socketPath.utf8CString
            guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
                throw NSError(domain: "DaemonClient", code: -2, userInfo: [NSLocalizedDescriptionKey: "Socket path too long"])
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
                throw NSError(domain: "DaemonClient", code: -3, userInfo: [NSLocalizedDescriptionKey: "Failed to connect to socket at \(socketPath)"])
            }

            var requestString = "\(method) \(path) HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            if let bodyData = body {
                requestString += "Content-Type: application/json\r\nContent-Length: \(bodyData.count)\r\n\r\n"
            } else {
                requestString += "\r\n"
            }

            guard let reqData = requestString.data(using: .utf8) else {
                throw NSError(domain: "DaemonClient", code: -4, userInfo: [NSLocalizedDescriptionKey: "Invalid request string"])
            }

            var written = 0
            try reqData.withUnsafeBytes { ptr in
                while written < reqData.count {
                    let res = Darwin.write(fd, ptr.baseAddress! + written, reqData.count - written)
                    if res <= 0 {
                        throw NSError(domain: "DaemonClient", code: -5, userInfo: [NSLocalizedDescriptionKey: "Write failed"])
                    }
                    written += res
                }
            }

            if let bodyData = body {
                written = 0
                try bodyData.withUnsafeBytes { ptr in
                    while written < bodyData.count {
                        let res = Darwin.write(fd, ptr.baseAddress! + written, bodyData.count - written)
                        if res <= 0 {
                            throw NSError(domain: "DaemonClient", code: -6, userInfo: [NSLocalizedDescriptionKey: "Body write failed"])
                        }
                        written += res
                    }
                }
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
                    throw NSError(domain: "DaemonClient", code: -7, userInfo: [NSLocalizedDescriptionKey: "Read error"])
                }
            }

            // Separate headers and body
            guard let headerEnd = responseData.range(of: Data("\r\n\r\n".utf8)) else {
                return responseData
            }
            return responseData.subdata(in: headerEnd.upperBound..<responseData.count)
        }.value
    }
}
