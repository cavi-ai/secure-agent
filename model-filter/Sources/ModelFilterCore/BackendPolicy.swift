import Darwin
import Foundation

public enum FilterError: Error, LocalizedError {
  case invalidPolicy, identityUnavailable, signingRequired, daemonSignature
  case unavailable(String)
  public var errorDescription: String? {
    switch self {
    case .invalidPolicy:
      return "A valid daemon instance and one to four distinct backend ports are required."
    case .identityUnavailable: return "The kernel process identity could not be verified."
    case .signingRequired:
      return "Model filtering requires an entitled, provisioned Secure Agent build."
    case .daemonSignature: return "The running daemon does not match this app's signing identity."
    case .unavailable(let message): return message
    }
  }
}

public struct ProcessIdentity: Codable, Equatable, Sendable {
  public let pid: Int32
  public let uid: UInt32
  public let pidVersion: UInt32
  public init(pid: Int32, uid: UInt32, pidVersion: UInt32) {
    self.pid = pid
    self.uid = uid
    self.pidVersion = pidVersion
  }
  public init(auditToken: Data) throws {
    guard auditToken.count == 32 else { throw FilterError.identityUnavailable }
    let words = auditToken.withUnsafeBytes { raw in
      (0..<8).map { raw.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self) }
    }
    guard words[5] > 0, words[5] <= UInt32(Int32.max), words[7] > 0 else {
      throw FilterError.identityUnavailable
    }
    self.init(pid: Int32(words[5]), uid: words[1], pidVersion: words[7])
  }
}

public struct BackendPolicy: Codable, Sendable {
  public let version: Int
  public let ports: [UInt16]
  public let daemon: ProcessIdentity
  public init(ports: [UInt16], daemon: ProcessIdentity) throws {
    guard !ports.isEmpty, ports.count <= 4, Set(ports).count == ports.count,
      !ports.contains(0), daemon.pid > 0, daemon.pidVersion > 0
    else { throw FilterError.invalidPolicy }
    self.version = 1
    self.ports = ports
    self.daemon = daemon
  }
  public init(from decoder: Decoder) throws {
    let values = try decoder.container(keyedBy: CodingKeys.self)
    guard try values.decode(Int.self, forKey: .version) == 1 else {
      throw FilterError.invalidPolicy
    }
    try self.init(
      ports: values.decode([UInt16].self, forKey: .ports),
      daemon: values.decode(ProcessIdentity.self, forKey: .daemon))
  }
  public func allows(host: String?, port: UInt16?, process: ProcessIdentity?) -> Bool {
    guard let host, let port, port > 0 else { return false }
    guard ports.contains(port) else { return true }
    guard let loopback = Self.loopbackScope(host, includeUnspecified: true) else { return false }
    return !loopback || process == daemon
  }
  public static func isLoopback(_ address: String) -> Bool {
    loopbackScope(address, includeUnspecified: false) == true
  }
  private static func loopbackScope(_ raw: String, includeUnspecified: Bool) -> Bool? {
    if raw.lowercased() == "localhost" { return true }
    let address =
      raw.contains(":")
      ? String(raw.split(separator: "%", maxSplits: 1, omittingEmptySubsequences: false)[0]) : raw
    var ipv4 = in_addr()
    if inet_pton(AF_INET, address, &ipv4) == 1 {
      return withUnsafeBytes(of: ipv4) {
        $0[0] == 127 || includeUnspecified && $0.allSatisfy { $0 == 0 }
      }
    }
    var ipv6 = in6_addr()
    guard inet_pton(AF_INET6, address, &ipv6) == 1 else { return nil }
    return withUnsafeBytes(of: ipv6) { bytes in
      let loopback = bytes[0..<15].allSatisfy { $0 == 0 } && bytes[15] == 1
      let mapped =
        bytes[0..<10].allSatisfy { $0 == 0 } && bytes[10] == 255 && bytes[11] == 255
        && (bytes[12] == 127 || includeUnspecified && bytes[12..<16].allSatisfy { $0 == 0 })
      return loopback || mapped || includeUnspecified && bytes.allSatisfy { $0 == 0 }
    }
  }
}
