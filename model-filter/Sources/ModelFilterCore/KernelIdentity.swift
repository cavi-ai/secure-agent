import Darwin
import Foundation
import Security

public enum KernelIdentity {
  public static func current() throws -> ProcessIdentity {
    var token = audit_token_t()
    var count = mach_msg_type_number_t(
      MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
    let result = withUnsafeMutablePointer(to: &token) { pointer in
      pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
        task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
      }
    }
    guard result == KERN_SUCCESS, count == 8 else { throw FilterError.identityUnavailable }
    return try ProcessIdentity(auditToken: withUnsafeBytes(of: token) { Data($0) })
  }

  /// Read kernel-attested socket credentials without process arguments or environment.
  public static func daemon(socketPath: String) throws -> ProcessIdentity {
    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw FilterError.identityUnavailable }
    defer { Darwin.close(fd) }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let bytes = socketPath.utf8CString
    guard !socketPath.contains("\0"), bytes.count <= MemoryLayout.size(ofValue: address.sun_path)
    else { throw FilterError.identityUnavailable }
    bytes.withUnsafeBytes { source in
      withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: source) }
    }
    let flags = fcntl(fd, F_GETFL)
    guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
      throw FilterError.identityUnavailable
    }
    let connected = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(fd, $0, socklen_t(2 + bytes.count))
      }
    }
    if connected != 0 {
      guard errno == EINPROGRESS else { throw FilterError.identityUnavailable }
      var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
      guard poll(&descriptor, 1, 2000) > 0 else { throw FilterError.identityUnavailable }
      var result: Int32 = 0
      var length = socklen_t(MemoryLayout<Int32>.size)
      guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &result, &length) == 0, result == 0 else {
        throw FilterError.identityUnavailable
      }
    }
    var token = audit_token_t()
    var length = socklen_t(MemoryLayout<audit_token_t>.size)
    guard getsockopt(fd, 0, LOCAL_PEERTOKEN, &token, &length) == 0, length == 32 else {
      throw FilterError.identityUnavailable
    }
    let data = withUnsafeBytes(of: token) { Data($0) }
    let identity = try ProcessIdentity(auditToken: data)
    guard identity.uid == getuid() else { throw FilterError.identityUnavailable }
    try verifyDaemon(auditToken: data)
    return identity
  }

  public static func signingTeam() throws -> String {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
      throw FilterError.signingRequired
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
      throw FilterError.signingRequired
    }
    var info: CFDictionary?
    guard
      SecCodeCopySigningInformation(
        staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
      let values = info as? [String: Any],
      let team = values[kSecCodeInfoTeamIdentifier as String] as? String,
      team.count == 10, team.allSatisfy({ $0.isASCII && ($0.isUppercase || $0.isNumber) })
    else { throw FilterError.signingRequired }
    return team
  }

  private static func verifyDaemon(auditToken: Data) throws {
    let team = try signingTeam()
    var code: SecCode?
    let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code
    else { throw FilterError.daemonSignature }
    var requirement: SecRequirement?
    let text =
      "anchor apple generic and identifier \"com.cavi-ai.secure-agent.daemon\" and certificate leaf[subject.OU] = \"\(team)\""
    guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
      SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement)
        == errSecSuccess
    else { throw FilterError.daemonSignature }
  }
}
