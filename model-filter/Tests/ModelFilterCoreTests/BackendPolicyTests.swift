import XCTest

@testable import ModelFilterCore

final class BackendPolicyTests: XCTestCase {
  let daemon = ProcessIdentity(pid: 42, uid: 501, pidVersion: 7)

  func testOnlyPinnedDaemonMayReachProtectedLoopbackPorts() throws {
    let policy = try BackendPolicy(ports: [11434], daemon: daemon)
    for host in [
      "127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1", "localhost", "::1%lo0", "0.0.0.0", "::",
    ] {
      XCTAssertTrue(policy.allows(host: host, port: 11434, process: daemon))
      XCTAssertFalse(policy.allows(host: host, port: 11434, process: nil))
      XCTAssertFalse(
        policy.allows(
          host: host, port: 11434, process: ProcessIdentity(pid: 42, uid: 501, pidVersion: 8)))
      XCTAssertFalse(
        policy.allows(
          host: host, port: 11434, process: ProcessIdentity(pid: 42, uid: 502, pidVersion: 7)))
      XCTAssertTrue(policy.allows(host: host, port: 11435, process: nil))
    }
    XCTAssertTrue(policy.allows(host: "192.0.2.1", port: 11434, process: nil))
    XCTAssertFalse(policy.allows(host: nil, port: nil, process: nil))
    XCTAssertFalse(policy.allows(host: "127.0.0.1", port: 0, process: daemon))
    XCTAssertFalse(policy.allows(host: "unresolved.invalid", port: 11434, process: nil))
  }

  func testInvalidPoliciesCannotBeConstructedOrDecoded() throws {
    for ports: [UInt16] in [[], [0], [11434, 11434], [1, 2, 3, 4, 5]] {
      XCTAssertThrowsError(try BackendPolicy(ports: ports, daemon: daemon))
    }
    XCTAssertThrowsError(
      try BackendPolicy(ports: [11434], daemon: ProcessIdentity(pid: 42, uid: 501, pidVersion: 0)))
    let raw = Data(
      #"{"version":2,"ports":[11434],"daemon":{"pid":42,"uid":501,"pidVersion":7}}"#.utf8)
    XCTAssertThrowsError(try JSONDecoder().decode(BackendPolicy.self, from: raw))
  }
}
