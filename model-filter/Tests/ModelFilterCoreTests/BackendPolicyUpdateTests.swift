import XCTest

@testable import ModelFilterCore

@MainActor
final class BackendPolicyUpdateTests: XCTestCase {
  let original = ProcessIdentity(pid: 42, uid: 501, pidVersion: 7)
  let restarted = ProcessIdentity(pid: 84, uid: 501, pidVersion: 8)

  func testApprovalPinsTheDaemonRunningAfterApproval() async throws {
    let approved = try BackendPolicy(ports: [11434], daemon: original)
    let current = try BackendPolicy(ports: [11434], daemon: restarted)
    var saved: BackendPolicy?
    try await BackendPolicyUpdate.afterOwnerApproval(
      approved: approved, current: { current }, save: { saved = $0 })
    XCTAssertEqual(saved?.daemon, restarted)
    XCTAssertFalse(saved?.allows(host: "127.0.0.1", port: 11434, process: original) ?? true)
  }

  func testApprovalRefusesChangedPortsOrOwner() async throws {
    let approved = try BackendPolicy(ports: [11434], daemon: original)
    for current in [
      try BackendPolicy(ports: [11434, 8080], daemon: restarted),
      try BackendPolicy(
        ports: [11434], daemon: ProcessIdentity(pid: 84, uid: 502, pidVersion: 8)),
    ] {
      var saved = false
      do {
        try await BackendPolicyUpdate.afterOwnerApproval(
          approved: approved, current: { current }, save: { _ in saved = true })
        XCTFail("A changed approval scope was accepted")
      } catch {}
      XCTAssertFalse(saved)
    }
  }

  func testRefreshDoesNotRestoreDisabledOrReconfiguredFilter() async throws {
    let previous = try BackendPolicy(ports: [11434], daemon: original)
    let current = try BackendPolicy(ports: [11434], daemon: restarted)
    let changed = try BackendPolicy(ports: [8080], daemon: original)
    for replacement: BackendPolicy? in [nil, changed, current] {
      var enabled: BackendPolicy? = previous
      var saved = false
      try await BackendPolicyUpdate.refresh(
        previous: previous, expectedPID: restarted.pid,
        current: {
          // Owner changes preferences while daemon startup is awaited.
          enabled = replacement
          return current
        }, reloadEnabled: { enabled }, save: { _ in saved = true })
      XCTAssertFalse(saved)
    }
  }

  func testRefreshUpdatesOnlyTheExpectedDaemonWithinApprovedScope() async throws {
    let previous = try BackendPolicy(ports: [11434], daemon: original)
    let current = try BackendPolicy(ports: [11434], daemon: restarted)
    var saved: BackendPolicy?
    try await BackendPolicyUpdate.refresh(
      previous: previous, expectedPID: restarted.pid, current: { current },
      reloadEnabled: { previous }, save: { saved = $0 })
    XCTAssertEqual(saved?.daemon, restarted)

    saved = nil
    try await BackendPolicyUpdate.refresh(
      previous: previous, expectedPID: 99, current: { current },
      reloadEnabled: { previous }, save: { saved = $0 })
    XCTAssertNil(saved)
  }

  func testRefreshRefusesChangedPortsOrOwner() async throws {
    let previous = try BackendPolicy(ports: [11434], daemon: original)
    for current in [
      try BackendPolicy(ports: [8080], daemon: restarted),
      try BackendPolicy(
        ports: [11434], daemon: ProcessIdentity(pid: 84, uid: 502, pidVersion: 8)),
    ] {
      var saved = false
      do {
        try await BackendPolicyUpdate.refresh(
          previous: previous, expectedPID: restarted.pid, current: { current },
          reloadEnabled: { previous }, save: { _ in saved = true })
        XCTFail("Refresh changed the approved scope")
      } catch {}
      XCTAssertFalse(saved)
    }
  }
}
