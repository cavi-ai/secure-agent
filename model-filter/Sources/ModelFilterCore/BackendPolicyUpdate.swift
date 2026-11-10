import Foundation

/// Policy updates shared by owner setup and daemon restart recovery.
@MainActor
public enum BackendPolicyUpdate {
  public static func afterOwnerApproval(
    approved: BackendPolicy,
    current: () async throws -> BackendPolicy,
    save: (BackendPolicy) async throws -> Void
  ) async throws {
    let policy = try await current()
    try requireSameScope(policy, approved: approved)
    try await save(policy)
  }

  public static func refresh(
    previous: BackendPolicy,
    expectedPID: Int32,
    current: () async throws -> BackendPolicy,
    reloadEnabled: () async throws -> BackendPolicy?,
    save: (BackendPolicy) async throws -> Void
  ) async throws {
    let policy = try await current()
    guard policy.daemon.pid == expectedPID else { return }
    guard let enabled = try await reloadEnabled(), enabled == previous else { return }
    try requireSameScope(policy, approved: previous)
    try await save(policy)
  }

  private static func requireSameScope(_ policy: BackendPolicy, approved: BackendPolicy) throws {
    guard policy.ports == approved.ports, policy.daemon.uid == approved.daemon.uid else {
      throw FilterError.unavailable(
        "Protected backend ports or owner changed; owner setup is required again.")
    }
  }
}
