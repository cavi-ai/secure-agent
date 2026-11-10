import Foundation
import LocalAuthentication
import ModelFilterCore
import NetworkExtension
import SystemExtensions

/// Owner-invoked setup. Merely building or launching Secure Agent does not
/// install a system extension or enable network filtering.
@MainActor
final class ModelFilterCommand: NSObject, OSSystemExtensionRequestDelegate {
  static let identifier = "com.cavi-ai.secure-agent.model-filter"
  private var activation: CheckedContinuation<Void, Error>?

  static func run(_ arguments: [String]) -> Never {
    Task { @MainActor in
      do {
        let command = ModelFilterCommand()
        switch arguments {
        case ["status"]:
          guard Bundle.main.object(forInfoDictionaryKey: "ModelFilterIncluded") as? Bool == true
          else {
            print("Model filter is not included in this build.")
            exit(0)
          }
          guard (try? KernelIdentity.signingTeam()) != nil else {
            print("Owner provisioning is required; filtering has not been verified.")
            exit(0)
          }
          let manager = NEFilterManager.shared()
          try await manager.loadFromPreferences()
          let owned =
            manager.providerConfiguration?.filterDataProviderBundleIdentifier == identifier
          print(
            owned && manager.isEnabled
              ? "Model filter is configured. Live coverage requires verification."
              : "Model filter is disabled.")
        case ["enable"]:
          guard Bundle.main.object(forInfoDictionaryKey: "ModelFilterIncluded") as? Bool == true
          else { throw FilterError.signingRequired }
          _ = try KernelIdentity.signingTeam()
          let policy = try await currentPolicy()
          try await authenticateOwner(
            reason:
              "Protect local model backend ports \(policy.ports.map(String.init).joined(separator:", "))."
          )
          try await command.activate()
          let manager = NEFilterManager.shared()
          try await manager.loadFromPreferences()
          try await BackendPolicyUpdate.afterOwnerApproval(
            approved: policy, current: currentPolicy,
            save: { try await configure(manager, policy: $0) })
          print(
            "Model filter configured. Verify direct IPv4/IPv6 refusal and gateway access before relying on coverage."
          )
        case ["disable"]:
          let manager = NEFilterManager.shared()
          try await manager.loadFromPreferences()
          guard manager.providerConfiguration?.filterDataProviderBundleIdentifier == identifier
          else { throw FilterError.unavailable("No Secure Agent model filter is configured.") }
          try await authenticateOwner(reason: "Disable Secure Agent's model backend filter.")
          manager.isEnabled = false
          try await manager.saveToPreferences()
          print("Model filter disabled. Direct backend access is no longer filtered.")
        default:
          throw FilterError.unavailable("Usage: SecureAgent --model-filter status|enable|disable")
        }
        exit(0)
      } catch {
        FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
        exit(1)
      }
    }
    RunLoop.main.run()
    exit(1)
  }

  static func refreshIfEnabled(expectedPID: Int32) async {
    guard Bundle.main.object(forInfoDictionaryKey: "ModelFilterIncluded") as? Bool == true else {
      return
    }
    do {
      let manager = NEFilterManager.shared()
      try await manager.loadFromPreferences()
      guard manager.isEnabled,
        manager.providerConfiguration?.filterDataProviderBundleIdentifier == identifier
      else { return }
      guard let data = manager.providerConfiguration?.vendorConfiguration?["policy"] as? Data else {
        throw FilterError.invalidPolicy
      }
      let previous = try JSONDecoder().decode(BackendPolicy.self, from: data)
      for attempt in 0..<15 {
        do {
          try await BackendPolicyUpdate.refresh(
            previous: previous, expectedPID: expectedPID, current: currentPolicy,
            reloadEnabled: {
              try await manager.loadFromPreferences()
              guard manager.isEnabled,
                manager.providerConfiguration?.filterDataProviderBundleIdentifier == identifier,
                let data = manager.providerConfiguration?.vendorConfiguration?["policy"] as? Data
              else { return nil }
              return try JSONDecoder().decode(BackendPolicy.self, from: data)
            }, save: { try await configure(manager, policy: $0) })
          return
        } catch {
          if attempt == 14 { throw error }
          try await Task.sleep(for: .seconds(1))
        }
      }
    } catch {
      NSLog(
        "[secure-agent] model filter could not bind the new daemon instance: %@",
        error.localizedDescription)
    }
  }

  private struct Activity: Decodable {
    struct Gateway: Decodable {
      let upstream: String
      let state: String
    }
    let gateways: [Gateway]
  }

  private static func authenticateOwner(reason: String) async throws {
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 0
    guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
    else {
      throw FilterError.unavailable("Owner authentication was not completed.")
    }
  }

  private static func currentPolicy() async throws -> BackendPolicy {
    let client = DaemonClient()
    let daemon = try KernelIdentity.daemon(socketPath: client.socketPath)
    let activity: Activity = try await client.getDecodable("/local-inference")
    guard !activity.gateways.isEmpty, activity.gateways.allSatisfy({ $0.state == "listening" })
    else {
      throw FilterError.unavailable(
        "Configure and start the inference gateways before enabling backend filtering.")
    }
    var ports = Set<UInt16>()
    for gateway in activity.gateways {
      guard let url = URLComponents(string: gateway.upstream), url.scheme == "http",
        let host = url.host,
        host == "localhost"
          || BackendPolicy.isLoopback(host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))),
        let number = url.port, let port = UInt16(exactly: number), port > 0,
        url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
        url.path.isEmpty || url.path == "/"
      else { throw FilterError.invalidPolicy }
      ports.insert(port)
    }
    guard try KernelIdentity.daemon(socketPath: client.socketPath) == daemon else {
      throw FilterError.identityUnavailable
    }
    return try BackendPolicy(ports: ports.sorted(), daemon: daemon)
  }

  private static func configure(_ manager: NEFilterManager, policy: BackendPolicy) async throws {
    if manager.isEnabled,
      let existing = manager.providerConfiguration?.filterDataProviderBundleIdentifier,
      existing != identifier
    {
      throw FilterError.unavailable("An existing filter configuration will not be replaced.")
    }
    let configuration = NEFilterProviderConfiguration()
    configuration.filterSockets = true
    configuration.filterDataProviderBundleIdentifier = identifier
    configuration.vendorConfiguration = ["policy": try JSONEncoder().encode(policy)]
    manager.providerConfiguration = configuration
    manager.localizedDescription = "Secure Agent model backends"
    manager.isEnabled = true
    try await manager.saveToPreferences()
  }

  private func activate() async throws {
    try await withCheckedThrowingContinuation { continuation in
      activation = continuation
      let request = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: Self.identifier, queue: .main)
      request.delegate = self
      OSSystemExtensionManager.shared.submitRequest(request)
    }
  }
  nonisolated func request(
    _ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result
  ) {
    Task { @MainActor in
      let pending = activation
      activation = nil
      if result == .completed {
        pending?.resume()
      } else {
        pending?.resume(
          throwing: FilterError.unavailable(
            "Restart macOS to finish extension installation, then rerun enable."))
      }
    }
  }
  nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
    Task { @MainActor in
      let pending = activation
      activation = nil
      pending?.resume(throwing: error)
    }
  }
  nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    print("Approve the Secure Agent model filter in System Settings to continue.")
  }
  nonisolated func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension replacement: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction { .replace }
}
