import Foundation
import ModelFilterCompat
import ModelFilterCore
import Network
import NetworkExtension

final class FilterDataProvider: NEFilterDataProvider, @unchecked Sendable {
  private let lock = NSLock()
  private var policy: BackendPolicy?

  override func startFilter(completionHandler: @escaping @Sendable (Error?) -> Void) {
    do {
      guard let data = filterConfiguration.vendorConfiguration?["policy"] as? Data else {
        throw FilterError.invalidPolicy
      }
      let policy = try JSONDecoder().decode(BackendPolicy.self, from: data)
      var rules: [NEFilterRule] = []
      for port in policy.ports {
        for (host, prefix) in [("127.0.0.0", 8), ("::1", 128), ("::ffff:127.0.0.0", 104)] {
          let rule: NENetworkRule
          if #available(macOS 15.0, *) {
            rule = NENetworkRule(
              remoteNetworkEndpoint: .hostPort(host: .init(host), port: .init(rawValue: port)!),
              remotePrefix: prefix, localNetworkEndpoint: nil, localPrefix: 0, protocol: .TCP,
              direction: .outbound)
          } else {
            rule = SAFilterLoopbackRule(host, port, UInt(prefix))
          }
          rules.append(NEFilterRule(networkRule: rule, action: .filterData))
        }
      }
      lock.withLock { self.policy = policy }
      apply(
        NEFilterSettings(rules: rules, defaultAction: .allow)
      ) { [weak self] error in
        if error != nil { self?.lock.withLock { self?.policy = nil } }
        completionHandler(error)
      }
    } catch { completionHandler(error) }
  }

  override func stopFilter(
    with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void
  ) {
    lock.withLock { policy = nil }
    completionHandler()
  }

  override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
    guard let policy = lock.withLock({ policy }), let socket = flow as? NEFilterSocketFlow,
      socket.direction == .outbound, socket.socketProtocol == IPPROTO_TCP
    else { return .drop() }
    let host: String?
    let port: UInt16?
    if #available(macOS 15.0, *) {
      if case .hostPort(let address, let number) = socket.remoteFlowEndpoint {
        host = "\(address)"
        port = number.rawValue
      } else {
        host = nil
        port = nil
      }
    } else {
      host = SAFilterRemoteHost(socket)
      let number = SAFilterRemotePort(socket)
      port = number > 0 ? number : nil
    }
    let process = socket.sourceProcessAuditToken.flatMap { try? ProcessIdentity(auditToken: $0) }
    return policy.allows(host: host, port: port, process: process) ? .allow() : .drop()
  }
}
