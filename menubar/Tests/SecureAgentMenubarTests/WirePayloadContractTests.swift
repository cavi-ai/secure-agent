import XCTest
@testable import SecureAgentMenubar

/// Every typed route the menu bar reads must decode as the daemon encodes it:
/// fully populated without leaving a declared field unset, and as a zero value.
final class WirePayloadContractTests: XCTestCase {
    func testMenuBarDecodesDaemonPayloads() {
        assertDecodes("/status", as: StatusResponse.self)
        assertDecodes("/resources", as: ResourceSnapshotModel.self)
        assertDecodes("/doctor", as: DaemonDoctorReportModel.self)
        assertDecodes("/routing/claude", as: RoutingInfo.self)
        assertDecodes("/flags", as: [FlagModel].self)
        assertDecodes("/posture", as: PostureModel.self)
        assertDecodes("/guard/pending", as: [GuardPending].self)
        assertDecodes("/guard/rules", as: [GuardRuleModel].self)
        assertDecodes("/stats/rollup", as: [RollupPointModel].self)
        assertDecodes("/audit", as: [AuditEntryModel].self)
        assertDecodes("/guard/path-allow", as: [GuardPathAllowModel].self)
    }

    func testUnsetOptionalsNamesEveryNilField() {
        let flag = FlagModel(id: "f", rule: "r", severity: 1, ts: "t", pid: 1, agent: "a", evidence: [])
        XCTAssertTrue(unsetOptionals(flag).contains("$.sessionId"))
        XCTAssertFalse(unsetOptionals(flag).contains("$.rule"))
    }

    private func assertDecodes<T: Decodable>(_ path: String, as type: T.Type,
                                             file: StaticString = #filePath, line: UInt = #line) {
        for (variant, payloads) in [("full", WirePayloads.full), ("empty", WirePayloads.empty)] {
            guard let json = payloads[path] else {
                XCTFail("no \(variant) payload for \(path)", file: file, line: line)
                continue
            }
            do {
                let value = try DaemonClient.decodeBody(T.self, path: path, body: Data(json.utf8))
                if variant == "full" {
                    XCTAssertEqual(unsetOptionals(value), [], "\(path): fields the daemon never sends",
                                   file: file, line: line)
                }
            } catch {
                XCTFail("\(path) \(variant): \(error)", file: file, line: line)
            }
        }
    }
}

/// Paths of optional stored properties left nil, walking nested values.
func unsetOptionals(_ value: Any, at path: String = "$") -> [String] {
    let mirror = Mirror(reflecting: value)
    switch mirror.displayStyle {
    case .optional:
        guard let wrapped = mirror.children.first?.value else { return [path] }
        return unsetOptionals(wrapped, at: path)
    case .struct, .class, .enum:
        return mirror.children.flatMap { unsetOptionals($0.value, at: path + "." + ($0.label ?? "_")) }
    case .collection, .set:
        return mirror.children.enumerated().flatMap { unsetOptionals($1.value, at: "\(path)[\($0)]") }
    case .dictionary:
        return mirror.children.flatMap { entry -> [String] in
            let pair = Array(Mirror(reflecting: entry.value).children)
            guard pair.count == 2 else { return [] }
            return unsetOptionals(pair[1].value, at: "\(path)[\(pair[0].value)]")
        }
    default:
        return []
    }
}
