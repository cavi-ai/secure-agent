import XCTest
@testable import SecureAgentMenubar

@MainActor
final class PayloadOutcomeTests: XCTestCase {
    func testNativeFindingNamesBoundedRequestOutcomeAfterReview() throws {
        for (control, expected) in [("blocked", "Blocked before forwarding"), ("observed-only", "Observed only; delivery unknown")] {
            let json = #"{"id":"fixture","rule":"proxy-secret-leak","severity":3,"ts":"","pid":0,"agent":"proxy","evidence":[],"acknowledged":true,"explain":{"what":"","disposition":{"state":"acknowledged","text":"Reviewed","why":""},"actions":[],"assessment":{"evidence_basis":["fingerprint-payload"],"risk":"critical","control":"\#(control)","residual_risk":"transmission-attempt","review_state":"reviewed","reason":"An outbound request matched a registered fingerprint.","limits":["Earlier exposure and external credential revocation are not verified."]}}}"#
            let flag = try JSONDecoder().decode(FlagModel.self, from: Data(json.utf8))
            let lines = ConsoleView.HeroModel(icon: "", color: .bad, title: "", subtitle: "", flag: flag, action: nil).flagLines
            XCTAssertTrue(lines.contains { $0.contains(expected) })
            XCTAssertTrue(lines.contains { $0.contains("Reviewed") })
            XCTAssertTrue(lines.contains { $0.contains("Transmission attempt") })
            XCTAssertTrue(lines.contains { $0.contains("not verified") })
        }
    }
}
