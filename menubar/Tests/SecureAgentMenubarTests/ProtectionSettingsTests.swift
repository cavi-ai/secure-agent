import XCTest
@testable import SecureAgentMenubar

final class ProtectionSettingsTests: XCTestCase {
    func testPolicyValidationFailureSurfacesDaemonReason() {
        let response = Data("HTTP/1.1 400 Bad Request\r\nContent-Length: 34\r\n\r\npattern custom: invalid expression\n".utf8)
        XCTAssertThrowsError(try DaemonClient.parseHTTPResponse(response, includePolicyError: true)) {
            XCTAssertEqual($0 as? DaemonClientError, .policyRejected("pattern custom: invalid expression"))
        }
        XCTAssertThrowsError(try DaemonClient.parseHTTPResponse(response)) {
            XCTAssertEqual($0 as? DaemonClientError, .http(400))
        }
    }

    func testGuardEditorPreservesPathAndSensitivityPolicy() throws {
        let rule = try JSONDecoder().decode(GuardPathRule.self, from: Data(#"{"id":"private","paths":["~/private/**","/work/.env"],"mode":"deny","read_sensitive":false}"#.utf8))
        var edit = ProtectionRuleEdit(rule: rule)
        XCTAssertEqual(edit.originalID, "private")
        XCTAssertEqual(edit.mode, "deny")
        XCTAssertFalse(edit.readSensitive)
        edit.expression = " ~/private/keys/** \n\n /work/.env \n"
        XCTAssertEqual(edit.paths, ["~/private/keys/**", "/work/.env"])
    }
}
