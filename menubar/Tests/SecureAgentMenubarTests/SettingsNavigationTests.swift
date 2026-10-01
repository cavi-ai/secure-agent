import AppKit
import XCTest
@testable import SecureAgentMenubar

final class SettingsNavigationTests: XCTestCase {
    func testEverySidebarSymbolExists() {
        for tab in SettingsTab.allCases {
            XCTAssertNotNil(NSImage(systemSymbolName: tab.symbol, accessibilityDescription: tab.title), tab.title)
        }
    }

    func testLocalAIUsesAppName() {
        XCTAssertEqual(SettingsTab.secureAgent.title, "Secure Agent")
    }
}
