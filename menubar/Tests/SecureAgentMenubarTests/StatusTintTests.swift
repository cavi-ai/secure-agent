import AppKit
import XCTest
@testable import SecureAgentMenubar

/// The status item's tint is the console's `--brand` purple, per menu bar appearance.
@MainActor
final class StatusTintTests: XCTestCase {

    private func rgb(_ name: NSAppearance.Name) throws -> [Double] {
        let appearance = try XCTUnwrap(NSAppearance(named: name))
        var out: [Double] = []
        appearance.performAsCurrentDrawingAppearance {
            let c = AppDelegate.statusTint.usingColorSpace(.sRGB)!
            out = [c.redComponent, c.greenComponent, c.blueComponent].map { (Double($0) * 1000).rounded() / 1000 }
        }
        return out
    }

    func testDarkMenuBarUsesDarkBrand() throws {
        XCTAssertEqual(try rgb(.darkAqua), [0.498, 0.424, 0.976])
    }

    func testLightMenuBarUsesLightBrand() throws {
        XCTAssertEqual(try rgb(.aqua), [0.302, 0.222, 0.818])
    }
}
