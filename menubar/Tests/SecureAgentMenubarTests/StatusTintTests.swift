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

    func testStatusIconRendersPurpleShieldWithWhiteCheck() throws {
        let purple = NSColor(srgbRed: 0.302, green: 0.222, blue: 0.818, alpha: 1)
        let image = try XCTUnwrap(AppDelegate.statusIcon("checkmark.shield.fill", foreground: purple))
        XCTAssertFalse(image.isTemplate)
        XCTAssertTrue(image.representations.contains { $0 is NSBitmapImageRep },
                      "The status bar must receive colored pixels, not a symbol it can template")

        let bitmap = try XCTUnwrap(NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: 72, pixelsHigh: 72,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
            isPlanar: false, colorSpaceName: .deviceRGB,
            bytesPerRow: 0, bitsPerPixel: 0
        ))
        let context = try XCTUnwrap(NSGraphicsContext(bitmapImageRep: bitmap))
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        image.draw(in: NSRect(x: 0, y: 0, width: 72, height: 72))
        context.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()

        var hasPurple = false
        var hasWhite = false
        for y in 0..<72 {
            for x in 0..<72 {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.sRGB),
                      color.alphaComponent > 0.9 else { continue }
                hasPurple = hasPurple || (color.blueComponent > 0.7 && color.redComponent < 0.5)
                hasWhite = hasWhite || (color.redComponent > 0.9 && color.greenComponent > 0.9 && color.blueComponent > 0.9)
            }
        }
        XCTAssertTrue(hasPurple, "The shield must retain its brand color")
        XCTAssertTrue(hasWhite, "The check must remain white")
    }

    func testLaunchIconHasVisiblePixelsInBothAppearances() throws {
        for name: NSAppearance.Name in [.aqua, .darkAqua] {
            let appearance = try XCTUnwrap(NSAppearance(named: name))
            var image: NSImage?
            appearance.performAsCurrentDrawingAppearance {
                image = AppDelegate.statusIcon("checkmark.shield.fill")
            }
            let bitmap = try XCTUnwrap(image?.representations.compactMap { $0 as? NSBitmapImageRep }.first)
            var opaquePixels = 0
            for y in 0..<bitmap.pixelsHigh {
                for x in 0..<bitmap.pixelsWide where (bitmap.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.9 {
                    opaquePixels += 1
                }
            }
            XCTAssertGreaterThan(opaquePixels, 100, "The launch icon must be visible in \(name.rawValue)")
        }
    }

    func testStatusItemIsPresentBeforeDaemonStartup() throws {
        let delegate = AppDelegate()
        let item = try XCTUnwrap(delegate.makeStatusItem())
        defer { NSStatusBar.system.removeStatusItem(item) }
        let button = try XCTUnwrap(item.button)
        XCTAssertNotNil(button.image)
        XCTAssertFalse(try XCTUnwrap(button.image).isTemplate)
        XCTAssertNotNil(button.action)
    }

}
