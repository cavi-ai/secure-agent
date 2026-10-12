import AppKit
import Darwin

/// Exercise the bundled, hosted status-item path without starting monitoring.
@main
@MainActor
struct StatusItemRenderingRegression {
    static func main() {
        if CommandLine.arguments.count > 1 {
            for path in CommandLine.arguments.dropFirst() {
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let bitmap = NSBitmapImageRep(data: data) else {
                    fputs("Cannot read menu-bar capture\n", stderr)
                    exit(1)
                }
                // A solid magenta marker makes actual rendering distinguishable
                // from the off-screen proxy window AppKit reports as visible.
                var pixels = 0
                for y in 0..<min(100, bitmap.pixelsHigh) {
                    for x in 0..<bitmap.pixelsWide {
                        guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { continue }
                        if color.redComponent > 0.85 && color.greenComponent < 0.4 && color.blueComponent > 0.85 {
                            pixels += 1
                        }
                    }
                }
                if pixels >= 100 {
                    print("Status item rendered in the captured menu bar")
                    return
                }
            }
            fputs("Status item did not render in any captured menu bar\n", stderr)
            exit(1)
        }

        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 240, height: 80),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.title = "Menu bar rendering regression"
        window.center()
        let owner = StatusItemController {
            let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 36, pixelsHigh: 36,
                                          bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                          isPlanar: false, colorSpaceName: .deviceRGB,
                                          bytesPerRow: 0, bitsPerPixel: 0)!
            for y in 0..<36 {
                for x in 0..<36 {
                    let pixel = bitmap.bitmapData! + y * bitmap.bytesPerRow + x * 4
                    pixel[0] = 255
                    pixel[1] = 0
                    pixel[2] = 255
                    pixel[3] = 255
                }
            }
            let image = NSImage(size: NSSize(width: 18, height: 18))
            image.addRepresentation(bitmap)
            image.isTemplate = false
            item.button?.image = image
            return item
        }
        Task { @MainActor in
            window.makeKeyAndOrderFront(nil)
            app.activate(ignoringOtherApps: true)
            guard owner.start() else { exit(1) }
            try? await Task.sleep(for: .seconds(1))
            print("CAPTURE \(NSScreen.screens.count)")
            fflush(stdout)
            try? await Task.sleep(for: .seconds(8))
            owner.stop()
            app.terminate(nil)
        }
        app.run()
    }
}
