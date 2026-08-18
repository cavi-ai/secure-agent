#!/usr/bin/env bash
# Generates packaging/AppIcon.icns: a white shield on a rounded indigo rect,
# rendered via a throwaway Swift script + iconutil. Requires Xcode CLT only.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

cat > "${WORK}/render.swift" <<'SWIFT'
import AppKit

let size: CGFloat = 1024
let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()

let inset: CGFloat = 64
let rect = NSRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
let path = NSBezierPath(roundedRect: rect, xRadius: 200, yRadius: 200)

let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.18, green: 0.24, blue: 0.55, alpha: 1),
    NSColor(calibratedRed: 0.10, green: 0.13, blue: 0.33, alpha: 1),
])!
gradient.draw(in: path, angle: -90)

if let symbol = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(.init(pointSize: 560, weight: .medium)) {
    let tinted = NSImage(size: symbol.size)
    tinted.lockFocus()
    NSColor.white.set()
    let r = NSRect(origin: .zero, size: symbol.size)
    symbol.draw(in: r)
    r.fill(using: .sourceAtop)
    tinted.unlockFocus()
    let dx = (size - symbol.size.width) / 2
    let dy = (size - symbol.size.height) / 2 - 10
    tinted.draw(in: NSRect(x: dx, y: dy, width: symbol.size.width, height: symbol.size.height))
}

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    fatalError("render failed")
}
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
SWIFT

swift "${WORK}/render.swift" "${WORK}/icon_1024.png"

ICONSET="${WORK}/AppIcon.iconset"
mkdir -p "${ICONSET}"
for spec in "16:icon_16x16.png" "32:icon_16x16@2x.png" "32:icon_32x32.png" "64:icon_32x32@2x.png" \
            "128:icon_128x128.png" "256:icon_128x128@2x.png" "256:icon_256x256.png" \
            "512:icon_256x256@2x.png" "512:icon_512x512.png" "1024:icon_512x512@2x.png"; do
  px="${spec%%:*}"; name="${spec##*:}"
  sips -z "${px}" "${px}" "${WORK}/icon_1024.png" --out "${ICONSET}/${name}" >/dev/null
done

iconutil -c icns "${ICONSET}" -o "${REPO_ROOT}/packaging/AppIcon.icns"
echo "==> Wrote ${REPO_ROOT}/packaging/AppIcon.icns"
