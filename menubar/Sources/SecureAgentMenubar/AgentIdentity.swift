import SwiftUI

/// Per-harness-agent identity: a brand mark in the vendor's color so
/// "claude", "cursor", and "codex" rows are visually distinct at a glance.
///
/// Known harnesses get a drawn brand glyph (vector, no bundled assets —
/// crisp at every size, works in SwiftPM without an xcassets catalog).
/// Unknown harnesses fall back to a deterministic hash-hued monogram.
@MainActor
enum AgentIdentity {
    struct Identity {
        let monogram: String
        let color: Color
        let known: Bool
    }

    private static let brandColors: [String: (hex: UInt32, mono: String)] = [
        "claude": (0xD97757, "✳"), // Anthropic clay-orange, starburst
        "cursor": (0x3D3D3D, "▰"), // Cursor near-black, split square
        "codex": (0x10A37F, "⬡"),  // OpenAI teal-green, knot/hex
        "opencode": (0x7C5CFF, "〈"),
        "antigravity": (0x5B6CFF, "▲"),
        "windsurf": (0x0EA5A0, "≋"),
        "aider": (0xFF6B35, "◉"),
        "gemini": (0x4E8DF5, "✦"),
        "codeium": (0x0E8CD6, "◈"),
        "copilot": (0x24292F, "◍"), // GitHub dark
        "ollama": (0x0F0F0F, "🦙"),
        "lm-studio": (0x1E3A5F, "◧"),
    ]

    static func forAgent(_ name: String) -> Identity {
        let key = name.lowercased()
        for (needle, spec) in brandColors where key.contains(needle) {
            return Identity(
                monogram: spec.mono,
                color: Color(.sRGB,
                             red: Double((spec.hex >> 16) & 0xFF) / 255,
                             green: Double((spec.hex >> 8) & 0xFF) / 255,
                             blue: Double(spec.hex & 0xFF) / 255, opacity: 1),
                known: true)
        }
        var h: UInt32 = 2166136261
        for b in key.utf8 { h = (h ^ UInt32(b)) &* 16777619 }
        return Identity(
            monogram: String(name.prefix(1)).uppercased(),
            color: Color(hue: Double(h % 3600) / 36000.0, saturation: 0.62, brightness: 0.66, opacity: 1),
            known: false)
    }

    /// The tile: tinted background + brand glyph on top (white strokes read
    /// on any brand color, matching how the vendor renders their mark on
    /// tinted chrome).
    static func tile(_ name: String, size: CGFloat = 22, fontSize: CGFloat? = nil) -> some View {
        let key = name.lowercased()
        let id = forAgent(name)
        return ZStack {
            if key.contains("claude") {
                ClaudeMarkGlyph(inset: size * 0.22, color: id.color)
            } else if key.contains("cursor") {
                CursorMark(inset: size * 0.2, color: id.color)
            } else if key.contains("codex") {
                CodexMark(inset: size * 0.2, color: id.color)
            } else if key.contains("opencode") {
                OpenCodeGlyph(inset: size * 0.22, color: id.color)
            } else if key.contains("antigravity") {
                TriangleMark(inset: size * 0.22, color: id.color)
            } else if key.contains("ollama") {
                OllamaMark(inset: size * 0.2, color: id.color)
            } else if key.contains("lm-studio") || key.contains("lmstudio") {
                LmStudioMark(inset: size * 0.2, color: id.color)
                Text(id.monogram)
                    .font(.system(size: (fontSize ?? size * 0.52), weight: .bold, design: .rounded))
                    .foregroundStyle(.white)
            }
        }
        .frame(width: size, height: size)
        .background(key.contains("cursor") ? Color(white: 0.92) : id.color.opacity(0.16))
        .clipShape(RoundedRectangle(cornerRadius: size * 0.24))
        .help(id.known ? name : "\(name) (unknown harness)")
    }
}

// MARK: - drawn brand glyphs

/// Anthropic's starburst: 8 tapered rays from center.
struct ClaudeMarkGlyph: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let c = CGPoint(x: box.width / 2, y: box.height / 2)
            let rOuter = min(box.width, box.height) / 2 - inset * 0.2
            let rInner = rOuter * 0.32
            for i in 0..<8 {
                let angle = Double(i) * .pi / 4
                let a = CGFloat(angle), b = angle + 0.28, b2 = angle - 0.28
                var path = Path()
                path.move(to: CGPoint(x: c.x + rInner * Foundation.cos(angle - 0.16), y: c.y + rInner * sin(angle - 0.16)))
                path.addLine(to: CGPoint(x: c.x + rOuter * cos(a), y: c.y + rOuter * sin(a)))
                path.addLine(to: CGPoint(x: c.x + rOuter * cos(b), y: c.y + rOuter * sin(b)))
                path.addLine(to: CGPoint(x: c.x + rInner * cos(angle + 0.16), y: c.y + rInner * sin(angle + 0.16)))
                ctx.fill(path, with: .color(color))
                _ = b2
            }
        }
    }
}

private func cos(_ a: Double) -> CGFloat { CGFloat(Foundation.cos(a)) }
private func sin(_ a: Double) -> CGFloat { CGFloat(Foundation.sin(a)) }

/// Cursor: a filled rounded square with a vertical split — the cursor logo
/// reads as two interlocking halves.
struct CursorMark: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let s = min(box.width, box.height) - inset
            let x = (box.width - s) / 2, y = (box.height - s) / 2
            let r = s * 0.22
            var left = Path()
            left.addRoundedRect(in: CGRect(x: x, y: y, width: s / 2, height: s),
                                cornerSize: CGSize(width: r, height: r),
                                style: .continuous)
            ctx.fill(left, with: .color(color.opacity(0.9)))
            var right = Path()
            right.addRoundedRect(in: CGRect(x: x + s / 2, y: y + s * 0.12, width: s / 2, height: s * 0.88),
                                 cornerSize: CGSize(width: r, height: r),
                                 style: .continuous)
            ctx.fill(right, with: .color(color.opacity(0.55)))
        }
    }
}

/// OpenAI/Codex: hexagonal knot — a hexagon outline with inner hex offset.
struct CodexMark: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let c = CGPoint(x: box.width / 2, y: box.height / 2)
            let r = min(box.width, box.height) / 2 - inset
            func hexPath(_ radius: CGFloat, rotate: Double) -> Path {
                var p = Path()
                for i in 0...6 {
                    let a = Double(i) * .pi / 3 + rotate
                    let pt = CGPoint(x: c.x + r * cos(a), y: c.y + r * sin(a))
                    if i == 0 { p.move(to: pt) } else { p.addLine(to: pt) }
                }
                return p
            }
            ctx.stroke(hexPath(r, rotate: 0), with: .color(color), lineWidth: r * 0.22)
            ctx.stroke(hexPath(r * 0.45, rotate: .pi / 6), with: .color(color), lineWidth: r * 0.18)
        }
    }
}

/// opencode: angle brackets with a slash.
struct OpenCodeGlyph: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let w = box.width - inset * 2, h = box.height - inset * 2
            let x0 = inset, y0 = inset
            var open = Path()
            open.move(to: CGPoint(x: x0 + w * 0.35, y: y0))
            open.addLine(to: CGPoint(x: x0, y: y0 + h / 2))
            open.addLine(to: CGPoint(x: x0 + w * 0.35, y: y0 + h))
            ctx.stroke(open, with: .color(color), style: StrokeStyle(lineWidth: h * 0.18, lineCap: .round, lineJoin: .round))
            var slash = Path()
            slash.move(to: CGPoint(x: x0 + w * 0.62, y: y0 + h))
            slash.addLine(to: CGPoint(x: x0 + w * 0.88, y: y0))
            ctx.stroke(slash, with: .color(color), style: StrokeStyle(lineWidth: h * 0.18, lineCap: .round))
        }
    }
}

/// Antigravity: ascending triangle with a cut baseline.
struct TriangleMark: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let w = box.width - inset * 2, h = box.height - inset * 2
            let x0 = inset, y0 = inset
            var path = Path()
            path.move(to: CGPoint(x: x0 + w / 2, y: y0))
            path.addLine(to: CGPoint(x: x0 + w, y: y0 + h))
            path.addLine(to: CGPoint(x: x0, y: y0 + h))
            path.closeSubpath()
            ctx.fill(path, with: .color(color))
            // Cut: a notch punched out of the bottom edge (the "gravity break").
            var cut = Path()
            let notchY = y0 + h * 0.72
            cut.move(to: CGPoint(x: x0 + w * 0.38, y: y0 + h))
            cut.addLine(to: CGPoint(x: x0 + w * 0.5, y: notchY))
            cut.addLine(to: CGPoint(x: x0 + w * 0.62, y: y0 + h))
            ctx.blendMode = .clear
            ctx.fill(cut, with: .color(.white))
        }
    }
}

/// Ollama: the llama silhouette abstracted to head + neck.
struct OllamaMark: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let w = box.width - inset * 2, h = box.height - inset * 2
            let x0 = inset, y0 = inset
            var path = Path()
            // Neck up from bottom-left to head.
            path.move(to: CGPoint(x: x0 + w * 0.30, y: y0 + h))
            path.addLine(to: CGPoint(x: x0 + w * 0.30, y: y0 + h * 0.34))
            // Ears/head: rounded top.
            path.addQuadCurve(to: CGPoint(x: x0 + w * 0.62, y: y0 + h * 0.30),
                              control: CGPoint(x: x0 + w * 0.30, y: y0))
            path.addQuadCurve(to: CGPoint(x: x0 + w * 0.82, y: y0 + h * 0.4),
                              control: CGPoint(x: x0 + w * 0.92, y: y0 + h * 0.12))
            path.addLine(to: CGPoint(x: x0 + w * 0.82, y: y0 + h))
            path.closeSubpath()
            ctx.fill(path, with: .color(color))
        }
    }
}

/// LM Studio: stacked layers (the studio "deck").
struct LmStudioMark: View {
    let inset: CGFloat
    let color: Color

    var body: some View {
        Canvas { ctx, box in
            let w = box.width - inset * 2, h = box.height - inset * 2
            let x0 = inset, y0 = inset
            let band = h / 4
            let opacities: [CGFloat] = [1.0, 0.62, 0.3]
            for i in 0..<3 {
                let idx = CGFloat(i)
                let gap = band + h * 0.06
                let y = y0 + idx * gap
                let rect = CGRect(x: x0, y: y, width: w, height: band * 0.72)
                var p = Path()
                p.addRoundedRect(in: rect, cornerSize: CGSize(width: 2, height: 2))
                let op = opacities[i]
                ctx.fill(p, with: .color(color.opacity(op)))
            }
        }
    }
}