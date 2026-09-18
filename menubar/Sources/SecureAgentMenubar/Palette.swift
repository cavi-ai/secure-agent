import SwiftUI

/// App palette, shared by every surface (popover, sheets, settings). Kept in
/// one place so a tint tweak doesn't need five edits. Both Color and
/// ShapeStyle surfaces are covered so `.brand` works in either inference
/// position (foregroundStyle/tint/foregroundStyle(Color)).
extension Color {
    static let brand = Color(.sRGB, red: 0.52, green: 0.44, blue: 0.97, opacity: 1)
    static let ok = Color(.sRGB, red: 0.30, green: 0.80, blue: 0.55, opacity: 1)
    static let warn = Color(.sRGB, red: 0.96, green: 0.62, blue: 0.20, opacity: 1)
    static let bad = Color(.sRGB, red: 0.92, green: 0.35, blue: 0.45, opacity: 1)
    /// The dim-but-visible text tier between .tertiary and .secondary.
    static let tertiaryText = Color(white: 0.62)
}

extension ShapeStyle where Self == Color {
    static var brand: Color { .brand }
    static var ok: Color { .ok }
    static var warn: Color { .warn }
    static var bad: Color { .bad }
}
