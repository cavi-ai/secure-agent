import Foundation

/// Reads and edits the daemon's config.yaml one line at a time. config.yaml is
/// user-owned: every byte outside the edited line is kept, and documents the
/// editor cannot reason about (flow style, document markers, duplicated or
/// quoted headers, duplicated keys, tabs in a block, nested values under a
/// scalar) are refused instead of rewritten. A nil block addresses top-level keys.
struct ConfigDocument: Equatable, Sendable {
    enum Error: LocalizedError, Equatable {
        case unsupported(String)
        var errorDescription: String? {
            switch self {
            case .unsupported(let scope):
                "config.yaml could not be read safely (\(scope)). Use one block per section with scalar settings and plain lists, without flow style or document markers. The file was left unchanged."
            }
        }
    }

    struct Scalar: Equatable, Sendable {
        let text: String
        let isQuoted: Bool
    }

    let text: String

    init(_ text: String) { self.text = text }

    // JSON strings are valid YAML scalars and escape quotes and control characters.
    static func quoted(_ text: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        return String(decoding: try! encoder.encode(text), as: UTF8.self)
    }

    // MARK: Reading

    func hasBlock(_ block: String) throws -> Bool {
        try Self.locate(nil, in: block, try Self.lines(text, scope: block)) != nil
    }

    func scalar(_ key: String, in block: String? = nil) throws -> Scalar? {
        let scope = block ?? key
        let lines = try Self.lines(text, scope: scope)
        guard let field = try Self.locate(key, in: block, lines)?.field else { return nil }
        guard field.count == 1 else { throw Error.unsupported(scope) }
        return try Self.parse(Self.value(lines[field.lowerBound], key: key), scope: scope)
    }

    /// True only for an explicit `true`; absent or unreadable settings are false.
    func flag(_ key: String, in block: String? = nil) -> Bool {
        (try? scalar(key, in: block))?.text == "true"
    }

    func list(_ key: String, in block: String? = nil) throws -> [String]? {
        let scope = block ?? key
        let lines = try Self.lines(text, scope: scope)
        guard let field = try Self.locate(key, in: block, lines)?.field else { return nil }
        return try Self.readList(lines, field, key: key, scope: scope).items
    }

    // MARK: Editing

    /// `value` is rendered YAML. An existing line is rewritten (a trailing
    /// comment on it goes); a missing key is inserted at the top of its block,
    /// or appended with `comment` above it at the top level; a missing block is
    /// appended.
    func setting(_ key: String, raw value: String, in block: String? = nil, introducedBy comment: String? = nil) throws -> ConfigDocument {
        let scope = block ?? key
        var lines = try Self.lines(text, scope: scope)
        let place = try Self.place(key, in: block, &lines)
        let entry = key + ": " + value
        if let field = place.field {
            guard field.count == 1 else { throw Error.unsupported(scope) }
            lines[field.lowerBound] = Self.spaces(Self.indentation(lines[field.lowerBound])) + entry        } else if let body = place.body {
            lines.insert(Self.spaces(place.indent) + entry, at: body.lowerBound)
        } else {
            if lines.last == "" { lines.removeLast() }
            lines += (comment?.components(separatedBy: "\n") ?? []) + [entry, ""]
        }
        return ConfigDocument(lines.joined(separator: "\n"))
    }

    func setting(_ key: String, to flag: Bool, in block: String? = nil, introducedBy comment: String? = nil) throws -> ConfigDocument {
        try setting(key, raw: flag ? "true" : "false", in: block, introducedBy: comment)
    }

    /// An existing list keeps its form (`[a, b]` or `- a` items) and position; a
    /// new one is written as items, or `[]` when empty. A new top-level list goes
    /// after the leading comment lines.
    func settingList(_ key: String, to values: [String], in block: String? = nil) throws -> ConfigDocument {
        let scope = block ?? key
        var lines = try Self.lines(text, scope: scope)
        let place = try Self.place(key, in: block, &lines)
        if let field = place.field {
            let existing = try Self.readList(lines, field, key: key, scope: scope)
            let indent = Self.indentation(lines[field.lowerBound])
            lines.replaceSubrange(field, with: Self.render(key, values, indent: indent,
                                                           itemIndent: existing.itemIndent ?? indent + 2, inline: existing.isInline))
        } else if let body = place.body {
            lines.insert(contentsOf: Self.render(key, values, indent: place.indent, itemIndent: place.indent + 2, inline: false),
                         at: body.lowerBound)
        } else {
            let top = lines.firstIndex { Self.isContent($0) } ?? lines.count
            lines.insert(contentsOf: Self.render(key, values, indent: 0, itemIndent: 2, inline: false), at: top)
        }
        return ConfigDocument(lines.joined(separator: "\n"))
    }

    /// Drops a scalar or list key; a key that is not there leaves the text as it is.
    func removing(_ key: String, in block: String? = nil) throws -> ConfigDocument {
        let scope = block ?? key
        var lines = try Self.lines(text, scope: scope)
        guard let field = try Self.locate(key, in: block, lines)?.field else { return self }
        guard lines[(field.lowerBound + 1)..<field.upperBound].allSatisfy({
            !Self.isContent($0) || $0.trimmingCharacters(in: .whitespaces).hasPrefix("-")
        }) else { throw Error.unsupported(scope) }
        lines.removeSubrange(field)
        return ConfigDocument(lines.joined(separator: "\n"))
    }

    // MARK: Structure

    private struct Place {
        /// The lines under a block header; nil for top-level keys.
        var body: Range<Int>?
        /// Indentation of the block's own keys.
        var indent: Int
        /// The key's line through its list items or nested lines.
        var field: Range<Int>?
    }

    private struct ListValue {
        var items: [String]
        var isInline: Bool
        var itemIndent: Int?
    }

    private static func lines(_ text: String, scope: String) throws -> [String] {
        let lines = text.components(separatedBy: "\n")
        guard !lines.contains(where: { $0.hasPrefix("{") || $0.hasPrefix("---") || $0.hasPrefix("...") }) else {
            throw Error.unsupported(scope)
        }
        return lines
    }

    /// The key's place, appending its block first when the block is missing.
    private static func place(_ key: String, in block: String?, _ lines: inout [String]) throws -> Place {
        if let place = try locate(key, in: block, lines) { return place }
        if lines.last == "" { lines.removeLast() }
        lines += [block! + ":", ""]
        return try locate(key, in: block, lines)!
    }

    /// Nil when `block` is missing. A nil `key` addresses the block header alone.
    private static func locate(_ key: String?, in block: String?, _ lines: [String]) throws -> Place? {
        let scope = block ?? key ?? ""
        guard let block else {
            guard let key, let start = try header(key, lines, scope: scope) else { return Place(body: nil, indent: 0, field: nil) }
            let field = extent(of: start, indent: 0, upTo: lines.count, lines)
            guard !lines[field].contains(where: { $0.hasPrefix("\t") }) else { throw Error.unsupported(scope) }
            return Place(body: nil, indent: 0, field: field)
        }
        guard let start = try header(block, lines, scope: scope) else { return nil }
        let suffix = lines[start].dropFirst(block.count + 1).trimmingCharacters(in: .whitespaces)
        guard suffix.isEmpty || suffix.hasPrefix("#") else { throw Error.unsupported(scope) }
        let end = lines.indices.dropFirst(start + 1).first {
            !lines[$0].hasPrefix(" ") && isContent(lines[$0])
        } ?? lines.count
        let body = (start + 1)..<end
        guard !lines[body].contains(where: { $0.hasPrefix("\t") }) else { throw Error.unsupported(scope) }
        let meaningful = body.filter { isContent(lines[$0]) }
        let indent = meaningful.map { indentation(lines[$0]) }.min() ?? 2
        guard let key else { return Place(body: body, indent: indent, field: nil) }
        let matches = meaningful.filter {
            indentation(lines[$0]) == indent && lines[$0].trimmingCharacters(in: .whitespaces).hasPrefix(key + ":")
        }
        guard matches.count <= 1 else { throw Error.unsupported(scope) }
        return Place(body: body, indent: indent, field: matches.first.map { extent(of: $0, indent: indent, upTo: end, lines) })
    }

    /// The single unindented `name:` line; a quoted, spaced or repeated header is refused.
    private static func header(_ name: String, _ lines: [String], scope: String) throws -> Int? {
        let pattern = #"^["']?"# + NSRegularExpression.escapedPattern(for: name) + #"["']?\s*:"#
        let starts = lines.indices.filter { lines[$0].range(of: pattern, options: .regularExpression) != nil }
        guard starts.count <= 1 else { throw Error.unsupported(scope) }
        guard let start = starts.first else { return nil }
        guard lines[start].hasPrefix(name + ":") else { throw Error.unsupported(scope) }
        return start
    }

    /// YAML permits list items at the key's own indentation.
    private static func extent(of start: Int, indent: Int, upTo upper: Int, _ lines: [String]) -> Range<Int> {
        var end = start + 1
        var cursor = end
        while cursor < upper {
            let line = lines[cursor]
            if !isContent(line) { cursor += 1; continue }
            guard indentation(line) > indent ||
                    (indentation(line) == indent && line.trimmingCharacters(in: .whitespaces).hasPrefix("-")) else { break }
            end = cursor + 1
            cursor += 1
        }
        return start..<end
    }

    private static func readList(_ lines: [String], _ field: Range<Int>, key: String, scope: String) throws -> ListValue {
        let inline = comment(stripped: value(lines[field.lowerBound], key: key))
        let rest = lines[(field.lowerBound + 1)..<field.upperBound]
        if inline.hasPrefix("["), inline.hasSuffix("]"), rest.isEmpty {
            let body = inline.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
            let items = body.isEmpty ? [] : try body.components(separatedBy: ",").map {
                try parse($0.trimmingCharacters(in: .whitespaces), scope: scope).text
            }
            return ListValue(items: items, isInline: true, itemIndent: nil)
        }
        guard inline.isEmpty else { throw Error.unsupported(scope) }
        let entries = rest.filter { isContent($0) }
        let items = try entries.map { line -> String in
            let entry = line.trimmingCharacters(in: .whitespaces)
            guard entry.hasPrefix("-") else { throw Error.unsupported(scope) }
            return try parse(String(entry.dropFirst()).trimmingCharacters(in: .whitespaces), scope: scope).text
        }
        return ListValue(items: items, isInline: false, itemIndent: entries.first.map(indentation))
    }

    private static func render(_ key: String, _ values: [String], indent: Int, itemIndent: Int, inline: Bool) -> [String] {
        if inline || values.isEmpty {
            return [spaces(indent) + key + ": [" + values.map(quoted).joined(separator: ", ") + "]"]
        }
        return [spaces(indent) + key + ":"] + values.map { spaces(itemIndent) + "- " + (isPlain($0) ? $0 : quoted($0)) }
    }

    // MARK: Scalars

    private static func parse(_ raw: String, scope: String) throws -> Scalar {
        if raw.isEmpty || raw.hasPrefix("#") { return Scalar(text: "", isQuoted: false) }
        if raw.hasPrefix("\"") {
            // Find the closing unescaped quote; preserve # inside quoted strings.
            var escaped = false
            for j in raw.indices.dropFirst() {
                let c = raw[j]
                if c == "\"" && !escaped {
                    let tail = raw[raw.index(after: j)...].trimmingCharacters(in: .whitespaces)
                    guard tail.isEmpty || tail.hasPrefix("#"),
                          let s = try? JSONDecoder().decode(String.self, from: Data(raw[...j].utf8)) else { throw Error.unsupported(scope) }
                    return Scalar(text: s, isQuoted: true)
                }
                escaped = c == "\\" && !escaped
            }
            throw Error.unsupported(scope)
        }
        if raw.hasPrefix("'") {
            let regex = try NSRegularExpression(pattern: #"^'((?:[^']|'')*)'\s*(?:#.*)?$"#)
            guard let match = regex.firstMatch(in: raw, range: NSRange(raw.startIndex..., in: raw)),
                  let range = Range(match.range(at: 1), in: raw) else { throw Error.unsupported(scope) }
            return Scalar(text: String(raw[range]).replacingOccurrences(of: "''", with: "'"), isQuoted: true)
        }
        let plain = comment(stripped: raw)
        guard !plain.isEmpty, !["[", "{", "|", ">", "*", "&", "!"].contains(where: { plain.hasPrefix($0) }) else {
            throw Error.unsupported(scope)
        }
        return Scalar(text: plain, isQuoted: false)
    }

    /// Whatever follows `key:` on the line.
    private static func value(_ line: String, key: String) -> String {
        line.trimmingCharacters(in: .whitespaces).dropFirst(key.count + 1).trimmingCharacters(in: .whitespaces)
    }

    private static func comment(stripped text: String) -> String {
        String(text.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]).trimmingCharacters(in: .whitespaces)
    }

    private static func isPlain(_ text: String) -> Bool {
        text.range(of: #"^[A-Za-z][A-Za-z0-9._/-]*$"#, options: .regularExpression) != nil
            && !["true", "false", "null", "yes", "no", "on", "off"].contains(text.lowercased())
    }

    private static func isContent(_ line: String) -> Bool {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return !trimmed.isEmpty && !trimmed.hasPrefix("#")
    }

    private static func indentation(_ line: String) -> Int { line.prefix { $0 == " " }.count }
    private static func spaces(_ count: Int) -> String { String(repeating: " ", count: count) }
}

/// config.yaml on disk: a missing file reads as an empty document, writes are atomic.
struct ConfigStore: Sendable {
    let path: String

    init(home: String) { path = "\(home)/.config/secure-agent/config.yaml" }

    func document() throws -> ConfigDocument {
        guard FileManager.default.fileExists(atPath: path) else { return ConfigDocument("") }
        return ConfigDocument(try String(contentsOfFile: path, encoding: .utf8))
    }

    func update(_ transform: (String) throws -> String) throws {
        let updated = try transform(document().text)
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try updated.write(toFile: path, atomically: true, encoding: .utf8)
    }
}
