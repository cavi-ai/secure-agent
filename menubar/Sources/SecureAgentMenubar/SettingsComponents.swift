import SwiftUI

/// A white symbol on a tinted rounded square: the sidebar and page-header
/// icon of each Settings page.
struct SettingsIconTile: View {
    let symbol: String
    let tint: Color
    var size: CGFloat = 20

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: size * 0.52, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(
                RoundedRectangle(cornerRadius: size * 0.24, style: .continuous)
                    .fill(tint.gradient)
            )
            .accessibilityHidden(true)
    }
}

/// Page title block above a Settings page's form.
struct SettingsPageHeader: View {
    let tab: SettingsTab

    var body: some View {
        HStack(spacing: 12) {
            SettingsIconTile(symbol: tab.symbol, tint: tab.tint, size: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(tab.title).font(.title2.weight(.semibold))
                Text(tab.summary).font(.subheadline).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
}

/// The state of a page in one line, with optional actions on the right.
struct SettingsStatusCard<Actions: View>: View {
    let symbol: String
    let tint: Color
    let headline: String
    let detail: String
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 34, height: 34)
                .background(Circle().fill(tint.opacity(0.14)))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(headline).font(.headline)
                Text(detail)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            actions
        }
        .padding(.vertical, 4)
    }
}

extension SettingsStatusCard where Actions == EmptyView {
    init(symbol: String, tint: Color, headline: String, detail: String) {
        self.init(symbol: symbol, tint: tint, headline: headline, detail: detail) { EmptyView() }
    }
}

/// Leading symbol of a settings row.
struct SettingsRowIcon: View {
    let symbol: String
    var tint: Color = .secondary

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(tint)
            .frame(width: 22)
            .accessibilityHidden(true)
    }
}

/// A row-sized empty state: what is missing and how one gets created.
struct SettingsEmptyRow: View {
    let symbol: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 10) {
            SettingsRowIcon(symbol: symbol)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).foregroundStyle(.secondary)
                Text(detail)
                    .font(.caption).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
    }
}

/// A non-zero count, as a small tinted capsule.
struct CountBadge: View {
    let text: String
    let tint: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(tint)
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .background(Capsule().fill(tint.opacity(0.14)))
    }
}

/// Display names and grouping for egress firewall rules. Rule ids stay the
/// identity (they are the config keys); titles cover the shipped defaults and
/// fall back to the id for user-added patterns and registered secrets.
enum FirewallRuleCatalog {
    static let titles: [String: String] = [
        "anthropic-key": "Anthropic API key",
        "openai-key": "OpenAI API key",
        "openai-project": "OpenAI project key",
        "github-pat": "GitHub token",
        "github-fine-grained": "GitHub fine-grained token",
        "gitlab-pat": "GitLab token",
        "aws-key": "AWS access key",
        "google-key": "Google API key",
        "stripe-key": "Stripe secret key",
        "stripe-restricted": "Stripe restricted key",
        "stripe-webhook": "Stripe webhook secret",
        "slack-token": "Slack token",
        "private-key": "Private key (PEM)",
        "jwt": "JSON Web Token",
        "bearer-token": "Bearer token",
        "npm-token": "npm token",
        "pypi-token": "PyPI token",
        "sendgrid-key": "SendGrid key",
        "twilio-sid": "Twilio account SID",
        "digitalocean-token": "DigitalOcean token",
        "doppler-token": "Doppler token",
        "db-conn-string": "Database URL with password",
        "entropy": "High-entropy string",
    ]

    static func title(for id: String) -> String { titles[id] ?? id }

    struct Group: Identifiable {
        let id: String
        let title: String
        let rules: [AppState.FirewallRuleRow]
    }

    struct BulkAction: Equatable {
        let title: String
        let mode: String
        let rules: [String]
    }

    /// A group's one-click action: block the rules still monitoring, or
    /// monitor all once every rule blocks. Heuristic rules guess, so blocking
    /// them all at once is never one click.
    static func bulkAction(for group: Group) -> BulkAction? {
        guard group.id != "unknown" else { return nil }
        let monitoring = group.rules.filter { ($0.stat.mode ?? "monitor") != "block" }
        if monitoring.isEmpty {
            return BulkAction(title: "Monitor all", mode: "monitor", rules: group.rules.map(\.id))
        }
        return BulkAction(title: "Block all", mode: "block", rules: monitoring.map(\.id))
    }

    /// Secret types in display order, with their section titles.
    static let typeOrder: [(type: String, title: String)] = [
        ("vendor-key", "API keys and tokens"),
        ("cloud-key", "Cloud and infrastructure"),
        ("private-key", "Private keys"),
        ("env-value", "Registered secrets"),
        ("unknown", "Heuristics"),
    ]

    /// Rules grouped by secret type in `typeOrder`; any other type follows
    /// under "Other rules". Inside a group, rules sort by title.
    static func groups(_ rules: [AppState.FirewallRuleRow]) -> [Group] {
        let sorted = rules.sorted {
            title(for: $0.id).localizedCaseInsensitiveCompare(title(for: $1.id)) == .orderedAscending
        }
        let known = Set(typeOrder.map(\.type))
        var result = typeOrder.compactMap { entry -> Group? in
            let members = sorted.filter { ($0.stat.type ?? "unknown") == entry.type }
            return members.isEmpty ? nil : Group(id: entry.type, title: entry.title, rules: members)
        }
        let other = sorted.filter { !known.contains($0.stat.type ?? "unknown") }
        if !other.isEmpty { result.append(Group(id: "other", title: "Other rules", rules: other)) }
        return result
    }
}
