import SwiftUI

/// The wizard and Settings share the same persisted runtime controls.
@MainActor
struct AdvisorOptionsView: View {
    @ObservedObject var setup = SetupManager.shared
    @State private var timeout = "60"
    @State private var classifier = false
    @State private var endpoint = "http://127.0.0.1:8009"
    @State private var model = "kev-latest"
    @State private var debug = false
    @State private var note: String?
    @State private var checking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Review timeout (seconds)")
                Spacer()
                TextField("Seconds", text: $timeout).frame(width: 90)
                    .labelsHidden()
                    .accessibilityLabel("Advisor review timeout in seconds")
            }
            Text("Includes model loading and evidence tools. Allow more time for a large local model. Requested plans have at least five minutes.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Toggle("Use a local classifier", isOn: $classifier)
            if classifier {
                TextField("Classifier endpoint", text: $endpoint)
                    .accessibilityLabel("Classifier endpoint")
                TextField("Classifier model", text: $model)
                    .accessibilityLabel("Classifier model")
                Text("Connect to a running Kev-compatible /v1/systemone service. It helps choose evidence to inspect; it cannot clear findings. If unavailable, the advisor continues without its hint.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button(checking ? "Checking…" : "Check classifier") {
                    checking = true
                    Task {
                        note = await Self.checkClassifier(endpoint: endpoint, model: model)
                        checking = false
                    }
                }.disabled(checking)
            }
            Toggle("Advisor debug logging", isOn: $debug)
            Text("Records tool names, request sizes and timings in the daemon log. Prompt text, evidence and model replies are excluded.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Save advisor settings") { save() }
                    .disabled(setup.advisorPreferencesError != nil || checking)
                Button("Open daemon log") { setup.openAdvisorLog() }
            }
            if let error = setup.advisorPreferencesError {
                Text(error).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            if let note {
                Text(note).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .onAppear { restore() }
        .onChange(of: setup.advisorPreferences) { _, _ in restore() }
    }

    private func restore() {
        let p = setup.advisorPreferences
        timeout = p.timeoutMS.isMultiple(of: 1000) ? String(p.timeoutMS / 1000) : String(Double(p.timeoutMS) / 1000)
        classifier = !p.classifierEndpoint.isEmpty
        if classifier { endpoint = p.classifierEndpoint }
        model = p.classifierModel
        debug = p.debug
    }

    private func save() {
        do {
            guard let seconds = Int(timeout), seconds > 0, seconds <= Int.max / 1000 else { throw AdvisorPreferences.PreferenceError.timeout }
            let selectedModel = model.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !classifier || !selectedModel.isEmpty else {
                note = "Enter the classifier's served model name."
                return
            }
            try setup.saveAdvisorPreferences(AdvisorPreferences(timeoutMS: seconds * 1000,
                classifierEndpoint: classifier ? endpoint.trimmingCharacters(in: .whitespacesAndNewlines) : "",
                classifierModel: selectedModel, debug: debug))
            note = "Saved — the daemon applies these settings live."
        } catch { note = error.localizedDescription }
    }

    static func checkClassifier(endpoint: String, model: String) async -> String {
        guard AdvisorPreferences.isLoopbackEndpoint(endpoint),
              let url = URL(string: endpoint.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/v1/models") else {
            return AdvisorPreferences.PreferenceError.endpoint.localizedDescription
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 3
        config.timeoutIntervalForResource = 3
        let session = URLSession(configuration: config, delegate: LoopbackProbeDelegate(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            let (bytes, response) = try await session.bytes(from: url)
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                return "The classifier service did not answer successfully. Check its endpoint."
            }
            var data = Data()
            for try await byte in bytes {
                guard data.count < 32768 else { return "The classifier's model list exceeded the response limit." }
                data.append(byte)
            }
            guard
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rows = (object["models"] ?? object["data"]) as? [[String: Any]],
                  rows.contains(where: { ($0["id"] as? String) == model || ($0["aliases"] as? [String] ?? []).contains(model) }) else {
                return "The service did not list this model. Check its endpoint and served model name."
            }
            return "Classifier connected; model is listed. Routing quality has not been evaluated."
        } catch { return "Classifier is not answering. Start its local server, then check again." }
    }
}

private final class LoopbackProbeDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
