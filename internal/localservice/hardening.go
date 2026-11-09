package localservice

import "context"

// Hardening describes server-owner actions. Returning a profile neither
// applies it nor establishes that a live service enforces it.
type Hardening struct {
	Runtime      string   `json:"runtime"`
	Title        string   `json:"title"`
	Support      string   `json:"support"`
	Settings     string   `json:"settings"`
	Steps        []string `json:"steps"`
	Verification []string `json:"verification"`
	Limitations  []string `json:"limitations"`
	Docs         string   `json:"documentation"`
}

func HardeningProfiles() []Hardening {
	verify := []string{
		"Restart the server through its existing owner or service manager, then update every client that uses it.",
		"Recheck the original endpoint and every direct backend listener, including IPv6. A gateway does not protect a reachable unauthenticated backend.",
		"Confirm missing and incorrect credentials fail before inference or administrative actions, then confirm an authorized client still works. Metadata checks alone cannot prove this.",
	}
	return []Hardening{
		{Runtime: "llama.cpp", Title: "llama.cpp", Support: "native_key_file", Settings: "--host 127.0.0.1 --api-key-file /absolute/path/model-api.key --cors-origins https://secure-agent-browser.invalid --no-cors-credentials",
			Steps:        []string{"Use a current llama-server build whose help lists these flags; retain the existing local model and serving options.", "Create an owner-only random key file with secure-agent local-services create-key /absolute/path/model-api.key. Add the settings to the existing launch configuration.", "For an existing Secure Agent advisor, set advisor.api_key_file to that path. Keep key contents out of launch arguments, URLs and browser storage."},
			Verification: verify, Limitations: []string{"This profile permits native authenticated clients and excludes browser frontends. Configure an exact trusted browser origin if one is required.", "Public health routes can remain reachable. Confirm authentication on the inference and administrative routes actually used; this feature does not send inference probes."}, Docs: "https://github.com/ggml-org/llama.cpp/tree/master/tools/server"},
		{Runtime: "mlx", Title: "MLX with mlx-agent", Support: "private_worker_and_gateway_key", Settings: "mlx-agent serve start <local-model> --runtime mlx_lm --jit --api-key-file /absolute/path/model-api.key",
			Steps:        []string{"Use an mlx-agent build supporting --api-key-file and inherited-unix-v1 private workers; weights must already be prepared locally.", "Create an owner-only key file with secure-agent local-services create-key /absolute/path/model-api.key. Review the serve start preview before confirming its hash.", "Retire the original raw MLX TCP server through its owner. Point authenticated clients at the new gateway; set advisor.api_key_file when Secure Agent uses it."},
			Verification: verify, Limitations: []string{"Protected serving supports plain MLX-LM text JIT serving. Accelerated or vision runtimes without private transport remain unsupported.", "A raw mlx_lm.server listener left running remains directly reachable. Same-user processes can access private Unix sockets."}, Docs: "https://github.com/cavi-ai/mlx-agent"},
		{Runtime: "ollama", Title: "Ollama", Support: "browser_hardening_only", Settings: "OLLAMA_HOST=127.0.0.1:11434\nOLLAMA_ORIGINS=",
			Steps:        []string{"In the existing service configuration, bind to literal loopback and remove added wildcard or untrusted OLLAMA_ORIGINS entries. Preserve the existing port when clients depend on it.", "Update older Ollama versions through the server owner, then recheck unrelated Origin and Host headers.", "For authenticated isolation, move the workload to a runtime with native authentication or an isolated backend. An authenticated frontend alone cannot secure Ollama's reachable backend."},
			Verification: []string{verify[0], verify[1], "Recheck unrelated Origin and Host refusals on the installed version; review native and administrative routes separately."},
			Limitations:  []string{"OLLAMA_ORIGINS is additive: built-in localhost, app, file and webview origins remain allowed. An empty value does not disable browser access.", "Ollama's local API has no native API-key enforcement. CORS and loopback binding are not authentication; this profile does not establish full protection."}, Docs: "https://docs.ollama.com/faq"},
		{Runtime: "openai-compatible", Title: "Other OpenAI-compatible servers", Support: "manual_review", Settings: "",
			Steps:        []string{"Identify the runtime and version through its owner. OpenAI-compatible metadata does not establish the server's identity or security controls.", "Enable the runtime's native authentication, use a literal loopback bind, and restrict browser origins. Keep the backend private if a gateway supplies authentication.", "Use advisor.api_key_file for a compatible bearer-authenticated advisor. Use advisor.classifier_api_key_file or directory_guard.shell_review.api_key_file for classifier endpoints that support bearer authentication."},
			Verification: verify, Limitations: []string{"No automatic hardening adapter is available for an unidentified runtime. Authentication and direct-backend isolation require runtime-specific verification.", "Secure Agent's Ollama local chat and dispatched harnesses retain their own client configuration; an advisor key file does not configure those clients."}, Docs: ""},
	}
}

// AssessDiscovered prioritizes configured endpoints, recognizable model
// listener names, known ports, then other visible local listeners.
func AssessDiscovered(ctx context.Context, configured []string) (Report, error) {
	// Validate before invoking the inventory or sending any metadata request.
	for _, endpoint := range configured {
		if _, err := endpointURL(endpoint); err != nil {
			return Report{}, err
		}
	}
	inventory := DiscoverListeners(ctx)
	selected, omitted, err := selectEndpoints(configured, inventory)
	if err != nil {
		return Report{}, err
	}
	report, err := Assess(ctx, selected)
	report.Inventory, report.Omitted = &inventory, omitted
	return report, err
}
