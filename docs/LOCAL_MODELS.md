# Protect local model services

[Documentation](README.md) · [Project home](../README.md)

Use a private MLX worker for Secure Agent's analysis, or review and harden an
existing model server. These are separate choices: configuring managed analysis
does not change other running servers. Analysis remains advisory and never
changes guard or firewall enforcement.

## Choose the protection scope

| Service | Supported protection | Scope |
|---|---|---|
| Secure Agent managed MLX analysis | Private Unix connection; no model TCP listener | The supervised analysis worker only; Apple Silicon macOS |
| Existing MLX-LM server | Authenticated loopback gateway with a private Unix worker | Reviewed, direct current-user macOS launchd job |
| Existing llama.cpp server | Native key-file authentication | Reviewed, direct current-user macOS launchd job |
| Existing Ollama server | Browser Origin and Host hardening | The local API remains unauthenticated |
| Other servers or service managers | Manual server-owner configuration | Metadata observations alone leave protection unassessed |

## Set up private managed analysis

Managed analysis requires Apple Silicon macOS, `uv`, and locally prepared model
weights. In **Settings → Analysis**, choose **Managed local model**, then select
**Install private model runtime**. The CLI provides the same installation:

```sh
secure-agent model-runtime install
```

The installer pins mlx-agent and its dependencies in Secure Agent's private
runtime directory. It preserves global tools and existing model caches, and
does not download weights. Prepare the selected model locally, choose it in
Settings, then select **Enable automatic analysis**. Chat has its own model
configuration; choosing an analysis model does not change it.

For an existing local model directory, the equivalent advisor fields are:

```yaml
advisor:
  enabled: true
  managed: true
  managed_model: "/absolute/path/to/local/model"
  endpoint: ""
  api_key_file: ""
```

Managed mode requires an empty HTTP endpoint and API-key setting. See
[Configuration](CONFIGURATION.md#advisor-map) for configuration files and
overrides. A cached model ID can also be used when its weights are already
available locally.

The worker starts on the first analysis request, streams over an inherited Unix
socket, and exits after two idle minutes. It opens no model TCP listener and
does not download missing weights. An unavailable or incompatible runtime leaves
managed analysis unavailable; monitoring and deterministic protection continue.
The private directory restricts access by Unix user, without isolating the
worker from other processes already running as that user.

## Check existing servers

Open **Monitoring → Check local model servers**, or run:

```sh
secure-agent local-services --json
```

This inventories visible TCP listeners and checks up to 16 loopback metadata
endpoints, prioritizing configured servers. Managed analysis appears separately
with its private transport state. Partial inventory, truncated results and
omitted endpoints remain explicit. Non-loopback listeners are listed but never
contacted. To check selected endpoints, repeat `--endpoint`:

```sh
secure-agent local-services --endpoint http://127.0.0.1:9000 --endpoint 'http://[::1]:9001' --json
```

The check sends bounded metadata GETs without prompts, credentials, model
loading or service changes. It reports anonymous metadata responses,
cross-origin sharing and responses to an unrelated Host header. A refusal or
successful metadata response does not establish protection of inference or
administrative routes. These observations remain **not assessed** for
enforcement. **Recheck servers** obtains fresh observations; copying a hardening
profile does not apply it. Assessment and remediation are owner/UI operations
and refuse agent processes.

## Apply hardening to a supported service

The review flow supports current-user macOS launchd definitions that directly
run `mlx_lm.server`, `llama-server` or `ollama serve`. Other launchers, wrappers
and service managers require manual configuration.

1. In the server check, choose **Review a running service** and supply the
   selected job's absolute plist path. Select **Preview hardening**.
2. Review the service identity, endpoint, proposed settings, key-file path and
   affected Secure Agent client fields. Preview reads the running job without
   changing it.
3. Select **Apply and verify** and confirm the restart. Verification may load
   the service's existing local model and interrupt its clients.
4. Read the returned receipt, protection scope, named checks and verification
   time before relying on the result.

The CLI provides the same preview and explicit application:

```sh
secure-agent local-services remediate --service-file /absolute/path/model.plist
secure-agent local-services remediate --confirm --preview-id <id> --preview-hash <preview_hash>
secure-agent local-services receipt --label com.example.model
```

A preview expires after five minutes. Apply refuses a changed definition,
process, client configuration, key or runtime. Matching advisor and classifier
key-file fields are updated while unrelated configuration is preserved.
Incompatible local-chat consumers prevent application instead of being silently
reconfigured.

For MLX and llama.cpp, verification requires missing and incorrect credentials
to fail on inference and administrative routes, then requires one authorized
output token using existing local weights. It also checks foreign Origin/Host
refusal, listener ownership and the absence of an unexpected or directly
reachable TCP backend in the service's visible process family. Incomplete
listener evidence prevents verification. Ollama receives browser hardening only;
successful verification does not add authenticated isolation to its local API.

A `verified` receipt describes those checks at `verified_at`. It is a saved
operation result, not continuous monitoring or proof of current service health.

## Recover after failure or restore original settings

Failed verification restores original files and leaves the service stopped.
To request restoration explicitly, use **Restore original settings** from its
receipt or run:

```sh
secure-agent local-services rollback --label com.example.model
```

Rollback also leaves the restored service stopped. Starting the original
service is a separate owner action and may restore its earlier exposure.

| Receipt state | Meaning and next action |
|---|---|
| `verified` | Review the recorded scope, checks and timestamp. |
| `failed_no_change` | The operation failed before applying service changes; read its failure and obtain a fresh preview. |
| `failed_restored_stopped` | Application or verification failed; original settings were restored and the service is stopped. |
| `restored_stopped` | Explicit rollback restored original settings and left the service stopped. |
| `rollback_required` | Safe recovery could not finish; review the failure and retained private originals before changing the service. |
| `prepared` or `applying` | The saved operation is incomplete; read the last result before retrying or requesting restoration. |

Restoration refuses configuration drift. It does not overwrite later edits or
automatically restart an unprotected original service. Receipts expose hashes
and check names, never key contents or raw service arguments.

## Configure other clients and servers

To inspect a server-owner profile, select its runtime:

```sh
secure-agent local-services --runtime llama.cpp
secure-agent local-services --runtime mlx
secure-agent local-services --runtime ollama
secure-agent local-services --runtime openai-compatible
```

For servers with native bearer authentication, create a private key without
printing it or replacing a file:

```sh
secure-agent local-services create-key /absolute/private/directory/model-api.key
```

The parent directory must already exist. Enable native authentication through
the server's owner/service manager, then configure each client separately. Secure
Agent supports `advisor.api_key_file`, `advisor.classifier_api_key_file` and
`directory_guard.shell_review.api_key_file`. Files are revalidated for each
request; a missing or unsafe key fails the request without anonymous fallback.
See [Model API key files](CONFIGURATION.md#model-api-key-files).

After restarting a manually configured service, verify every direct IPv4/IPv6
listener, refusal of missing/bad credentials on inference and administration,
and successful authorized inference. A gateway cannot secure a reachable raw
backend. Loopback binding and CORS settings alone do not establish
authentication. Ollama's origin list is additive and its local API does not
enforce API keys.

Secure Agent's routing proxy handles explicitly routed traffic; it does not
transparently intercept unrelated browser connections to model servers. See the
[advisor threat model](ADVISOR_THREAT_MODEL.md#existing-model-server-hardening)
for boundaries and the [local-services API](API.md#get-local-services) for probe
limits and receipt contracts.
