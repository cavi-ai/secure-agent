# Security Policy

## 🔒 Supported Versions

We actively maintain and provide security updates for the latest release on the `main` branch.

| Version | Supported |
| ------- | ------------------ |
| `main`  | ✅ Yes             |
| < 1.0   | ⚠️ Best Effort     |

---

## 🚨 Reporting a Vulnerability

If you discover a potential security vulnerability in `secure-agent`, please **do not report it publicly via GitHub issues**.

Instead, please report vulnerabilities responsibly by emailing security disclosures to:

📧 **security@cavi.ai**

### What to Include in Your Report

To help us triage and investigate the issue efficiently, please include:

1. **Description**: A clear overview of the issue and potential security impact.
2. **Reproduction Steps**: Step-by-step instructions or proof-of-concept payload.
3. **Environment**: macOS version, Go version, agent harness (Claude Code, Cursor, Codex, etc.).
4. **Impact Assessment**: What data, credentials, or system resources could be exposed or modified.

---

## 🛡️ Security & Privacy Practices in `secure-agent`

- **Redaction**: Detected secret values are masked with `[REDACTED]` before inclusion in stored/displayed evidence and local model context. Detection has limits: an unregistered value that matches no pattern can be missed. See [secret handling](docs/FIREWALL_THREAT_MODEL.md#handling-of-secret-material).
- **Local access**: The daemon's Unix socket is owner-scoped (`0600`) with peer authorization. An enabled loopback proxy also serves the console API behind a separate console token; some routes further refuse agent processes. See [API authentication](docs/API.md#peer-authentication--endpoint-roles).
- **External destinations**: Fleet webhooks and OTLP export are opt-in and send selected telemetry to configured destinations. Local chat and advisor calls require loopback model endpoints. Routed agent requests still go to their original upstream destinations. Review [configuration](docs/CONFIGURATION.md) and the [advisor threat model](docs/ADVISOR_THREAT_MODEL.md) for the scope of each path.

---

## ⏱️ Disclosure Process

- **Acknowledgement**: We will acknowledge receipt of your vulnerability report within 48 hours.
- **Investigation**: We will investigate and validate the issue within 5 business days.
- **Remediation**: Once verified, we will develop and release a fix as quickly as possible and publicly credit your responsible disclosure (unless you prefer anonymity).
