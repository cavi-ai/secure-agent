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

- **Redaction**: All secret values (passwords, private keys, API tokens, JWTs) detected in agent transcripts or event streams are redacted in memory using Layer-5 patterns (`[REDACTED]`).
- **Local Isolation**: The daemon API binds strictly to a local Unix domain socket with restricted permissions (`0600`).
- **No Telemetry Phone-Home**: `secure-agent` operates entirely on your local machine. No system logs or audit traces are transmitted to external servers.

---

## ⏱️ Disclosure Process

- **Acknowledgement**: We will acknowledge receipt of your vulnerability report within 48 hours.
- **Investigation**: We will investigate and validate the issue within 5 business days.
- **Remediation**: Once verified, we will develop and release a fix as quickly as possible and publicly credit your responsible disclosure (unless you prefer anonymity).
