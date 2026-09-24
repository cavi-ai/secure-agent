// Real /flags rows with `explain`, captured read-only from a live daemon
// (GET /flags/{id}/explain, the /flags row shape); file paths reduced to
// basenames, no secret-shaped values.
enum LiveFlagsFixture {
    static let json = #"""
[
 {
  "id": "12e7022e2de04005",
  "rule": "sensitive-read-then-connect",
  "severity": 3,
  "ts": "2026-09-23T00:01:33.112461172Z",
  "pid": 13250,
  "agent": "claude",
  "evidence": [
   {
    "kind": "read",
    "label": "config",
    "sub": "sensitive read",
    "ts": "2026-09-23T00:01:33Z",
    "text": "claude (pid 13250) read config at 2026-09-23T00:01:33Z"
   },
   {
    "kind": "connect",
    "label": "2600:1f10:4fa9:a02:3441:aad6:bb1a:fd73:443",
    "sub": "egress",
    "ts": "2026-09-22T20:01:36-04:00",
    "text": "then connected to 2600:1f10:4fa9:a02:3441:aad6:bb1a:fd73:443 at 2026-09-22T20:01:36-04:00"
   },
   {
    "kind": "connect",
    "label": "2606:4700:20::681a:4a4:443",
    "sub": "egress",
    "ts": "2026-09-22T20:01:38-04:00",
    "text": "then connected to 2606:4700:20::681a:4a4:443 at 2026-09-22T20:01:38-04:00"
   },
   {
    "kind": "connect",
    "label": "2606:4700:20::681a:4a4:443",
    "sub": "egress",
    "ts": "2026-09-22T20:01:42-04:00",
    "text": "then connected to 2606:4700:20::681a:4a4:443 at 2026-09-22T20:01:42-04:00"
   }
  ],
  "title": "Agent read a secret, then connected out",
  "advisor": {
   "assessment": "benign",
   "confidence": 0.93,
   "rationale": "The Claude agent read its own bookmark-librarian skill config under synced and then made HTTPS connections to Cloudflare (2600:1f10:4fa9 / 2606:4700:20::), which is a standard API/CDN endpoint, not an exfiltration target.",
   "suggested_action": "allow-host",
   "model": "qwen3.8:27b-mlx",
   "created_at": "2026-09-23T00:09:15.122777Z"
  },
  "acknowledged": true,
  "explain": {
   "what": "Claude read a sensitive file in Claude skills (skills), then reached AWS 3 s later.",
   "subject": {
    "path": "config",
    "display": "config",
    "basename": "config",
    "category": "other_sensitive",
    "category_label": "sensitive file",
    "owner_label": "Claude skills (skills)"
   },
   "egress": [
    {
     "host": "2600:1f10:4fa9:a02:3441:aad6:bb1a:fd73",
     "port": 443,
     "org": "AWS",
     "kind": "ipv6",
     "allowlisted": true,
     "gap_seconds": 3
    },
    {
     "host": "2606:4700:20::681a:4a4",
     "port": 443,
     "org": "Cloudflare",
     "kind": "ipv6",
     "allowlisted": false,
     "gap_seconds": 5
    }
   ],
   "disposition": {
    "state": "acknowledged",
    "text": "Reviewed",
    "why": "Agent read a secret, then connected out"
   },
   "actions": [
    {
     "id": "allow-host",
     "label": "Allow 2606:4700:20::681a:4a4 (Cloudflare) for claude",
     "consequence": "Future connections from claude to 2606:4700:20::681a:4a4 are trusted and stop being flagged.",
     "method": "POST",
     "path": "/allowlist",
     "body": {
      "agent": "claude",
      "host": "2606:4700:20::681a:4a4"
     },
     "recommended": true
    },
    {
     "id": "open-incident",
     "label": "Open incident report",
     "consequence": "Shows the incident's remediation checklist with rotation advice; changes nothing.",
     "method": "GET",
     "path": "/incidents?id=inc-1790121693-13250-12e7022e2de04005&format=markdown"
    }
   ]
  }
 },
 {
  "id": "53ed2e773a9d65a1",
  "rule": "secret-in-transcript",
  "severity": 2,
  "ts": "2026-09-23T20:55:55.628137Z",
  "pid": 0,
  "agent": "codex",
  "session_id": "01a0d00b-857a-7bc1-b82e-011e3a94923d",
  "workspace": "career-ops",
  "evidence": [
   {
    "kind": "transcript",
    "label": "rollout-2026-09-23T16-53-31-01a0d00b-857a-7bc1-b82e-011e3a94923d.jsonl",
    "sub": "pattern match",
    "rule": "openai-key",
    "ts": "2026-09-23T16:55:55-04:00",
    "text": "codex transcript rollout-2026-09-23T16-53-31-01a0d00b-857a-7bc1-b82e-011e3a94923d.jsonl matched pattern rule openai-key at 2026-09-23T16:55:55-04:00"
   }
  ],
  "title": "Secret appeared in an agent transcript",
  "advisor": {
   "assessment": "suspicious",
   "confidence": 0.72,
   "rationale": "An OpenAI API key was written into the codex agent's session transcript file on rollout-2026-09-23T16-53-31-01a0d00b-857a-7bc1-b82e-011e3a94923d.jsonl, and the rule fired 23 times in the past week after zero in the prior week, indicating the key is being repeatedly logged into a file that may be readable by other processes or synced off-machine.",
   "suggested_action": "rotate-credentials",
   "model": "qwen3.8:27b-mlx",
   "created_at": "2026-09-23T20:56:24.300271Z"
  },
  "acknowledged": true,
  "explain": {
   "what": "A secret (openai-key) appeared in a Codex transcript (rollout-2026-09-23T16-53-31-01a0d00b-857a-7bc1-b82e-011e3a94923d.jsonl).",
   "subject": {
    "path": "rollout-2026-09-23T16-53-31-01a0d00b-857a-7bc1-b82e-011e3a94923d.jsonl",
    "display": "agents…57a-7bc1-b82e-011e3a94923d.jsonl",
    "basename": "rollout-2026-09-23T16-53-31-01a0d00b-857a-7bc1-b82e-011e3a94923d.jsonl",
    "category": "transcript",
    "category_label": "agent transcript",
    "rule": "openai-key",
    "owner_label": "system"
   },
   "context": {
    "session_id": "01a0d00b-857a-7bc1-b82e-011e3a94923d",
    "harness": "codex",
    "repo": "career-ops",
    "branch": "main",
    "workspace": "career-ops",
    "model": "gpt-5.6-sol"
   },
   "disposition": {
    "state": "acknowledged",
    "text": "Reviewed",
    "why": "Secret appeared in an agent transcript"
   },
   "actions": [
    {
     "id": "open-incident",
     "label": "Open incident report",
     "consequence": "Shows the incident's remediation checklist with rotation advice; changes nothing.",
     "method": "GET",
     "path": "/incidents?id=inc-1790196955-0-53ed2e773a9d65a1&format=markdown",
     "recommended": true
    }
   ]
  }
 },
 {
  "id": "bcafe8fcc06567d3",
  "rule": "keychain-access",
  "severity": 2,
  "ts": "2026-09-12T03:08:45.848156546Z",
  "pid": 51364,
  "agent": "codex",
  "evidence": [
   {
    "kind": "text",
    "label": "codex (pid 51364) accessed keychain file SystemTrustSettings.plist at 2026-09-12T03:08:45Z",
    "text": "codex (pid 51364) accessed keychain file SystemTrustSettings.plist at 2026-09-12T03:08:45Z"
   }
  ],
  "title": "Agent touched the keychain",
  "acknowledged": true,
  "explain": {
   "what": "Codex opened a keychain file.",
   "disposition": {
    "state": "acknowledged",
    "text": "Reviewed",
    "why": "Agent touched the keychain"
   },
   "actions": [
    {
     "id": "mute-class",
     "label": "Dismiss this flag class",
     "consequence": "\"Agent touched the keychain\" stops raising flags; monitoring continues and suppressed hits are counted.",
     "method": "POST",
     "path": "/mute",
     "body": {
      "host": "*",
      "rule": "keychain-access"
     }
    },
    {
     "id": "open-incident",
     "label": "Open incident report",
     "consequence": "Shows the incident's remediation checklist with rotation advice; changes nothing.",
     "method": "GET",
     "path": "/incidents?id=inc-1789182525-51364-bcafe8fcc06567d3&format=markdown"
    }
   ]
  }
 }
]
"""#
}
