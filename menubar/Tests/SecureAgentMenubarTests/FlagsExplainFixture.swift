// Schema from GET /flags/{id}/explain; values synthetic.
enum FlagsExplainFixture {
    static let json = #"""
[
 {
  "id": "a1a1a1a1a1a1a1a1",
  "rule": "sensitive-read-then-connect",
  "severity": 3,
  "ts": "2026-09-23T00:01:33.112461172Z",
  "pid": 100,
  "agent": "claude",
  "evidence": [
   {
    "kind": "read",
    "label": "config",
    "sub": "sensitive read",
    "ts": "2026-09-23T00:01:33Z",
    "text": "claude (pid 100) read config at 2026-09-23T00:01:33Z"
   },
   {
    "kind": "connect",
    "label": "2001:db8:1::1:443",
    "sub": "egress",
    "ts": "2026-09-22T20:01:36-04:00",
    "text": "then connected to 2001:db8:1::1:443 at 2026-09-22T20:01:36-04:00"
   },
   {
    "kind": "connect",
    "label": "2001:db8:2::2:443",
    "sub": "egress",
    "ts": "2026-09-22T20:01:38-04:00",
    "text": "then connected to 2001:db8:2::2:443 at 2026-09-22T20:01:38-04:00"
   },
   {
    "kind": "connect",
    "label": "2001:db8:2::2:443",
    "sub": "egress",
    "ts": "2026-09-22T20:01:42-04:00",
    "text": "then connected to 2001:db8:2::2:443 at 2026-09-22T20:01:42-04:00"
   }
  ],
  "title": "Agent read a secret, then connected out",
  "advisor": {
   "assessment": "benign",
   "confidence": 0.93,
   "rationale": "The agent read its own skill configuration and then made outbound HTTPS connections to known cloud provider ranges consistent with routine API and CDN traffic.",
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
     "host": "2001:db8:1::1",
     "port": 443,
     "org": "AWS",
     "kind": "ipv6",
     "allowlisted": true,
     "gap_seconds": 3
    },
    {
     "host": "2001:db8:2::2",
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
     "label": "Allow this Cloudflare address for claude",
     "consequence": "Future connections from claude to 2001:db8:2::2 are trusted and stop being flagged.",
     "method": "POST",
     "path": "/allowlist",
     "body": {
      "agent": "claude",
      "host": "2001:db8:2::2"
     },
     "recommended": true
    },
    {
     "id": "open-incident",
     "label": "Open incident report",
     "consequence": "Shows the incident's remediation checklist with rotation advice; changes nothing.",
     "method": "GET",
     "path": "/incidents?id=inc-syn-0001&format=markdown"
    }
   ]
  }
 },
 {
  "id": "b2b2b2b2b2b2b2b2",
  "rule": "secret-in-transcript",
  "severity": 2,
  "ts": "2026-09-23T20:55:55.628137Z",
  "pid": 0,
  "agent": "codex",
  "session_id": "00000000-0000-4000-8000-000000000002",
  "workspace": "example-repo",
  "evidence": [
   {
    "kind": "transcript",
    "label": "rollout-2026-01-01T00-00-00-00000000-0000-4000-8000-000000000002.jsonl",
    "sub": "pattern match",
    "rule": "openai-key",
    "ts": "2026-09-23T16:55:55-04:00",
    "text": "codex transcript rollout-2026-01-01T00-00-00-00000000-0000-4000-8000-000000000002.jsonl matched pattern rule openai-key at 2026-09-23T16:55:55-04:00"
   }
  ],
  "title": "Secret appeared in an agent transcript",
  "advisor": {
   "assessment": "suspicious",
   "confidence": 0.72,
   "rationale": "A secret pattern was detected in an agent's session transcript file, repeating over the past week after not appearing in the prior week.",
   "suggested_action": "rotate-credentials",
   "model": "qwen3.8:27b-mlx",
   "created_at": "2026-09-23T20:56:24.300271Z"
  },
  "acknowledged": true,
  "explain": {
   "what": "A secret (openai-key) appeared in a Codex transcript (rollout-2026-01-01T00-00-00-00000000-0000-4000-8000-000000000002.jsonl).",
   "subject": {
    "path": "rollout-2026-01-01T00-00-00-00000000-0000-4000-8000-000000000002.jsonl",
    "display": "agents…000000000002.jsonl",
    "basename": "rollout-2026-01-01T00-00-00-00000000-0000-4000-8000-000000000002.jsonl",
    "category": "transcript",
    "category_label": "agent transcript",
    "rule": "openai-key",
    "owner_label": "system"
   },
   "context": {
    "session_id": "00000000-0000-4000-8000-000000000002",
    "harness": "codex",
    "repo": "example-repo",
    "branch": "main",
    "workspace": "example-repo",
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
     "path": "/incidents?id=inc-syn-0002&format=markdown",
     "recommended": true
    }
   ]
  }
 },
 {
  "id": "c3c3c3c3c3c3c3c3",
  "rule": "keychain-access",
  "severity": 2,
  "ts": "2026-09-12T03:08:45.848156546Z",
  "pid": 200,
  "agent": "codex",
  "evidence": [
   {
    "kind": "text",
    "label": "codex (pid 200) accessed keychain file SystemTrustSettings.plist at 2026-09-12T03:08:45Z",
    "text": "codex (pid 200) accessed keychain file SystemTrustSettings.plist at 2026-09-12T03:08:45Z"
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
     "path": "/incidents?id=inc-syn-0003&format=markdown"
    }
   ]
  }
 }
]
"""#
}
