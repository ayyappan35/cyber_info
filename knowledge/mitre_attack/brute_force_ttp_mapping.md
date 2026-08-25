# MITRE ATT&CK: Brute Force / Account Takeover TTP Mapping

## T1110 — Brute Force
Systematic password guessing against one or more accounts.
- **T1110.001 Password Guessing** — many passwords against one username. Maps to this system's `login_fail` events clustered on a single `username` within a short window.
- **T1110.003 Password Spraying** — one or a few common passwords against many usernames, to stay under a per-account lockout threshold. Maps to `login_fail` events spread across many distinct `username` values from the same `ip` within a short window.
- **T1110.004 Credential Stuffing** — previously breached username/password pairs replayed against this system. Indistinguishable from spraying at the telemetry level; treat any high-volume multi-account failure burst from one source as this family.

See `incident_response/brute_force_and_credential_stuffing.md` for the corresponding detection signals and response runbook.

## T1087 — Account Discovery
`T1087.001 Local Account` — enumerating which usernames exist before attacking them, typically visible as failures whose `detail` distinguishes "unknown user" from "bad password". See `incident_response/user_enumeration.md`.

## T1078 — Valid Accounts
Once a brute-force or stuffing attempt succeeds, the attacker holds a valid credential and can authenticate normally — this is why a `login_success` immediately following a burst of `login_fail` events for the same account is high-signal, not just the failures themselves.

## T1078.004 / Session material
A leaked or replayed session token (`session_replay` event, `try_session_replay` tool) achieves the same outcome as T1078 without ever guessing a password. See `incident_response/session_hijacking_and_replay.md`.

## Why this mapping matters here
`get_user_risk`/`get_login_history` (security MCP) surface the raw signals; this document exists so the threat-assessment stage of the defense pipeline can name which technique a given pattern of `auth_logs` rows corresponds to, rather than inventing ad-hoc terminology per run.
