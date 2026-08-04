# Scenario 2: Password Spray Against Multiple Accounts + Persistence Attempt

[← Back to README](../../README.md) · [MITRE Coverage](../mitre-coverage.md)

| | |
|---|---|
| **MITRE ATT&CK Technique(s)** | T1110.003 (Password Spraying), T1078.002 (Domain Accounts), T1550.002 (flagged — see analysis) |
| **Target** | Workstation — `10.0.2.6` (`DESKTOP-EE3IFE3.company.local`) |
| **Attacker Tool** | netexec (SMB), Impacket `atexec` |
| **Verdict** | ✅ Spray detected on all accounts (success + failures). ✅ Scoping possible via Wazuh alone. ⚠️ Post-compromise persistence attempt blocked by privilege boundary, not by detection — see Findings. |

---

## Executive Summary

*(Non-technical, four sentences — for a client/manager audience)*

Three domain accounts were targeted in a coordinated password-guessing attempt against a company workstation. One account, Alisha, was compromised using a weak/reused password; the other two held. The attacker attempted to establish a foothold on the compromised account by creating a scheduled task, but this was blocked because the account did not have administrator rights on the machine — no persistence was established. All activity was captured and is fully traceable in the security monitoring system.

---

## Timeline (UTC)

| Time (UTC) | Event |
|---|---|
| ~07:38:17 | Failed logon attempt — account `Daniel`, source `192.168.31.132`, NTLM, Logon Type 3 (network) |
| ~07:38:xx | Failed logon attempt — account `James`, same source, same pattern |
| 07:54:17 | **Successful logon — account `Alisha`**, same source, NTLM V2, Logon Type 3 |
| shortly after | Persistence attempt: remote scheduled task creation via Impacket `atexec` as `Alisha` against workstation — rejected with `rpc_s_access_denied` |

*Note: exact per-second timestamp for `James`'s failure was not individually captured in this write-up's evidence set; pattern and timing were consistent with `Daniel`'s in the same spray run.*

---

## Findings

1. **A single-password spray was run against three domain accounts** (`James`, `Daniel`, `Alisha`) targeting the workstation only — the Domain Controller was not directly reachable from the attacker's network position, and was not targeted in this test.
2. **Two accounts held** (`James`, `Daniel`) — repeated `4625` (logon failure, NTLM, Logon Type 3) events, correctly decoded and alerted by Wazuh rule `60122`/custom rule `100010`.
3. **One account was compromised** (`Alisha`) — a `4624` success event was generated and correctly alerted by Wazuh rule `92652` (*"Successful Remote Logon Detected... possible pass-the-hash attack"*).
4. **Post-compromise persistence was attempted and failed at the privilege layer, not the detection layer.** Using `Alisha`'s valid credentials, a remote scheduled task was attempted via Impacket's `atexec` (`schtasks /create ...` over DCE/RPC). This was rejected with `rpc_s_access_denied` — `Alisha` has valid domain credentials but is **not** a local administrator on the workstation, so ATSVC/RPC-based remote task creation is blocked by Windows itself.
5. **Detection visibility gap identified:** the rejected persistence attempt did **not** generate a distinct, separately alertable Windows Security or Sysmon event beyond the initial successful NTLM logon. The RPC-level authorization failure for the scheduled-task request was not observed as its own telemetry entry in Wazuh. In a real environment, this means a SOC would see "account X logged on successfully" but would have **no direct signal** that the attacker also attempted (and failed) to escalate/persist immediately afterward — that step is currently invisible without additional instrumentation (e.g., Sysmon Event ID 1 on `schtasks.exe`/task-scheduler-specific auditing, which was not enabled for this test).

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Source IP (attacker) | `192.168.31.132` |
| Targeted accounts | `James`, `Daniel`, `Alisha` |
| Compromised account | `Alisha` |
| Authentication method | NTLM / NTLM V2, Logon Type 3 (network) |
| Persistence tool signature | Impacket `atexec` (DCE/RPC scheduled task creation attempt) |
| Target host | `DESKTOP-EE3IFE3.company.local` (`10.0.2.6`) (`192.168.31.110`) |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic | Evidence |
|---|---|---|---|
| Password Spraying | T1110.003 | Credential Access | Single password, 3 accounts, low per-account failure count, Wazuh rules `60122`/`100010` |
| Valid Accounts (Domain) | T1078.002 | Persistence, Priv Esc, Initial Access, Lateral Movement | `Alisha` successful NTLM logon, rule `92652` |
| *(Flagged, not confirmed)* Pass the Hash | T1550.002 | Defense Evasion, Lateral Movement | Rule `92652` auto-labels this technique on any NTLM network logon — **not confirmed** here; this was a plaintext-equivalent password auth, not an actual PtH. Same over-classification issue documented in Scenario 1. |
| *(Attempted, blocked)* Scheduled Task/Job | T1053.005 | Persistence, Privilege Escalation | Impacket `atexec` attempt, rejected `rpc_s_access_denied` |

---

## Scope (Tiered)

| Tier | Accounts | Basis |
|---|---|---|
| **Tier 1 — Confirmed compromised** | `Alisha` | Successful NTLM logon (4624) from attacker IP |
| **Tier 2 — Targeted, not breached** | `James`, `Daniel` | Failed logon attempts (4625) from same attacker IP, same session window |
| **Tier 3 — Investigated and cleared** | *(none in this test)* | No third account was baselined against this spray; all three targeted accounts fell into Tier 1 or 2 |

---

## Actions Taken / Recommended Containment Sequence

*(This is a lab environment — the sequence below documents the correct order of operations that would be executed in a live environment, following the standard revoke → reset → remove-persistence → block → verify pattern.)*

1. **Revoke active sessions** for `Alisha` (kill any live authenticated session before touching credentials, so an already-open session can't be used while containment is in progress).
2. **Reset `Alisha`'s password** to a strong, non-spray-guessable value.
3. **Confirm no persistence exists** — in this case, verified directly: the scheduled-task attempt failed, so no cleanup of a foothold is required. In a real incident, this step would include checking for scheduled tasks, new local accounts, registry run-keys, and new services regardless of whether an attempt was "seen," since a successful attempt might not always generate visible telemetry (see Findings, point 5).
4. **Force password resets for `James` and `Daniel`** as a precaution, since they were directly targeted even though they held — spray attempts against an account are a signal the password may be weak/guessable regardless of outcome.
5. **Block the attacker's source IP** (`192.168.31.132`) at the workstation/network level.
6. **Verify** — re-run the failed/successful logon queries in Wazuh for the attacker IP after containment and confirm no further activity.

---

## Recommendations

- **Enforce account lockout policy** tuned to catch low-and-slow spray patterns (a handful of failures per account across many accounts) rather than only high-volume single-account brute force.
- **Enable Task Scheduler / "Other Object Access Events" auditing** on endpoints to close the visibility gap identified in Findings point 5 — this would surface both successful *and* rejected remote task-creation attempts as distinct, alertable events.
- **Review and tune rule `92652`** so "possible pass-the-hash" is not applied to every NTLM network logon indiscriminately (same recommendation as Scenario 1) — as shipped, it will over-alert on both real and benign NTLM authentication, reducing signal-to-noise for analysts.
- **Restrict local admin rights** on endpoints to a minimal set of accounts — in this test, the privilege boundary (not detection) was what stopped the attack from progressing to persistence. That boundary should be treated as a control worth explicitly monitoring and preserving, not an incidental side effect.

---

## Lessons Learned

- **What worked:** individual credential-failure detection, successful-logon detection, and multi-account scoping were all achievable directly from Wazuh's default Windows ruleset with no custom tuning required beyond the `srcip`-extraction rule (`100010`) built for Scenario 1's active-response work.
- **What didn't work / gap identified:** rejected post-compromise persistence attempts (RPC-level authorization failures) are not visible in the current logging configuration. A SOC relying solely on the logon events here would correctly identify the compromise but would have **no evidence** of what the attacker tried to do next unless that next step happened to succeed and generate its own event.
- **Engineering note:** a domain-authentication format issue (FQDN vs. NetBIOS domain name in NTLM auth strings) initially caused all three spray attempts to fail uniformly, including the account with the objectively correct password — a reminder that "same error across every target" is itself a diagnostic signal pointing at the auth mechanism/tooling, not necessarily the credentials themselves.

---

[← Back to README](../../README.md) · [MITRE Coverage](../mitre-coverage.md)