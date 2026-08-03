# Scenario 1: SMB Brute Force Against Workstation

[← Back to README](../../README.md) · [MITRE Coverage](../mitre-coverage.md)

| | |
|---|---|
| **MITRE ATT&CK Technique** | T1110 – Brute Force |
| **Related techniques observed** | T1550.002 (Pass the Hash — flagged, see analysis), T1078.002 (Domain Accounts), T1021.001 (RDP — flagged, see analysis) |
| **Target** | Workstation — `10.0.2.6` (`DESKTOP-EE3IFE3.company.local`) |
| **Attacker Tool** | netexec (SMB module) |
| **Verdict** | ✅ Detected — individual failures logged, correlated brute-force alert fired, successful logon flagged (with caveats — see Analysis) |

---

## Objective

Simulate a credential-guessing attack against a domain-joined Windows 10 workstation over SMB, to validate whether Wazuh's default ruleset (a) captures individual failed authentication attempts, (b) correlates a burst of failures into a single actionable alert rather than leaving an analyst to spot the pattern manually, and (c) correctly identifies the eventual successful logon.

## Attack Execution

**Target account:** `James` (local account on the workstation)

**Tool / command used:**
```bash
netexec smb 10.0.2.6 -u James -p /usr/share/wordlists/rockyou.txt --local-auth
```

**Context:**
- Account was deliberately created for this test with a password not near the top of the wordlist, to generate a realistic volume of failed attempts before any eventual match.
- Prior to this run, an SMB reachability/firewall issue was resolved (workstation's network profile was set to Public, blocking inbound 445; corrected to Private and confirmed with `nmap -p 445`).
- An earlier attempt with Hydra failed outright (`invalid reply from smb://`) due to Hydra's SMB module lacking modern SMBv2/3 support — netexec was used instead as the actively maintained, SMB2/3-compatible tool.
- A separate anonymous/null-session probe (likely from earlier `enum4linux`/recon activity against the same host) also appears in the log window and is included below since it's relevant to the same authentication-telemetry story.

## Expected Telemetry

- **Windows Security Event ID 4625** — failed logon, once per incorrect password attempt
- **Windows Security Event ID 4624** — successful logon, if/when the attack finds a valid credential
- Source IP/workstation name of the attacking host (Kali) should be present in the event detail

## Wazuh Detection Result

### 1. Individual failed attempts — detected
**Rule fired:** `60122` — *"Logon Failure - Unknown user or bad password"* (level 5)
Fired once per failed attempt. Volume during the attack window ran into the thousands of individual events (~1,800+ in the captured window alone).

📸 `docs/screenshots/scenario-01-failed-logons.png`

### 2. Correlated brute-force alert — detected
**Rule fired:** `60204` — *"Multiple Windows Logon Failures"* (level 10)
This is the important result: Wazuh's default ruleset didn't just log each failure independently — it correlated the burst into a single higher-severity alert. This is what would actually surface to an analyst's queue rather than requiring them to manually notice a pattern across thousands of raw events.

📸 `docs/screenshots/scenario-01-correlated-alert.png`

### 3. Successful logon(s) — detected, but over-classified
Two successful logons appear in the window:

**a) Anonymous/null-session logon**
- Rule `92652` — *"Successful Remote Logon Detected - User:\ANONYMOUS LOGON - NTLM authentication, possible pass-the-hash attack."* (level 6)
- `logonType: 3` (network), `targetUserName: ANONYMOUS LOGON`, source `192.168.31.132`

**b) `James` account successful logon**
- Rule `92657` — *"Successful Remote Logon Detected - User:\James - NTLM authentication, possible pass-the-hash attack - Possible RDP connection. Verify that KALI is allowed to perform RDP connections"* (level 6)
- `logonType: 3` (network), `workstationName: KALI`, NTLM V2, source `192.168.31.132`

📸 `docs/screenshots/scenario-01-successful-logon.png`

---

## Verdict & Analysis

- ✅ **Individual failed attempts:** fully detected, high fidelity, correct rule/level.
- ✅ **Correlation:** Wazuh's default ruleset successfully escalated the failure burst into a single "Multiple Windows Logon Failures" alert — this is real out-of-the-box value, not something that needed custom tuning.
- ⚠️ **Successful logon classification is over-broad.** Both successful logons in this window were labeled as *"possible pass-the-hash attack"*, and the `James` login was additionally flagged as a *"Possible RDP connection."* Neither was accurate:
  - This was a standard SMB/NTLM network logon (`logonType: 3`) from netexec — not pass-the-hash (no hash was passed; a plaintext-equivalent password was used over NTLM auth) and not RDP (SMB traffic, not an RDP session).
  - The rule appears to trigger broadly on **any NTLM network logon** rather than on indicators specific to pass-the-hash (e.g., absence of a plausible interactive logon chain, or NTLM authentication without a corresponding Kerberos pre-auth where one would be expected) or RDP (which would show a different logon type / port).
  - **Practical implication for a real SOC:** this rule, as-is, would generate a "possible PtH" alert on ordinary SMB tooling, remote admin scripts, and legitimate service accounts authenticating over the network — a real source of alert fatigue if not tuned.
- **Timeliness:** all three alert types (raw failure, correlated failure, successful logon) appeared with the event, in near real time — no meaningful lag observed.
- **Anonymous logon event** is worth separate note: a null-session/anonymous SMB connection succeeded and was logged/flagged, which is itself a useful signal (anonymous access should generally not be succeeding against a hardened host) but wasn't specifically investigated as its own scenario here — see Future Work.

## Remediation / Tuning Applied

No custom rule was required for **detection** — 60122 and 60204 handled this case well out of the box.

**Tuning opportunity identified (not yet applied — flagged for Future Work):**
Narrow or split rule `92657`/`92652`'s conditions so that "possible pass-the-hash" / "possible RDP" labels only apply when corroborating indicators are present (e.g., NTLM auth *without* an expected Kerberos exchange on a domain that should be using Kerberos, or an actual RDP-associated port/logon type), rather than firing on every NTLM network logon. As shipped, this rule's specificity is low enough to produce false-positive-flavored labeling on benign/expected authentication.

---

[← Back to README](../../README.md) · [MITRE Coverage](../mitre-coverage.md)