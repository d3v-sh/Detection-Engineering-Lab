# MITRE ATT&CK Coverage

[← Back to README](../README.md)

Full rollup of every technique executed against the lab, its detection verdict, and a link to the detailed scenario writeup.

Legend: ✅ Detected · ⚠️ Partially detected · ❌ Not detected · ⏳ Not yet run

| Technique | ATT&CK ID | Tactic | Scenario | Verdict |
|---|---|---|---|---|
| Brute Force | T1110 | Credential Access | [Scenario 1](./scenarios/scenario-01-brute-force.md) | ✅ Detected (raw + correlated alert) |
| Domain Accounts (successful auth) | T1078.002 | Persistence / Priv Esc / Initial Access | [Scenario 1](./scenarios/scenario-01-brute-force.md) | ⚠️ Detected but over-classified as PtH/RDP |
| Password Spraying | T1110.003 | Credential Access | [Scenario 2](./scenarios/scenario-02-password-spray.md) | ✅ Detected across all 3 targeted accounts |
| Valid Accounts (Domain) | T1078.002 | Persistence / Priv Esc / Initial Access / Lateral Movement | [Scenario 2](./scenarios/scenario-02-password-spray.md) | ✅ Detected (rule 92652) |
| Scheduled Task/Job (attempted) | T1053.005 | Persistence / Priv Esc | [Scenario 2](./scenarios/scenario-02-password-spray.md) | ❌ Not detected — blocked by privilege boundary, but no distinct telemetry for the attempt itself |
| Spearphishing Link | T1566.002 | Initial Access | [Scenario 3](./scenarios/scenario-03-phishing-email-analysis.md) | ✅ Confirmed via header/infra analysis (static triage — no lab telemetry involved) |

*(Rows are added only after a technique has actually been executed against the lab — this table reflects real coverage, not a planned roadmap.)*

<!-- Add rows as scenarios are executed. Keep in sync with the table in README.md. -->

## Coverage Summary

Three scenarios executed to date:

- **2/2** live attack scenarios (Scenarios 1-2) resulted in successful detection at the raw-event level, and **2/2** produced an analyst-actionable alert (correlated or direct), not just raw events
- **1** static analysis scenario (Scenario 3) — a real-world phishing sample triaged and confirmed via independent header and infrastructure verification, no lab telemetry involved
- **2** rule-accuracy gaps identified: (1) successful NTLM network logons labeled "possible pass-the-hash"/"possible RDP" regardless of actual technique — see [Scenario 1](./scenarios/scenario-01-brute-force.md#verdict--analysis); (2) rejected remote scheduled-task creation attempts (RPC-level authorization failure) generate no distinct Wazuh-visible telemetry — see [Scenario 2](./scenarios/scenario-02-password-spray.md#findings)
- **1** privilege-boundary success: a compromised domain account was correctly blocked from establishing persistence because it lacked local admin rights on the target — a control working as intended, independent of detection tooling

This summary is updated after each scenario is completed, not written in advance.

## Notes on Methodology

- Techniques were selected to be representative of common AD-focused attack paths (initial access → credential access → lateral movement), not exhaustive.
- "Detected" means a Wazuh alert fired that would give a real SOC analyst enough context to begin triage — not merely that raw log data reached the indexer.
- Where relevant, a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer may be published separately for a visual heat-map view of coverage.

---

[← Back to README](../README.md)