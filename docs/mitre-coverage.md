# MITRE ATT&CK Coverage

[← Back to README](../README.md)

Full rollup of every technique executed against the lab, its detection verdict, and a link to the detailed scenario writeup.

Legend: ✅ Detected · ⚠️ Partially detected · ❌ Not detected · ⏳ Not yet run

| Technique | ATT&CK ID | Tactic | Scenario | Verdict |
|---|---|---|---|---|
| Brute Force | T1110 | Credential Access | [Scenario 1](./scenarios/scenario-01-brute-force.md) | ✅ Detected (raw + correlated alert) |
| Domain Accounts (successful auth) | T1078.002 | Persistence / Priv Esc / Initial Access | [Scenario 1](./scenarios/scenario-01-brute-force.md) | ⚠️ Detected but over-classified as PtH/RDP |

*(Rows are added only after a technique has actually been executed against the lab — this table reflects real coverage, not a planned roadmap.)*

<!-- Add rows as scenarios are executed. Keep in sync with the table in README.md. -->

## Coverage Summary

One scenario executed to date, covering two effective techniques (the intended brute-force attack, plus an unplanned but observed successful-authentication classification issue):

- **1/1** attack scenarios run resulted in successful detection at the raw-event level
- **1/1** resulted in a correlated, analyst-actionable alert (not just raw events)
- **1** rule-accuracy gap identified: successful NTLM network logons are labeled "possible pass-the-hash" / "possible RDP" by default, regardless of whether either is actually occurring — see [Scenario 1](./scenarios/scenario-01-brute-force.md#verdict--analysis) for detail

This summary is updated after each scenario is completed, not written in advance.

## Notes on Methodology

- Techniques were selected to be representative of common AD-focused attack paths (initial access → credential access → lateral movement), not exhaustive.
- "Detected" means a Wazuh alert fired that would give a real SOC analyst enough context to begin triage — not merely that raw log data reached the indexer.
- Where relevant, a [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer may be published separately for a visual heat-map view of coverage.

---

[← Back to README](../README.md)