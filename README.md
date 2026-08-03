# SOC-Lab: Active Directory Threat Detection with Wazuh

> A self-hosted SOC lab simulating an enterprise Windows environment (Domain Controller + Workstation), monitored with a containerized Wazuh SIEM stack, and validated against real attack techniques executed from a dedicated attacker VM.

**Status:** 🚧 Active — infrastructure deployed, telemetry pipeline (Sysmon + Wazuh agents) confirmed, 1 attack scenario executed and documented.

---

## What this project is

Most "I deployed Wazuh" projects stop at the dashboard screenshot. This one is built around a simple question for each attack technique: **did the SIEM actually catch it, and if not, why not?**

The lab consists of:
- A Windows Server 2022 **Domain Controller** (AD DS + DNS)
- A domain-joined Windows 10 **Workstation**
- A Dockerized **Wazuh** stack (manager + indexer + dashboard) as the SIEM
- A **Kali** attacker VM used to run real, known techniques against the environment

Every attack executed is documented as: technique → command → what Wazuh saw (or didn't) → remediation. See [Attack Documentation](#attack-documentation--remediation) below.

---

## Architecture & Setup

Network diagram, VM roles, IP scheme, the setup process, problems hit along the way, and lessons learned all live here:

**→ [`docs/architecture-and-setup.md`](./docs/architecture-and-setup.md)**

Quick summary: 4 VMs on a shared VirtualBox NAT Network, Wazuh deployed via Docker Compose, Sysmon (SwiftOnSecurity config) on both Windows hosts feeding into Wazuh agents, static IPs across the board.

---

## Attack Documentation & Remediation

Each scenario is documented independently — technique used, exact command, expected telemetry, what Wazuh actually detected, and the remediation/tuning applied.

| # | Scenario | MITRE ATT&CK ID | Detected? | Doc |
|---|---|---|---|---|
| 1 | SMB Brute Force (workstation) | T1110 | ✅ | [scenario-01](./docs/scenarios/scenario-01-brute-force.md) |

*(New rows are added here only once a scenario has actually been executed and documented — this table reflects completed work, not a planned roadmap.)*

*(Table and files grow as scenarios are executed — see [`docs/mitre-coverage.md`](./docs/mitre-coverage.md) for the full rollup.)*

Legend: ✅ Detected · ⚠️ Partially detected · ❌ Not detected · ⏳ Not yet run

---

## MITRE ATT&CK Coverage

Full technique-to-detection rollup, independent of reading each scenario in full:

**→ [`docs/mitre-coverage.md`](./docs/mitre-coverage.md)**

---

## Tech Stack

| Component | Choice |
|---|---|
| Hypervisor | Oracle VirtualBox (shared NAT Network) |
| SIEM | Wazuh 4.14.x (Docker single-node: manager + indexer + dashboard) |
| Endpoint telemetry | Windows Event Logs + Sysmon (SwiftOnSecurity config) |
| Domain environment | Windows Server 2022 (AD DS, DNS) + Windows 10 workstation |
| Attacker tooling | Kali Linux |

---

## Future Work

Infrastructure and tooling additions planned for this lab — not attacks (those are only added to the tables above once actually executed):

- [ ] Add WebGoat (Dockerized) as a dedicated vulnerable web target to extend detection coverage into web attack techniques
- [ ] Publish a MITRE ATT&CK Navigator layer for visual coverage
- [ ] Add active-response automation infrastructure (e.g., auto-block capability on brute-force detection)

---

## Author

**Dev Shishodia** — [GitHub](https://github.com/d3v-sh) · [LinkedIn](https://linkedin.com/in/devshishodia)