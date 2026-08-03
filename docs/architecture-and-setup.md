# Architecture & Setup

[← Back to README](../README.md)

## Architecture

```
![Architecture](docs/architecture.png)

```

Note: the attacker VM runs on a second physical machine (not the VirtualBox host) to keep the host's 16GB RAM budget free for the four SIEM/AD VMs, and to approximate a more realistic network boundary between attacker and target than co-locating everything on one hypervisor.

### IP Scheme

| Host | Static IP |
|---|---|
| Wazuh Server | `10.0.2.3` |
| Domain Controller | `10.0.2.4` |
| Workstation | `10.0.2.6` |

The workstation is dual-homed: one adapter on the shared NAT Network (`10.0.2.x`) to reach the DC and Wazuh server, and a second adapter bridged to the local LAN so the attacker machine (a separate physical host running Kali, kept off the main host to reduce resource load) can reach it directly. The Domain Controller remains NAT-Network-only. This means attacks against the DC specifically require pivoting through the workstation, while the workstation itself is directly reachable from the attacker — an intentional approximation of a real initial-access-then-pivot path rather than a flat, fully-open lab network.

All VMs on the NAT Network side retain internet egress in addition to inter-VM reachability (see [Problems Faced](#problems-faced-during-setup) below for why plain NAT does not provide this).

---

## Setup Summary

1. Provisioned 4 VMs on a shared VirtualBox NAT Network
2. Deployed Wazuh manager/indexer/dashboard via the official `wazuh-docker` single-node Compose stack
3. Installed and enrolled Wazuh agents on the DC and workstation
4. Deployed Sysmon (SwiftOnSecurity config) on both Windows hosts; wired the Sysmon event channel into each agent's `ossec.conf`
5. Assigned static IPs to all four VMs to eliminate DHCP/DNS drift across reboots
6. Verified end-to-end telemetry flow via the Wazuh **Discover** view before beginning attack simulation

### Key commands

**Wazuh stack (on Ubuntu server):**
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.7
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

**Sysmon (on each Windows host, PowerShell, TLS 1.2 forced — see below):**
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

**Wiring Sysmon into the Wazuh agent (`ossec.conf`):**
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## Problems Faced During Setup

Documented honestly because they were as much a part of the engineering work as the final result.

### 1. Bare-metal Wazuh install failure cascade (led to switching to Docker)
Initial attempt used the official `wazuh-install.sh -a` bare-metal installer on Ubuntu Server. Hit a chain of issues:
- `wazuh-keystore: No such file or directory` — package installed per `apt`, but `/var/ossec` never got populated (partial install state).
- Repeated `dpkg` removal failures with **exit code 127** — broken `prerm`/`postrm` maintainer scripts calling commands/paths that no longer existed after prior partial installs, blocking clean reinstallation.
- **Disk space exhaustion** disguised as an indexer install failure — Ubuntu's LVM-based installer only allocated 14GB to the root LV despite a 30GB virtual disk; the remainder sat unallocated.
- **Port conflicts** (1515, 55000) from stray processes left behind by earlier failed installs.

**Resolution:** rather than keep fighting bare-metal package state corruption, switched to the official Dockerized Wazuh deployment (`wazuh-docker`), which sidesteps `apt`/`dpkg` state entirely.

### 2. Docker deployment: 500 error on dashboard login
Dashboard reachable but login returned Internal Server Error 500. Investigation via `docker compose logs` showed the real cause: the **indexer never formed a healthy cluster** (`ClusterManagerNotDiscoveredException`) — leftover, inconsistent cluster state in the Docker named volume from earlier failed `up`/`down` cycles.

**Resolution:** `docker compose down -v` (full volume wipe) + regenerate certs + fresh `up`.

### 3. Docker disk exhaustion (again)
Same underlying LVM sizing issue resurfaced — root filesystem filled again from accumulated Docker images/volumes across repeated failed attempts, throwing `java.io.IOException: No space left on device` inside the indexer container.

**Resolution:** `docker system prune -a --volumes -f` to reclaim space from dangling images/containers/volumes; confirmed with `df -h` before restarting the stack.

### 4. VirtualBox NAT vs. NAT Network — VMs couldn't reach each other
After getting both the DC and Wazuh server individually online, discovered they were on **different subnets** (`10.0.2.x` vs `10.0.3.x`) and could not ping each other at all. Root cause: plain **NAT** in VirtualBox gives each VM its own isolated private network — it is not shared between VMs even if subnets happened to overlap.

**Resolution:** created a dedicated VirtualBox **NAT Network** and moved all VMs onto it, preserving internet egress while enabling inter-VM connectivity.

### 5. DNS resolution failures (two separate instances)
- **On the DC:** could ping by IP but not by hostname. Cause: the DC runs its own DNS server (`127.0.0.1`/`::1`) with no forwarder configured for external resolution.
  **Fix:** `Add-DnsServerForwarder -IPAddress 8.8.8.8`.
- **On the Windows 10 workstation:** same symptom, different cause — Windows 10 has no DNS server role (`Get-DnsServerForwarder` doesn't exist there); it's a DNS *client* that needs to point at a working resolver (the DC, once its forwarder was fixed).

### 6. PowerShell + TLS on Windows 10
`Invoke-WebRequest` against GitHub raw content failed with "the underlying connection was closed" despite working internet connectivity (raw `ping` succeeded). Cause: Windows PowerShell 5.x doesn't enable TLS 1.2 by default, and GitHub rejects older TLS negotiations.

**Fix:**
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

---

## Lessons Learned

- **LVM sizing on Ubuntu Server installs isn't automatic** — a 30GB virtual disk doesn't mean 30GB usable; the installer's default LV allocation can leave most of it unallocated. Always check `df -h` against the *expected* size early, not after a failure blames something else.
- **Diagnose from the actual error, not the symptom's first appearance** — several failures (dashboard 500, indexer crash) initially looked like config/credential problems but were disk space or cluster-state issues underneath. Reading container/service logs directly, rather than reacting to the surface error, saved a lot of wasted effort.
- **VirtualBox networking modes are not interchangeable** — NAT and NAT Network solve different problems (internet egress vs. inter-VM connectivity) and picking the wrong one produces symptoms (like mismatched subnets) that look like a routing bug but are actually an architecture choice.
- **DNS has layers** — "no internet" can mean routing failure, DNS resolution failure, or missing forwarders, and each needs a different fix. Testing IP-based connectivity (`ping 8.8.8.8`) vs. name-based (`ping google.com`) separately is the fastest way to isolate which layer is broken.
- **When repeated failures pile up, don't keep patching — consider the sturdier path.** Switching from a bare-metal Wazuh install to the official Docker deployment after enough `dpkg` state corruption was the right call, not a workaround; containerization removed an entire class of problems rather than fixing them one at a time.

---

[← Back to README](../README.md)