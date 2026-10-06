# LimaCharlie EDR Detection Lab

![LimaCharlie](https://img.shields.io/badge/EDR-LimaCharlie-blue)
![Platform](https://img.shields.io/badge/Platform-Windows_11-lightgrey)
![Rules](https://img.shields.io/badge/Detection-D%26R_Rules-green)
![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## Overview
A commercial cloud EDR/XDR lab built on LimaCharlie to demonstrate SOC analyst
skills: endpoint detection engineering, attack simulation, alert validation, and
incident investigation mapped to MITRE ATT&CK.

This project completes my SOC portfolio alongside the
[Wazuh open-source SIEM lab](https://github.com/ShiroKiro/soc-security-monitoring-lab)
and the [Microsoft Sentinel cloud SIEM lab](https://github.com/ShiroKiro/microsoft-sentinel-siem-lab),
adding hands-on experience with a **commercial EDR platform** and endpoint-level
detection — the layer that sits below SIEM. It is the realized follow-up to the
EDR roadmap item from the Sentinel lab: commercial endpoint detection, delivered
on LimaCharlie's free Community tier instead of Defender for Endpoint.

**Duration:** October 2026
**Environment:** LimaCharlie (Europe region) + Windows 11 Enterprise VM (VMware)
**Author:** Oleg Tuboltsev

---

## Architecture

**Data Flow:**
Windows 11 endpoint (LimaCharlie sensor) → LimaCharlie cloud → D&R rules → Detections

**Components:**
- `desktop-d5fg7b4` — Windows 11 Enterprise VM, LimaCharlie EDR sensor installed
- Kali Linux VM — attacker host (same NAT segment) for network-based attacks
- LimaCharlie org `oleg-soc-edr-lab` (Europe) — detection engineering and telemetry

**Telemetry configured:**
- Native EDR events: `NEW_PROCESS`, `SENSITIVE_PROCESS_ACCESS`
- Enabled via Event Collection (Exfil): `REGISTRY_WRITE`, `REGISTRY_CREATE`
- Windows Event Logs streamed via Artifact Collection (`wel://Security:*`,
  `wel://System:*`, `wel://Microsoft-Windows-PowerShell/Operational:*`)

**Detection Layer:**
- 5 custom D&R (Detect & Respond) rules across 4 attack scenarios
- Stateful (threshold) and stateless detection logic
- Each rule mapped to MITRE ATT&CK

**Setup screenshots:**
[Org dashboard](screenshots/1-dashboard.png) ·
[Installed agent](screenshots/2-installed-agent.png) ·
[Artifact collection](screenshots/3-artifact-collection.png) ·
[Console netstat](screenshots/5-netstat-web.png) ·
[LCQL query](screenshots/6-query.png)

---

## Detection Scenarios

### 1. RDP / Logon Brute-Force
| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Credential Access |
| MITRE Technique | T1110.001 Brute Force: Password Guessing |
| Event | `WEL` (Security 4625) |
| Logic | Stateful — 5+ failed logons within 60s |

```yaml
event: WEL
op: is windows
with events:
  count: 5
  within: 60
  op: is
  path: event/EVENT/System/EventID
  value: "4625"
```

Simulated with `hydra` over RDP from Kali. One detection raised per burst.
Full writeup: [`scenarios/01-rdp-bruteforce.md`](scenarios/01-rdp-bruteforce.md)

---

### 2. Suspicious PowerShell & LOLBin Execution
| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Execution, Defense Evasion |
| MITRE Technique | T1059.001 PowerShell / T1218 System Binary Proxy Execution |
| Event | `NEW_PROCESS` |
| Logic | Command-line flags + parent-child chain |

Two rules: PowerShell launched with evasion flags (`-nop`, `-w hidden`,
`-enc`, `ExecutionPolicy Bypass`), and a signed LOLBin (`regsvr32`/`mshta`/
`rundll32`) spawned by PowerShell.
Full writeup: [`scenarios/02-powershell-lolbins.md`](scenarios/02-powershell-lolbins.md)

---

### 3. Registry Run Key Persistence
| Field | Value |
|-------|-------|
| Severity | Medium |
| MITRE Tactic | Persistence |
| MITRE Technique | T1547.001 Registry Run Keys / Startup Folder |
| Event | `REGISTRY_WRITE` |
| Logic | Regex match on `\CurrentVersion\Run(Once)?\` |

Required enabling `REGISTRY_WRITE` in Event Collection (not in the default
profile). The raw registry stream is high-volume, so the rule is scoped to
autostart keys to stay actionable.
Full writeup: [`scenarios/03-registry-run-key.md`](scenarios/03-registry-run-key.md)

---

### 4. LSASS Access / Credential Dumping
| Field | Value |
|-------|-------|
| Severity | High |
| MITRE Tactic | Credential Access |
| MITRE Technique | T1003.001 OS Credential Dumping: LSASS Memory |
| Event | `SENSITIVE_PROCESS_ACCESS` |
| Logic | Target process = `lsass.exe` |

Four dumping methods (comsvcs, Dumpert/direct syscalls, ProcDump, Task Manager)
were attempted via Atomic Red Team — **all blocked by layered defenses**:
Defender signature on the command line, then LSASS Protected Process Light
(`RunAsPPL = 2`) denying every memory handle. Documented as a defense-in-depth
result; the detection rule is production-ready for hosts where PPL is absent or
bypassed.
Full writeup: [`scenarios/04-lsass-access.md`](scenarios/04-lsass-access.md)

---

## Detection Engineering Workflow

Each scenario followed the same cycle:

1. **Generate** — trigger the technique (manual command, hydra, or Atomic Red Team)
2. **Inspect** — read the raw event JSON in Timeline to find field paths
3. **Write** — author the D&R rule (detect + respond)
4. **Validate** — confirm true positive fires and true negative stays silent
5. **Document** — timeline, IOCs, MITRE mapping, screenshots, tuning notes

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Scenario |
|--------|-----------|----------|
| Credential Access | T1110.001 Brute Force | 1 |
| Execution | T1059.001 PowerShell | 2 |
| Defense Evasion | T1218 System Binary Proxy Execution | 2 |
| Persistence | T1547.001 Registry Run Keys | 3 |
| Credential Access | T1003.001 LSASS Memory | 4 |

---

## What I Learned

- Deploying and enrolling a commercial EDR sensor on a Windows endpoint
- Configuring EDR telemetry (Event Collection / Exfil) and understanding why
  specific event types (registry, LSASS access) are not collected by default
- Writing both stateless and stateful (threshold) D&R detection rules
- Reading raw event JSON to map field paths for detection logic
- Validating detections with true-positive / true-negative testing
- Simulating attacks safely with Atomic Red Team
- Interpreting a defense-in-depth outcome (Defender + LSASS PPL) as a valid finding

---

## Transferable Skills

LimaCharlie's detection model maps directly onto enterprise EDR/XDR platforms:

| LimaCharlie | Microsoft Defender for Endpoint | CrowdStrike |
|---|---|---|
| D&R rules (detect/respond YAML) | Custom Detection Rules | IOA / custom detections |
| LCQL queries | Advanced Hunting (KQL) | Event Search / CQL |
| `NEW_PROCESS`, `REGISTRY_WRITE` telemetry | Device process/registry events | Falcon telemetry |
| Response actions (isolate, deny_tree) | Live Response / automated actions | Real Time Response |

The detection engineering concepts — event schema, field paths, threshold logic,
MITRE mapping, false-positive tuning — carry across all three.

---

## Portfolio Series

| Lab | Type | Layer |
|---|---|---|
| [Wazuh SOC Lab](https://github.com/ShiroKiro/soc-security-monitoring-lab) | Open-source, self-hosted | SIEM + IDS |
| [Microsoft Sentinel Lab](https://github.com/ShiroKiro/microsoft-sentinel-siem-lab) | Cloud-native SIEM | SIEM |
| **LimaCharlie EDR Lab** (this repo) | Commercial cloud EDR | Endpoint / EDR |

Together they cover open-source and commercial tooling across the SIEM and EDR
layers of a SOC.

---

## Repository Structure

```
limacharlie-edr-lab/
├── README.md
├── architecture/      # lab diagram
├── rules/             # D&R detection rules (YAML)
├── scenarios/         # per-scenario investigation writeups
├── screenshots/       # detections, events, rule editor
└── iocs/              # indicators of compromise
```

---

**Author:** Oleg Tuboltsev · [LinkedIn](www.linkedin.com/in/oleh-tuboltsev) · Kankaanpää, Finland
