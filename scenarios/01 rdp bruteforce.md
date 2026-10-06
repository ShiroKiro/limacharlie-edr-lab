# Scenario 01 — RDP / Logon Brute-Force

**MITRE ATT&CK:** [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
**Tactic:** Credential Access (TA0006)
**Sensor:** LimaCharlie EDR agent on Windows 11 Enterprise (`desktop-d5fg7b4`)

---

## 1. Hypothesis

An attacker performing password guessing against RDP/SMB generates a burst of
failed logon events (Windows Security EventID 4625) from a single source in a
short time window. A single failed logon is normal user error; a burst is not.

**Detection logic:** 5 or more failed logons (EventID 4625) on a Windows sensor
within a 60-second window.

## 2. Telemetry source

| Item | Value |
|------|-------|
| Event channel | Windows Security log, streamed via Artifact Collection rule `windows-event-logs` (`wel://Security:*`) |
| LimaCharlie event type | `WEL` |
| Key field — EventID | `event/EVENT/System/EventID` |
| Key field — target account | `event/EVENT/EventData/TargetUserName` |
| Key field — source IP | `event/EVENT/EventData/IpAddress` |
| Prerequisite | `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` |

## 3. Attack simulation

Network brute-force from a Kali VM on the same NAT segment against the Windows
endpoint's RDP service:

```bash
hydra -t 4 -V -l adminuser -P /usr/share/wordlists/rockyou.txt rdp://192.168.62.132
```

Stopped after ~10–15 seconds (dozens of attempts) — a full wordlist run is
unnecessary to cross the threshold.

## 4. Detection rule

See [`../rules/01-rdp-bruteforce.yaml`](../rules/01-rdp-bruteforce.yaml).

**Detect:**
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

**Respond:**
```yaml
- action: report
  name: RDP/Logon Brute-Force - 5+ failed logons in 60s (T1110.001)
```

The top-level rule filters to WEL events from Windows sensors. The `with events`
block declares a nested stateful rule that fires only when 5+ matching events
(EventID 4625) occur within 60 seconds on the same sensor.

> **Note:** stateful rules (`with events`) cannot be validated with TEST RULE —
> they are verified by live event generation or Replay.

## 5. Investigation

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-10-01 17:14:00 | Burst of 4625 failed logons from 192.168.62.129 (target `adminuser`) |
| 2026-10-01 17:14:01 | Detection generated (`RDP/Logon Brute-Force...`), ~1s latency |

### Triage of the matched event

| Field | Value | Meaning |
|-------|-------|---------|
| EventID | 4625 | Failed logon |
| LogonType | 3 | Network logon (remote, not local) |
| AuthenticationPackageName | NTLM | Remote auth attempt |
| TargetUserName | adminuser | Account being guessed |
| IpAddress | 192.168.62.129 | Source of the attack |
| WorkstationName | Kali | Attacker hostname |
| Status / SubStatus | 0xc000006d / 0xc0000064 | Bad password / user does not exist |

A single detection was raised for the whole burst — confirming the threshold
logic deduplicates a noisy series into one actionable alert.

## 6. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Source IP | 192.168.62.129 |
| Attacker hostname | Kali |
| Targeted account | adminuser |
| Logon type | 3 (network) |
| Event signature | 4625, SubStatus 0xc0000064 |

## 7. Response

In this lab the rule uses `report` only. In production, suitable automated
responses escalating with confidence would be:

- Raise a prioritized alert / ticket for SOC triage (implemented here).
- Collect context from the host (`os_processes`, `netstat`) via sensor tasking.
- For a confirmed external source: isolate the endpoint (`isolation` action) or
  push a firewall rule blocking the source IP.

## 8. Tuning notes (v1 → v2)

- **v1 (this rule):** counts all 4625 on the sensor. Simple, catches both local
  and network attempts.
- **v2 ideas:** add `group by` on `TargetUserName` and/or `IpAddress` so bursts
  are scoped per-account or per-source; restrict to `LogonType` 3/10 to focus on
  remote attacks; add a suppression window to avoid repeat alerts on a sustained
  campaign.

## 9. Screenshots

| File | Shows |
|------|-------|
| `../screenshots/01-detection.png` | Detection in the Detections view |
| `../screenshots/01-event-4625.png` | Raw 4625 event JSON (oid/iid/ext_ip redacted) |
| `../screenshots/01-rule.png` | D&R rule in the editor |