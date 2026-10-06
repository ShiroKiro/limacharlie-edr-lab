# Scenario 03 — Registry Run Key Persistence

**MITRE ATT&CK:** [T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
**Tactic:** Persistence (TA0003), Privilege Escalation (TA0004)
**Sensor:** LimaCharlie EDR agent on Windows 11 Enterprise (`desktop-d5fg7b4`)

---

## 1. Hypothesis

A common persistence technique: an attacker writes a value to a Registry
autostart key (`...\CurrentVersion\Run` or `RunOnce`) so their payload executes
on every logon. Detection targets writes to these specific keys.

**Detection logic:** any `REGISTRY_WRITE` on a Windows sensor where the key path
matches `\CurrentVersion\Run\` or `\CurrentVersion\RunOnce\`.

## 2. Telemetry source

| Item | Value |
|------|-------|
| LimaCharlie event type | `REGISTRY_WRITE` |
| Key field — registry path | `event/REGISTRY_KEY` |
| Key field — written value (first 16 bytes) | `event/REGISTRY_VALUE` |
| Key field — value size | `event/SIZE` |

**Important configuration note:** `REGISTRY_WRITE` is **not** part of the default
Windows exfil profile. It had to be explicitly enabled in **Sensors → Event
Collection** (Exfil) for the `default-windows` rule. The default profile only
ships `NEW_PROCESS`, `TERMINATE_PROCESS` and `CODE_IDENTITY`. This is a real EDR
tuning lesson: telemetry you rely on must be deliberately turned on, and registry
telemetry is high-volume — the raw stream is dominated by legitimate writes from
`svchost`, WMI tracing and DeliveryOptimization, so the detection rule must be
tightly scoped.

## 3. Attack simulation

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EvilPersist_<rand> /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

`HKCU` is written by the OS as the native kernel path
`\REGISTRY\USER\<SID>\Software\Microsoft\Windows\CurrentVersion\Run\...`, which is
why the rule matches on the path tail rather than the `HKCU`/`HKLM` prefix.

## 4. Detection rule

See [`../rules/03-registry-run-key.yaml`](../rules/03-registry-run-key.yaml).

```yaml
event: REGISTRY_WRITE
op: and
rules:
  - op: is windows
  - op: matches
    path: event/REGISTRY_KEY
    re: (?i)\\CurrentVersion\\Run(Once)?\\
    case sensitive: false
```

Respond:
```yaml
- action: report
  name: Registry Run Key persistence (T1547.001)
```

The regex matches both `\CurrentVersion\Run\<value>` and `\RunOnce\<value>`
across HKLM and HKU hives, while excluding unrelated keys that merely contain the
word "Run".

## 5. Investigation

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-10-05 03:34:50 | Write to `...\CurrentVersion\Run\EvilPersist_<rand>` (PID 3132) |
| 2026-10-05 03:34:51 | Detection generated (~1.2s latency) |

### Triage of the matched event

| Field | Value | Meaning |
|-------|-------|---------|
| REGISTRY_KEY | `\REGISTRY\USER\S-1-5-21-...-1001\...\CurrentVersion\Run\EvilPersist_<rand>` | Per-user autostart key |
| REGISTRY_VALUE | `C:\Windo...` (first 16 bytes) | Payload path written to the key |
| SIZE | 58 | Length of the written value |
| TYPE | 1 | REG_SZ (string) |
| PROCESS_ID | 3132 | Process that performed the write |

The `S-1-5-21-...` SID identifies the local user account — distinguishing a
targeted user-hive persistence from machine-wide (`HKLM`) persistence.

## 6. Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| Registry key | `...\CurrentVersion\Run\EvilPersist_<rand>` |
| Payload reference | `C:\Windows\System32\calc.exe` (benign lab stand-in) |
| Value type | REG_SZ |

## 7. Response

In the lab the rule uses `report`. In production:
- Alert and pull the full value data (the event carries only the first 16 bytes;
  task the sensor to read the complete key for the payload path).
- Correlate the writing PID (3132) back to its process tree for attribution.
- For confirmed malicious persistence: delete the registry value and quarantine
  the referenced binary.

## 8. True Positive / True Negative test

| Test | Command | Result |
|------|---------|--------|
| TP | `reg add HKCU\...\CurrentVersion\Run /v EvilPersist_<rand> ...` | Detection fires |
| TN | `reg add HKCU\Software\LabTest\Config /v SomeSetting ...` | Silent (not a Run key) |

## 9. Tuning notes

- The raw `REGISTRY_WRITE` stream is extremely noisy; scoping to Run/RunOnce keys
  is what makes the detection actionable.
- v2 ideas: add other autostart locations (`Winlogon\Shell`, `Image File
  Execution Options`, services keys); allowlist known-good software install paths
  to suppress legitimate installer writes.

## 10. Screenshots

| File | Shows |
|------|-------|
| `../screenshots/03-detection.png` | Run key detection in Detections |
| `../screenshots/03-event.png` | Raw REGISTRY_WRITE JSON (oid/iid/ext_ip redacted) |
| `../screenshots/03-noise.png` | Raw registry stream before scoping (tuning rationale) |
