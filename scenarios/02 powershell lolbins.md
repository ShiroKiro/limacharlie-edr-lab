# Scenario 02 — Suspicious PowerShell & LOLBin Execution

**MITRE ATT&CK:**
- [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1218 — System Binary Proxy Execution (LOLBins)](https://attack.mitre.org/techniques/T1218/)

**Tactic:** Execution (TA0002), Defense Evasion (TA0005)
**Sensor:** LimaCharlie EDR agent on Windows 11 Enterprise (`desktop-d5fg7b4`)

---

## 1. Hypothesis

Two common attacker behaviours on Windows endpoints:

- **(2a)** PowerShell launched with evasion flags — hidden window, execution-policy
  bypass, encoded commands, or download cradles — rather than interactive use.
- **(2b)** A signed, trusted system binary (LOLBin) such as `regsvr32`, `mshta`
  or `rundll32` spawned by PowerShell to proxy execution and evade controls that
  trust Microsoft-signed binaries.

Both are detected on process creation (`NEW_PROCESS`) by command-line content and
parent-child relationship — behaviour, not file reputation.

## 2. Telemetry source

| Item | Value |
|------|-------|
| LimaCharlie event type | `NEW_PROCESS` (native EDR telemetry) |
| Key field — image path | `event/FILE_PATH` |
| Key field — command line | `event/COMMAND_LINE` |
| Key field — parent image | `event/PARENT/FILE_PATH` |

No extra audit configuration required — process creation is collected by the
sensor natively.

---

## 3. Detection 2a — Suspicious PowerShell flags

### Rule
See [`../rules/02a-powershell-flags.yaml`](../rules/02a-powershell-flags.yaml).

```yaml
event: NEW_PROCESS
op: and
rules:
  - op: is windows
  - op: ends with
    path: event/FILE_PATH
    value: powershell.exe
    case sensitive: false
  - op: matches
    path: event/COMMAND_LINE
    re: (?i)(-enc|-encodedcommand|-nop|-noprofile|-w hidden|-windowstyle hidden|-exec bypass|-executionpolicy bypass|downloadstring|frombase64string|iex)
```

Respond:
```yaml
- action: report
  name: Suspicious PowerShell flags (T1059.001)
```

### Simulation
```powershell
powershell.exe -nop -w hidden -ExecutionPolicy Bypass -Command "Write-Output lab-test-2a"
powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA
powershell.exe -Command "IEX (Write-Output 'lab-test-download-cradle')"
```

### Matched event
| Field | Value |
|-------|-------|
| Command line | `powershell.exe -nop -w hidden -ExecutionPolicy Bypass -Command "Write-Output lab-test-2a"` |
| Image | `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe` |
| User | DESKTOP-D5FG7B4\Oleh |
| Detection time | 2026-10-01 14:26:08 UTC |
| Triggering flags | `-nop`, `-w hidden`, `-ExecutionPolicy Bypass` |

---

## 4. Detection 2b — LOLBin spawned by PowerShell

### Rule
See [`../rules/02b-lolbin-from-powershell.yaml`](../rules/02b-lolbin-from-powershell.yaml).

```yaml
event: NEW_PROCESS
op: and
rules:
  - op: is windows
  - op: or
    rules:
      - op: ends with
        path: event/FILE_PATH
        value: mshta.exe
        case sensitive: false
      - op: ends with
        path: event/FILE_PATH
        value: regsvr32.exe
        case sensitive: false
      - op: ends with
        path: event/FILE_PATH
        value: rundll32.exe
        case sensitive: false
  - op: ends with
    path: event/PARENT/FILE_PATH
    value: powershell.exe
    case sensitive: false
```

Respond:
```yaml
- action: report
  name: LOLBin spawned by PowerShell (T1218)
```

### Simulation
```powershell
Start-Process regsvr32.exe -ArgumentList "/u"
```

### Matched event
| Field | Value |
|-------|-------|
| Command line | `regsvr32.exe /u` |
| Image | `C:\WINDOWS\system32\regsvr32.exe` |
| Parent image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| FILE_IS_SIGNED | 1 (Microsoft-signed) |
| Detection time | 2026-10-01 14:32:00 UTC |

**Key insight:** `regsvr32.exe` is a legitimate, Microsoft-signed binary
(`FILE_IS_SIGNED: 1`). Reputation-based controls trust it. The detection relies
on *behaviour* — the parent-child chain `powershell.exe -> regsvr32.exe` — which
is why LOLBin abuse must be caught by context, not file signature.

---

## 5. Indicators / detection artifacts

| Type | Value |
|------|-------|
| Technique 2a | Encoded/obfuscated PowerShell flags in command line |
| Technique 2b | Signed LOLBin with anomalous PowerShell parent |
| Host | desktop-d5fg7b4 |

## 6. Response

Both rules use `report` in the lab. In production:
- Alert + enrich with full process tree (`event/PARENT` chain already captured).
- For high-confidence encoded-command matches: kill the process (`deny_tree`) and
  isolate the host pending triage.
- Feed matches to an allowlist-tuning loop to drive down false positives from
  legitimate admin scripting.

## 7. Tuning notes

- **2a false positives:** legitimate automation (SCCM, Intune, backup jobs) uses
  `-NoProfile` / `-ExecutionPolicy Bypass`. v2 would allowlist known script paths
  / signing or require 2+ flags together to raise severity.
- **2b scope:** extend the LOLBin list (`certutil`, `bitsadmin`, `wmic`, `cscript`)
  and the anomalous-parent set (Office apps, browsers) for broader coverage.

## 8. Screenshots

| File | Shows |
|------|-------|
| `../screenshots/02a-powershell-detection.png` | PowerShell-flags detection |
| `../screenshots/02b-lolbin-detection.png` | LOLBin detection with parent chain |
