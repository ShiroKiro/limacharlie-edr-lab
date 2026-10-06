# Scenario 04 — LSASS Access / Credential Dumping

**MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
**Tactic:** Credential Access (TA0006)
**Sensor:** LimaCharlie EDR agent on Windows 11 Enterprise (`desktop-d5fg7b4`)

---

## 1. Hypothesis

Credential theft frequently targets the memory of `lsass.exe` (Local Security
Authority Subsystem Service), which holds authentication material. Any process
opening a handle to LSASS memory is high-signal and worth alerting on.

**Detection logic:** a `SENSITIVE_PROCESS_ACCESS` event where the target is
`lsass.exe`.

> **Platform note:** in LimaCharlie, `SENSITIVE_PROCESS_ACCESS` is emitted *only*
> for processes accessing `lsass.exe` on Windows — so this event type is itself a
> credential-access signal.

## 2. Telemetry source

| Item | Value |
|------|-------|
| LimaCharlie event type | `SENSITIVE_PROCESS_ACCESS` |
| Key field — target process | `event/TARGET/FILE_PATH` |
| Key field — accessing process | `event/SOURCE/FILE_PATH` |
| Collection requirement | High-volume event — enabled via Exfil / Event Collection; for production use an Exfil **Watch rule** to scope collection |

## 3. Attack simulation — four methods attempted

Four standard LSASS-dumping techniques were run against the endpoint. **All four
were blocked by layered host defenses** — a defense-in-depth result.

| # | Method | Tool | Result |
|---|--------|------|--------|
| 1 | ProcDump dump | `procdump.exe -ma lsass` (Atomic T1003.001-1) | Failed — prereq/`Access is denied` |
| 2 | comsvcs MiniDump | `rundll32 comsvcs.dll MiniDump` (Atomic T1003.001-2) | **Blocked by Defender** — flagged as `Trojan:Win32/RundllLolBin.AF` on the command line (AMSI/behavioral) |
| 3 | Direct syscalls | Outflank Dumpert (Atomic T1003.001-3) | Bypassed AMSI, but **`Failed to get processhandle`** — LSASS protection denied the handle |
| 4 | Task Manager dump | Right-click lsass → Create dump file | **`Access is denied`** |

### Root cause — LSASS Protected Process Light

```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
    RunAsPPL    REG_DWORD    0x2
```

`RunAsPPL = 2` means LSASS runs as a Protected Process Light (PPL) — enabled by
default on this Windows 11 build. Under PPL, even SYSTEM/Administrator cannot open
a memory-read handle to `lsass.exe`, which is why every dump method failed at the
`OpenProcess`/handle stage. No successful LSASS access occurred, so no
`SENSITIVE_PROCESS_ACCESS` event was generated on this host.

## 4. Detection rule

See [`../rules/04-lsass-access.yaml`](../rules/04-lsass-access.yaml).

```yaml
event: SENSITIVE_PROCESS_ACCESS
op: and
rules:
  - op: is windows
  - op: ends with
    path: event/TARGET/FILE_PATH
    value: lsass.exe
    case sensitive: false
```

Respond:
```yaml
- action: report
  name: LSASS memory access - possible credential dumping (T1003.001)
```

The rule is production-ready: on a host where LSASS access succeeds (PPL disabled,
or a PPL-bypass technique such as a vulnerable signed driver), any handle opened
to LSASS memory raises the detection.

## 5. Analysis / outcome

This scenario demonstrates **defense-in-depth rather than a successful detection
firing**, which is itself a valid SOC finding:

- **Windows Defender** blocked the signature-based LOLBin method at the command
  line (method 2).
- **AMSI evasion** (method 3) defeated the signature layer but was stopped by the
  next layer — **LSASS PPL** at the kernel.
- **PPL** also blocked the trusted-path attempt via Task Manager (method 4).

On a correctly hardened Windows 11 endpoint, credential dumping against LSASS is
blocked before it starts. The EDR detection rule is deployed as the catch for
hosts where those protections are absent or bypassed.

## 6. Indicators / detection artifacts

| Type | Value |
|------|-------|
| Target process | lsass.exe |
| Techniques attempted | comsvcs MiniDump, direct syscalls (Dumpert), ProcDump, Task Manager |
| Defender signature observed | Trojan:Win32/RundllLolBin.AF |
| Host hardening | RunAsPPL = 2 (LSASS PPL enabled) |

## 7. Response

In production the rule would:
- Alert as high severity (LSASS access is rarely benign).
- Capture the accessing process tree and binary for triage.
- Isolate the host and kill the accessing process on high confidence.
- Exceptions: allowlist known-good accessors (AV/EDR engines, some backup tools)
  to control false positives.

## 8. Validation note

Because `SENSITIVE_PROCESS_ACCESS` fires only on real LSASS access, and LSASS is
PPL-protected on this host, the rule could not be triggered live in this lab
without weakening the endpoint. Deliberately disabling PPL was rejected as it
would misrepresent a hardened system; the blocked-attack evidence above is the
documented result instead.

## 9. Tuning notes

- v2: add `SOURCE/FILE_PATH` allowlisting for legitimate accessors to suppress FPs.
- Pair with `THREAD_INJECTION` / `REMOTE_PROCESS_HANDLE` detections for broader
  credential-access and injection coverage.
- Consider correlating with Defender (`WEL` Defender logs) so AV blocks and EDR
  detections appear in one incident timeline.

## 10. Screenshots

| File | Shows |
|------|-------|
| `../screenshots/04-defender-block.png` | Defender flagging comsvcs method (Trojan:Win32/RundllLolBin.AF) |
| `../screenshots/04-dumpert-fail.png` | Dumpert `Failed to get processhandle` |
| `../screenshots/04-taskmgr-denied.png` | Task Manager "Access is denied" on lsass |
| `../screenshots/04-runasppl.png` | RunAsPPL = 2 registry query |
