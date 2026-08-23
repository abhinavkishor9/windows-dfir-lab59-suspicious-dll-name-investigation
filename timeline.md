# Timeline — Lab 59 Suspicious DLL Name Investigation

## Timeline Purpose

This timeline documents the creation and investigation of suspiciously named DLL artifacts and their comparison with legitimate Windows DLLs.

Actual timestamps should be retained from the PowerShell output and Event Viewer when finalizing the lab.

---

# Investigation Timeline

| Time | Source | Activity | Result |
|---|---|---|---|
| 06:20 | File System | Investigation directory created | `C:\SuspiciousDLLNameLab` established |
| 06:23:09 | File System | `kernel32.dll` created | 68-byte controlled artifact |
| 06:23:55 | File System | `svchost.dll` created | 82-byte controlled artifact |
| 06:24:41 | File System | `version.dll` created | 80-byte controlled artifact |
| 06:24+ | File System | Metadata collected | Baseline recorded |
| 06:24+ | File System | SHA-256 calculated | Artifact hashes recorded |
| 06:30+ | File System | Test file contents inspected | Text content confirmed |
| 06:30+ | File System | Legitimate Windows DLL compared | Path/size/hash differences identified |
| 06:30+ | Authenticode | Signatures checked | Legitimate files valid; test files UnknownError |
| 06:30+ | File Search | Temp/Downloads/LocalAppData searched | No relevant DLLs found |
| 06:30+ | Sysmon | Event ID 1 reviewed | Process telemetry available |
| 06:30+ | Sysmon | Event ID 3 reviewed | Network telemetry available |
| 06:30+ | Sysmon | Event ID 7 checked | No events available |
| 06:30+ | PowerShell | Event ID 4104 searched | No relevant results |
| 06:30+ | Security | Event ID 4688 searched | No relevant results |
| Final | DFIR Analysis | Evidence correlated | Masquerading characteristics established |

---

# Phase 1 — Investigation Preparation

## 06:20 — Investigation Directory Created

The directory:

    C:\SuspiciousDLLNameLab

was created successfully.

The directory was used exclusively for controlled laboratory artifacts.

---

# Phase 2 — Controlled DLL Artifacts

## 06:23:09 — `kernel32.dll` Created

A harmless text file named:

    kernel32.dll

was created.

Size:

    68 bytes

Creation time:

    23-08-2026 06:23:09

---

## 06:23:55 — `svchost.dll` Created

A harmless text file named:

    svchost.dll

was created.

Size:

    82 bytes

Creation time:

    23-08-2026 06:23:55

---

## 06:24:41 — `version.dll` Created

A harmless text file named:

    version.dll

was created.

Size:

    80 bytes

Creation time:

    23-08-2026 06:24:41

---

# Phase 3 — Baseline Evidence

## After Artifact Creation

File metadata was collected for all three controlled files.

SHA-256 hashes were also collected.

The files were then compared with legitimate Windows components.

---

# Phase 4 — Legitimate DLL Comparison

## Windows `kernel32.dll`

Legitimate path:

    C:\Windows\System32\kernel32.dll

Size:

    783720 bytes

SHA-256:

    4636F65D449B1353100578C6CB139933CF2B134F5E246119D18968873A058BED

Signature:

    Valid

---

## Windows `version.dll`

Legitimate path:

    C:\Windows\System32\version.dll

Size:

    32584 bytes

SHA-256:

    AF45A728552CCFDCD9435C40ACE60A9354D7C1B52ABF507A2F1CB371DADA4FDE

Signature:

    Valid

---

# Phase 5 — Controlled Artifact Comparison

## Test `kernel32.dll`

Size:

    68 bytes

SHA-256:

    411DD104E12BF1F5FB6348E3CD1B64184991042099C7DC2B54DD13D6C88D43F2

Signature:

    UnknownError

Content:

    LAB 59 - harmless test artifact

---

## Test `version.dll`

Size:

    80 bytes

SHA-256:

    0B250FA548FF7A03C94B21427E072813DF50255DF13A505E5E2CB1AE9836AC85

Signature:

    UnknownError

---

# Phase 6 — Telemetry Investigation

## Sysmon Event ID 1

Sysmon process-creation telemetry was available.

No evidence was established that the controlled DLL artifacts were executed.

---

## Sysmon Event ID 3

Sysmon network telemetry was available and returned numerous events.

No specific network communication was attributed to execution of the controlled DLL artifacts.

---

## Sysmon Event ID 7

The Image Load event was queried.

Result:

    No events found

Therefore:

    Sysmon Event ID 7 = Not Available

This prevented direct DLL-load investigation through Sysmon.

---

## PowerShell Event ID 4104

PowerShell Script Block Logging was queried for the test directory and DLL filenames.

Result:

    No relevant events

Therefore, no PowerShell script evidence was identified linking the DLL artifacts to PowerShell execution.

---

## Security Event ID 4688

Security process-creation telemetry was queried for the suspicious DLL filenames.

Result:

    No relevant events

No process execution was established for the controlled DLL artifacts.

---

# Phase 7 — Additional DLL Searches

Searches were performed in:

    %TEMP%

    %USERPROFILE%\Downloads

    %LOCALAPPDATA%

No relevant DLL files were identified in those locations.

---

# Phase 8 — Troubleshooting

An initial PowerShell search used:

    -ErrorActionContinue

This generated a parameter error.

The command was corrected to:

    -ErrorAction SilentlyContinue

The corrected command completed normally.

---

# Phase 9 — Final Evidence Correlation

The evidence chain was:

    Suspicious DLL Name
          |
          v
       Full Path
          |
          v
       File Size
          |
          v
      File Contents
          |
          v
       SHA-256
          |
          v
    Digital Signature
          |
          v
    Process Telemetry
          |
          v
    Image Load Telemetry
          |
          v
    Network Telemetry
          |
          v
    Final Assessment

---

# Final Timeline Summary

| Evidence Category | Finding |
|---|---|
| Test DLL Names | Familiar Windows DLL names used |
| Test DLL Location | Outside `C:\Windows\System32` |
| Test DLL Size | Extremely small |
| Test DLL Content | Text rather than DLL binary |
| Test DLL Hashes | Different from legitimate Windows DLLs |
| Legitimate DLL Signatures | Valid |
| Test DLL Signatures | UnknownError |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 3 | Available |
| Sysmon Event ID 7 | Unavailable |
| PowerShell Event ID 4104 | No relevant results |
| Security Event ID 4688 | No relevant results |
| DLL Execution | Not established |
| DLL Loading | Not established |

---

# Final Assessment

The controlled files demonstrated strong masquerading characteristics:

    Familiar Name
        +
    Unexpected Location
        +
    Tiny File Size
        +
    Text Content
        +
    Different Hash
        +
    Unknown Signature

However, no evidence established that the test files were executed or loaded.

---

# Investigation Conclusion

The timeline demonstrates why DLL investigations should begin with the artifact itself and then expand outward to process, image-load, network, and timeline evidence.

The controlled files successfully demonstrated that a filename can create an appearance of legitimacy while the actual artifact is completely different from the genuine Windows component.

The evidence therefore supports:

    Suspicious DLL Naming / Masquerading

but does not support:

    Confirmed DLL Execution
    Confirmed DLL Loading
    Confirmed DLL Side-Loading
