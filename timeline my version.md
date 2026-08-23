# Timeline 

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
