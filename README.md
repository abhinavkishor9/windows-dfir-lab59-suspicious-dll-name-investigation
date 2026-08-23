# Windows DFIR Lab 59 — Suspicious DLL Name Investigation

## Overview

This lab investigates suspicious DLL naming and potential DLL masquerading from a Windows DFIR perspective. The investigation focuses on an important forensic principle: a filename that looks like a legitimate Windows DLL does not automatically mean that the file is legitimate.

A controlled investigation directory was created and populated with harmless text files using familiar DLL-style names such as `kernel32.dll`, `svchost.dll`, and `version.dll`. These files were deliberately not executed. Their paths, sizes, contents, SHA-256 hashes, and Authenticode signatures were compared with legitimate Windows DLLs located in `C:\Windows\System32`.

Sysmon Event ID 1 and Event ID 3 were available on the endpoint. Sysmon Event ID 7 was not available, while PowerShell Event ID 4104 and Security Event ID 4688 did not provide relevant results for the controlled DLL-name artifacts.

---

# Investigation Objectives

- Determine whether a suspicious DLL name corresponds to a legitimate Windows component.
- Compare the suspicious file's path with the expected location of the legitimate DLL.
- Compare file size and metadata between suspiciously named and legitimate files.
- Verify whether suspiciously named files are actually valid DLL binaries.
- Compare SHA-256 hashes between suspicious-looking files and legitimate Windows DLLs.
- Examine digital-signature status for both legitimate and suspiciously named files.
- Investigate whether any process was associated with the test DLL artifacts.
- Review Sysmon Event ID 1 for process creation context.
- Review Sysmon Event ID 3 for surrounding network activity.
- Determine whether Sysmon Event ID 7 is available for DLL image-load investigation.
- Investigate PowerShell Event ID 4104 for script-related activity.
- Investigate Windows Security Event ID 4688 for process-related activity.
- Distinguish suspicious naming from confirmed DLL execution or loading.
- Document telemetry gaps and avoid unsupported conclusions.

---

# Investigation Scenario

A Windows workstation is being investigated after an analyst notices files using names that resemble trusted Windows DLLs. The names appear legitimate at first glance, but the files are located outside the normal Windows system directories.

The analyst must determine whether these files are genuine Windows components, renamed files, fake DLLs, or potentially malicious DLLs.

The investigation focuses on:

- File location
- File size
- File contents
- SHA-256
- Digital signature
- Process association
- DLL-load telemetry
- Network activity
- Timeline

All test files used in the laboratory were harmless text files and were never executed.

---

# Lab Environment

| Component | Details |
|---|---|
| Operating System | Windows |
| Investigation Type | Windows DFIR |
| Investigation Directory | `C:\SuspiciousDLLNameLab` |
| Test Files | `kernel32.dll`, `svchost.dll`, `version.dll` |
| Sysmon Event ID 1 | Available |
| Sysmon Event ID 3 | Available |
| Sysmon Event ID 7 | Not available |
| PowerShell Event ID 4104 | No relevant results |
| Security Event ID 4688 | No relevant results |

---

# Controlled Test Artifacts

The following harmless files were created:

    C:\SuspiciousDLLNameLab\kernel32.dll
    C:\SuspiciousDLLNameLab\svchost.dll
    C:\SuspiciousDLLNameLab\version.dll

The files were actually simple text files containing controlled laboratory messages.

They were intentionally given DLL-like filenames to demonstrate how filename-based trust can be misleading.

---

# Baseline File Metadata

The controlled artifacts had the following sizes:

| File | Size |
|---|---:|
| `kernel32.dll` | 68 bytes |
| `svchost.dll` | 82 bytes |
| `version.dll` | 80 bytes |

The files were created during the investigation on 23 August 2026.

---

# Legitimate Windows DLL Comparison

The legitimate Windows DLL:

    C:\Windows\System32\kernel32.dll

was approximately:

    783720 bytes

The legitimate Windows file:

    C:\Windows\System32\version.dll

was approximately:

    32584 bytes

This demonstrated a significant difference between the real system components and the controlled test files.

---

# File Content Verification

The controlled `kernel32.dll` was opened with:

    Get-Content "C:\SuspiciousDLLNameLab\kernel32.dll"

The output was:

    LAB 59 - harmless test artifact

This demonstrated that the file was actually a text file despite using a `.dll` extension.

The test artifacts were never executed.

---

# SHA-256 Analysis

The controlled test files produced the following hashes:

    kernel32.dll
    411DD104E12BF1F5FB6348E3CD1B64184991042099C7DC2B54DD13D6C88D43F2

    svchost.dll
    F2CF7D6453752FE108376C7EC1A207BC7655F8AE599415DF6632C11F1FEBDF4D

    version.dll
    0B250FA548FF7A03C94B21427E072813DF50255DF13A505E5E2CB1AE9836AC85

The legitimate Windows `kernel32.dll` hash was:

    4636F65D449B1353100578C6CB139933CF2B134F5E246119D18968873A058BED

The legitimate Windows `version.dll` hash was:

    AF45A728552CCFDCD9435C40ACE60A9354D7C1B52ABF507A2F1CB371DADA4FDE

The hashes did not match.

This provided strong evidence that the test artifacts were not the legitimate Windows DLLs.

---

# Digital Signature Analysis

The legitimate Windows DLLs returned:

    Status: Valid

for both `kernel32.dll` and `version.dll`.

The controlled test artifacts returned:

    Status: UnknownError

for the corresponding files.

This was interpreted as supporting evidence that the test artifacts were not legitimate signed Windows components.

The signature result was not treated as a standalone maliciousness verdict.

---

# Path Analysis

The legitimate DLL path was:

    C:\Windows\System32\kernel32.dll

The controlled test file was:

    C:\SuspiciousDLLNameLab\kernel32.dll

The same filename appeared in two completely different locations.

This demonstrated why full file paths are critical during DLL investigations.

---

# Sysmon Event ID 1

Sysmon Event ID 1 was available and was queried during the investigation.

The event log contained numerous process-creation events.

The investigation searched for process activity potentially associated with the suspicious DLL names.

No evidence was established that the controlled DLL artifacts were executed.

---

# Sysmon Event ID 3

Sysmon Event ID 3 was available.

The investigation returned numerous network connection events during the investigation timeframe.

These events demonstrated that Sysmon network telemetry was functioning.

No specific network activity was attributed to execution of the controlled DLL artifacts.

---

# Sysmon Event ID 7

Sysmon Event ID 7 was queried to determine whether Image Load telemetry was available.

The endpoint returned:

    No events were found that match the specified selection criteria.

Therefore:

    Sysmon Event ID 7 = Not Available

This limited the investigation's ability to directly investigate DLL image-load activity using Sysmon.

---

# PowerShell Event ID 4104

PowerShell Event ID 4104 was queried for:

    SuspiciousDLLNameLab
    kernel32.dll
    svchost.dll
    version.dll

No relevant events were returned.

Therefore, PowerShell Script Block Logging did not provide additional evidence connecting the test artifacts to script execution.

---

# Windows Security Event ID 4688

Windows Security Event ID 4688 was queried for the controlled DLL names.

No relevant events were returned.

This meant that Security process-creation telemetry could not be used to establish an execution relationship for the test DLL artifacts.

This was documented as a telemetry limitation.

---

# Additional DLL Searches

The investigation searched for DLLs in:

    %TEMP%

    %USERPROFILE%\Downloads

    %LOCALAPPDATA%

No relevant DLL artifacts were returned from these searches.

One search initially used an invalid PowerShell parameter:

    -ErrorActionContinue

The command was corrected to:

    -ErrorAction SilentlyContinue

The corrected searches executed successfully.

---

# Evidence Correlation

The investigation followed this model:

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
    Process Evidence
          |
          v
    Image Load Evidence
          |
          v
    Network Evidence
          |
          v
       Timeline

This approach prevented the filename alone from being treated as proof of malicious activity.

---

# Key Findings

- Three DLL-looking test files were created.
- The files were harmless text files.
- Their filenames resembled legitimate Windows DLL names.
- The test files were stored outside `C:\Windows\System32`.
- Their sizes were dramatically different from legitimate Windows components.
- Their SHA-256 hashes did not match the legitimate Windows DLLs.
- Legitimate Windows `kernel32.dll` and `version.dll` had valid Authenticode signatures.
- The controlled test `kernel32.dll` and `version.dll` returned `UnknownError`.
- Sysmon Event ID 1 was available.
- Sysmon Event ID 3 was available.
- Sysmon Event ID 7 was unavailable.
- No relevant PowerShell Event ID 4104 results were found.
- No relevant Security Event ID 4688 results were found.
- No evidence established that the controlled DLL artifacts were executed or loaded.

---

# DFIR Interpretation

The controlled artifacts demonstrate a simple but important masquerading concept: a filename can look legitimate while the underlying file is completely different.

The combination of unusual path, extremely small file size, text content, different SHA-256 hash, and missing/invalid signature information provides strong evidence that the test files are not legitimate Windows DLLs.

However, because the files were never executed, the investigation does not demonstrate DLL execution, DLL side-loading, or DLL injection.

---

# Suspicious DLL Assessment Model

A suspicious DLL should be investigated using:

    Name
      +
    Path
      +
    Size
      +
    File Type
      +
    Hash
      +
    Signature
      +
    Process
      +
    Image Load
      +
    Network
      +
    Timeline

For example:

    kernel32.dll
       +
    C:\Users\<user>\AppData\Local\Temp\
       +
    Unknown Signature
       +
    Different Hash
       +
    Unexpected Process Loads DLL
       +
    Network Connection

would warrant significant additional investigation.

---

# MITRE ATT&CK Relevance

Potentially relevant techniques in a real incident could include:

**T1036 — Masquerading**

Relevant when an attacker makes a file appear legitimate by using misleading names, locations, or other attributes.

**T1574.002 — DLL Side-Loading**

Relevant only when evidence demonstrates that a legitimate executable loaded an attacker-controlled DLL through DLL search-order behavior.

The controlled lab only demonstrates suspicious naming and masquerading concepts. It does not establish DLL side-loading.

---

# Evidence Limitations

The investigation had several important limitations:

- Sysmon Event ID 7 was unavailable.
- No relevant PowerShell Event ID 4104 events were found.
- No relevant Security Event ID 4688 events were found.
- The controlled DLL files were not executed.
- No memory analysis was performed.
- No EDR image-load telemetry was available.
- No direct DLL-loading event was established.

Therefore, the investigation can confidently demonstrate suspicious DLL naming and artifact mismatch, but it cannot establish malicious DLL execution.

---

# Conclusion

This investigation demonstrated why analysts should never trust a DLL based only on its filename.

The controlled `kernel32.dll`, `svchost.dll`, and `version.dll` files used familiar Windows names, but their paths, tiny file sizes, text contents, hashes, and signature results clearly distinguished them from the legitimate Windows components.

Sysmon process and network telemetry were available, but Sysmon Event ID 7 was not. No relevant PowerShell 4104 or Security 4688 evidence was identified, and none of the controlled DLL files were executed.

The final DFIR conclusion is:

> The test artifacts demonstrated suspicious DLL naming and masquerading characteristics, but the available evidence does not establish DLL execution or loading.

---

# Skills Demonstrated

- Windows DFIR
- DLL Artifact Investigation
- DLL Masquerading Analysis
- File Path Analysis
- File Metadata Analysis
- SHA-256 Comparison
- Authenticode Validation
- Sysmon Event ID 1
- Sysmon Event ID 3
- Sysmon Event ID 7 Availability Analysis
- PowerShell Event ID 4104 Analysis
- Security Event ID 4688 Analysis
- Telemetry Gap Documentation
- Evidence Correlation
- Timeline Construction

---

# Disclaimer

This lab used harmless text files with DLL-style filenames. The files were not executed, loaded, injected, or used as malware. No real Windows system DLLs were modified.
