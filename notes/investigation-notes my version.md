# Investigation Notes 

# Investigation Directory

The controlled directory was created:

`C:\SuspiciousDLLNameLab`

The directory was created at approximately:

`23-08-2026 06:20`

---

# Controlled Artifacts

Three harmless files were created:

    kernel32.dll
    svchost.dll
    version.dll

The contents were simple text strings.

For example:

    LAB 59 - harmless test artifact

The files were intentionally given DLL extensions to demonstrate how filenames can be misleading.

---

# Baseline Metadata

The controlled files had the following metadata:

| File | Size | Creation Time | Last Write Time |
|---|---:|---|---|
| `kernel32.dll` | 68 bytes | 23-08-2026 06:23:09 | 23-08-2026 06:23:09 |
| `svchost.dll` | 82 bytes | 23-08-2026 06:23:55 | 23-08-2026 06:23:55 |
| `version.dll` | 80 bytes | 23-08-2026 06:24:41 | 23-08-2026 06:24:41 |

The extremely small sizes were immediately different from normal Windows DLLs.

---

# SHA-256 Analysis

The controlled artifacts produced:

    kernel32.dll
    411DD104E12BF1F5FB6348E3CD1B64184991042099C7DC2B54DD13D6C88D43F2

    svchost.dll
    F2CF7D6453752FE108376C7EC1A207BC7655F8AE599415DF6632C11F1FEBDF4D

    version.dll
    0B250FA548FF7A03C94B21427E072813DF50255DF13A505E5E2CB1AE9836AC85

The hashes were recorded as unique identifiers for the test artifacts.

---

# File Content Investigation

The controlled `kernel32.dll` was opened using:

    Get-Content "C:\SuspiciousDLLNameLab\kernel32.dll"

Output:

    LAB 59 - harmless test artifact

This demonstrated that the artifact was a text file despite its `.dll` extension.

This was a key finding because the filename did not correspond to the underlying file type.

---

# Legitimate kernel32.dll Comparison

The legitimate Windows component was:

    C:\Windows\System32\kernel32.dll

Metadata:

    Length: 783720 bytes
    CreationTime: 04-08-2026 07:05:38
    LastWriteTime: 04-08-2026 07:05:38

SHA-256:

    4636F65D449B1353100578C6CB139933CF2B134F5E246119D18968873A058BED

The controlled artifact:

    C:\SuspiciousDLLNameLab\kernel32.dll

was only:

    68 bytes

and had a completely different hash.

This established that the two files were not the same.

---

# Legitimate version.dll Comparison

The legitimate Windows component was:

    C:\Windows\System32\version.dll

Metadata:

    Length: 32584 bytes
    CreationTime: 04-08-2026 07:04:51
    LastWriteTime: 04-08-2026 07:04:51

SHA-256:

    AF45A728552CCFDCD9435C40ACE60A9354D7C1B52ABF507A2F1CB371DADA4FDE

The controlled `version.dll` was only 80 bytes and had a different SHA-256 hash.

---

# File Information Comparison

The legitimate Windows `kernel32.dll` contained normal Windows version information:

    InternalName: kernel32
    OriginalFilename: kernel32
    FileDescription: Windows NT BASE API Client DLL
    Product: Microsoft Windows Operating System

The controlled test artifact did not represent a genuine Windows component.

This demonstrated the importance of looking beyond the filename.

---

# Digital Signature Investigation

The legitimate Windows files returned:

    Status: Valid

The controlled files returned:

    Status: UnknownError

Observed examples:

    C:\Windows\System32\kernel32.dll
    Status: Valid

    C:\SuspiciousDLLNameLab\kernel32.dll
    Status: UnknownError

and:

    C:\Windows\System32\version.dll
    Status: Valid

    C:\SuspiciousDLLNameLab\version.dll
    Status: UnknownError

This provided additional evidence that the controlled files were not legitimate signed Windows components.

---

# Suspicious Path Analysis

The legitimate Windows file was stored in:

    C:\Windows\System32\

The controlled file was stored in:

    C:\SuspiciousDLLNameLab\

This distinction was important.

A familiar DLL name outside its expected system location should receive additional scrutiny.

---

# Additional DLL Searches

The investigation searched for DLL files in:

    %TEMP%

    %USERPROFILE%\Downloads

    %LOCALAPPDATA%

No relevant DLL files were returned from these searches.

This provided additional environmental context.

---

# PowerShell Search Error

An initial command used:

    -ErrorActionContinue

PowerShell reported:

    A parameter cannot be found that matches parameter name 'ErrorActionContinue'.

The command was corrected to:

    -ErrorAction SilentlyContinue

The corrected search completed successfully.

This was documented as a command syntax issue rather than an investigation failure.

---

# Sysmon Event ID 1

Sysmon Event ID 1 was available.

A broad query produced multiple process-creation events throughout the investigation period.

The investigation did not establish that the controlled DLL files were executed.

The event was therefore used primarily as supporting endpoint telemetry.

---

# Sysmon Event ID 3

Sysmon Event ID 3 was available and returned numerous network connection events.

The observed events covered the investigation timeframe, including activity after the DLL artifacts were created.

No specific network event was attributed to the controlled DLL artifacts.

---

# Sysmon Event ID 7

The investigation queried Event ID 7:

    Get-WinEvent -FilterHashTable @{
        LogName="Microsoft-Windows-Sysmon/Operational"
        Id=7
    }

No events were found.

Therefore:

    Sysmon Event ID 7 = Not Available

This prevented direct use of Sysmon Image Load telemetry for the test DLLs.

---

# PowerShell Event ID 4104

Event ID 4104 was queried for:

    SuspiciousDLLNameLab
    kernel32.dll
    svchost.dll
    version.dll

No relevant events were returned.

Therefore, PowerShell Script Block Logging did not provide additional evidence connecting the test files to script execution.

---

# Security Event ID 4688

Security Event ID 4688 was queried for:

    kernel32.dll
    svchost.dll
    version.dll

No relevant events were returned.

Therefore, Security process-creation telemetry could not establish execution of the controlled DLL artifacts.

---

# Execution Status

The controlled DLL artifacts were never executed.

No attempt was made to run:

    rundll32.exe
    regsvr32.exe

or any other DLL execution mechanism.

This was intentional.

The lab focused exclusively on artifact and naming investigation.

---

# Evidence Correlation

The investigation followed:

    DLL Name
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
    Image Load Telemetry
       |
       v
    Network Evidence
       |
       v
    Final Assessment

The strongest evidence came from the combination of path, size, content, hash, and signature.

---

