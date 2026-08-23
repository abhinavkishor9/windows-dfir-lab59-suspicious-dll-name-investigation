# Troubleshooting Notes — Lab 59 Suspicious DLL Name Investigation

## 1. DLL Files Were Actually Text Files

### Observation

The controlled `kernel32.dll` returned:

    LAB 59 - harmless test artifact

when read with:

    Get-Content "C:\SuspiciousDLLNameLab\kernel32.dll"

### Explanation

The file was deliberately created as a text file and given a `.dll` extension.

### DFIR Lesson

A `.dll` extension does not prove that a file is actually a Windows DLL.

---

## 2. Test DLL Was Much Smaller Than Legitimate DLL

### Observation

Controlled:

    kernel32.dll = 68 bytes

Legitimate:

    C:\Windows\System32\kernel32.dll = 783720 bytes

### Interpretation

The enormous size difference provided strong evidence that the two files were completely different artifacts.

### DFIR Lesson

File size is a useful triage indicator, but should be combined with hashes and signature information.

---

## 3. SHA-256 Hashes Did Not Match

### Observation

Controlled `kernel32.dll`:

    411DD104E12BF1F5FB6348E3CD1B64184991042099C7DC2B54DD13D6C88D43F2

Legitimate Windows `kernel32.dll`:

    4636F65D449B1353100578C6CB139933CF2B134F5E246119D18968873A058BED

### Interpretation

The two files were not identical.

The same comparison was performed for `version.dll`.

### DFIR Lesson

Cryptographic hashes provide stronger evidence of file identity than filenames.

---

## 4. Digital Signature Returned UnknownError

### Observation

Legitimate Windows DLLs returned:

    Valid

Controlled test files returned:

    UnknownError

### Interpretation

The controlled files were not recognized as valid signed Windows components.

### Important

`UnknownError` is not the same as:

    Malware

It must be interpreted together with path, size, type, hash, and process behavior.

---

## 5. Sysmon Event ID 7 Was Unavailable

### Problem

The Event ID 7 query returned:

    No events were found that match the specified selection criteria.

### Significance

Sysmon Image Load telemetry was not available on this endpoint.

### DFIR Impact

The investigation could not use Sysmon Event ID 7 to establish whether a process loaded one of the test DLLs.

### Resolution

The analysis relied on:

- File evidence
- Process Event ID 1
- Security 4688 where available
- PowerShell 4104
- Network Event ID 3

---

## 6. PowerShell Event ID 4104 Had No Relevant Results

### Observation

The search for:

    SuspiciousDLLNameLab
    kernel32.dll
    svchost.dll
    version.dll

returned no relevant events.

### Interpretation

PowerShell Script Block Logging did not provide evidence connecting the controlled DLL files to script activity.

### DFIR Lesson

No relevant 4104 event does not prove that no process interacted with the files.

---

## 7. Security Event ID 4688 Had No Relevant Results

### Observation

The search for the DLL filenames in Event ID 4688 produced no relevant events.

### Interpretation

No process-creation evidence was available specifically linking an execution event to the test DLL artifacts.

### DFIR Lesson

The lack of 4688 evidence does not prove that the files could never have been executed. It only means that this source did not provide the expected evidence.

---

## 8. Initial PowerShell Parameter Error

### Problem

The following parameter was used accidentally:

    -ErrorActionContinue

PowerShell returned:

    A parameter cannot be found that matches parameter name 'ErrorActionContinue'.

### Cause

The correct syntax requires the `-ErrorAction` parameter followed by a value.

### Correction

The command was corrected to:

    -ErrorAction SilentlyContinue

### DFIR Lesson

Command syntax errors should be documented separately from evidence findings.

---

## 9. DLL Search Returned No Additional Files

### Observation

Searches were performed in:

    %TEMP%

    %USERPROFILE%\Downloads

    %LOCALAPPDATA%

No relevant DLLs were found.

### Interpretation

No additional suspicious DLL artifacts were identified in the searched locations.

This does not establish that no suspicious DLLs exist elsewhere on the system.

---

## 10. DLLs Were Not Executed

### Safety Decision

The controlled DLL files were never executed.

No use was made of:

    rundll32.exe

or:

    regsvr32.exe

### Reason

The purpose was to investigate suspicious naming safely.

### DFIR Lesson

A good DFIR lab should not execute fake or malicious artifacts simply to generate telemetry.

---

## 11. Filename Was Not Treated as Proof

### Observation

The test files used names such as:

    kernel32.dll
    svchost.dll
    version.dll

### Correct Interpretation

These names only create a lead.

The analyst must examine:

    Name
    Path
    Size
    Content
    Hash
    Signature
    Process
    Image Load
    Network
    Timeline

---

# Troubleshooting Summary

| Observation | Resolution |
|---|---|
| `.dll` files were text files | Used content verification |
| `kernel32.dll` was only 68 bytes | Compared with legitimate 783720-byte DLL |
| Hashes differed | Used SHA-256 as artifact identifier |
| Legitimate signatures were valid | Compared with test-file signature status |
| Test signatures returned `UnknownError` | Recorded exact result |
| Sysmon Event ID 7 unavailable | Documented telemetry gap |
| 4104 had no relevant events | Documented lack of script evidence |
| 4688 had no relevant events | Documented process telemetry gap |
| Invalid `-ErrorActionContinue` parameter | Corrected to `-ErrorAction SilentlyContinue` |
| No DLLs in searched secondary locations | Documented search result |
| No test DLL execution | Preserved safe lab boundary |

---

# Final Troubleshooting Lesson

The main lesson from Lab 59 is that suspicious filenames should trigger investigation, not an immediate malicious verdict.

A file named:

    kernel32.dll

could be:

- The legitimate Windows DLL.
- A copied legitimate DLL.
- A renamed malicious DLL.
- A fake file.
- A benign test artifact.

Only correlation of **path, metadata, content, hash, signature, process activity, image-load telemetry, and network behavior** can establish which situation applies.
