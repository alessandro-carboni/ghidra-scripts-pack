# Ghidra Malware Triage

A modular malware triage framework built on Ghidra automation, combining Python-based static analysis, a Go orchestration pipeline, and a Rust-powered capability and risk scoring engine.

## Goal

Transform raw static analysis output into structured triage reports through a multi-stage pipeline.

## Current Status

Step 1 completed:

- Ghidra headless execution verified
- PyGhidra script execution verified
- First raw JSON report generation implemented
- PowerShell wrapper created for repeatable local execution

## Planned Pipeline

```text
[Binary]
   ↓
PowerShell / Go CLI
   ↓
Ghidra headless + Python scripts
   ↓
raw_report.json
   ↓
Rust intelligence engine
   ↓
enriched_report.json
   ↓
Markdown report
```

---

## Current Output Example

```JSON
{
  "sample": {
    "name": "notepad.exe",
    "path": "/C:/Users/aless/Desktop/_/Programmazione/notepad.exe",
    "format": "Portable Executable (PE)"
  },
  "external_symbols": [
    "CreateFileW",
    "WriteFile",
    "CloseHandle"
  ]
}
```