# LitterBox
Your malware's favorite sandbox - where red teamers come to bury their payloads.
A sandbox environment designed specifically for malware development and payload testing. This framework enables red teamers to validate evasion techniques, assess detection signatures, and test implant behavior before deployment in the field. Think of it as your personal LitterBox for perfecting your tradecraft without leaving traces on production detection systems.

The platform provides automated analysis through an intuitive web interface, monitoring process behavior and generating comprehensive runtime analysis reports. This ensures your payloads work as intended before execution in target environments.


## Core Features

### Initial Analysis
Upon file upload, LitterBox automatically performs:
- File identification and hashing (MD5, SHA256)
- Shannon entropy calculation
- File type detection and MIME analysis
- Original filename preservation
- Upload timestamp recording

### PE File Analysis
For executables (.exe, .dll, .sys):
- File type detection (PE32/PE32+)
- Machine type identification
- Compilation timestamp extraction
- Subsystem identification
- Entry point location
- Section enumeration
- Import DLL listing

### Office Document Analysis
For Office files (.docx, .xlsx, .doc, .xls, .xlsm, .docm):
- Macro detection
- VBA code analysis (if macros present)

## Analysis Options

### Static Analysis
- Scanning binaries against known detection signatures and rulesets
- Analyzing file characteristics and entropy levels for suspicious indicators
- Strings analyzing to locate strings that can serve as suspicious indicators

### Dynamic Analysis
Supports two modes: File, PID
- Scanning executable files and processes to identify suspicious behavioral characteristics  
- Inspecting memory regions to detect anomalous content and hidden payloads
- Analyzing process hollowing and injection techniques for detection artifacts 
- Monitoring sleep patterns of beacon processes
- Validating integrity of PE files and detecting runtime modifications

## Integrated Tools

### Static Analyzers
- YARA - Pattern matching and signature detection
- CheckPlz (ThreatCheck) - AV detection testing

### Dynamic Analyzers
- YARA (memory scanning) - Runtime pattern detection
- PE-Sieve - Process and memory inspection
- Moneta - Sleep pattern analysis
- Patriot - Runtime monitoring
- Hunt-Sleeping-Beacons - Beacon behavior analysis

## API Reference

### File Operations
```http
POST /upload                   # Upload files for analysis
GET  /analyze/static/<hash>    # Static file analysis
POST /analyze/dynamic/<hash>   # Dynamic file analysis
POST /analyze/dynamic/<pid>    # Process analysis
```

### System Management
```http
GET  /health                  # System health and tool status check
POST /cleanup                # Clean analysis artifacts and uploads
POST /validate/<pid>         # Validate process accessibility
```

## Configuration

The `config.yml` file controls:
- Upload directory and allowed extensions
- Analysis tool paths and options
- YARA rule locations
- Analysis timeouts and limits
