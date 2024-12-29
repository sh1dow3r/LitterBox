# LitterBox

LitterBox provides automated analysis of payloads and malware through an intuitive web interface. The platform streamlines pre-deployment testing by validating evasion techniques, monitoring process behavior, and generating comprehensive runtime analysis reports. Designed for validating tradecraft, it enables rapid testing of payloads against common detection mechanisms before execution in target environments.

## Core Features

### Initial Analysis
Upon file upload, LitterBox automatically performs:
- File identification and hashing (MD5, SHA256)
- Shannon entropy calculation
- File type detection and MIME analysis
- Original filename preservation
- Upload timestamp recording

### Analysis Options

#### PE File Analysis
For executables (.exe, .dll, .sys):
- File type detection (PE32/PE32+)
- Machine type identification
- Compilation timestamp extraction
- Subsystem identification
- Entry point location
- Section enumeration
- Import DLL listing

#### Office Document Analysis
For Office files (.docx, .xlsx, .doc, .xls, .xlsm, .docm):
- Macro detection
- VBA code analysis (if macros present)

#### Static Analysis
# Static Analysis
- Scanning binaries against known detection signatures and rulesets
- Analyzing file characteristics and entropy levels for suspicious indicators
- Extracting and validating metadata from executables and documents
- Evaluating PE headers and structures for signs of manipulation


#### Dynamic Analysis
Supports two modes:
- Scanning executable files and processes to identify suspicious behavioral characteristics  
- Inspecting memory regions to detect anomalous content and hidden payloads
- Analyzing process hollowing and injection techniques for detection artifacts 
- Monitoring sleep patterns and network behavior of beacon processes
- Validating integrity of PE files and detecting runtime modifications


## API Endpoints

### File Operations
- `POST /upload` - Upload files for analysis
- `GET /analyze/static/<hash>` - Static file analysis
- `POST /analyze/dynamic/<hash>` - Dynamic file analysis
- `POST /analyze/dynamic/<pid>` - Process analysis

### System Management
- `GET /health` - System health and tool status check
- `POST /cleanup` - Clean analysis artifacts and uploads
- `POST /validate/<pid>` - Validate process accessibility
