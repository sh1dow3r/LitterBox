# LitterBox
Your malware's favorite sandbox - where red teamers come to bury their payloads.

A sandbox environment designed specifically for malware development and payload testing. 

This Web Application enables red teamers to validate evasion techniques, assess detection signatures, and test implant behavior before deployment in the field. 

Think of it as your personal LitterBox for perfecting your tradecraft without leaving traces on production detection systems.

The platform provides automated analysis through an intuitive web interface, monitoring process behavior and generating comprehensive runtime analysis reports. 

This ensures your payloads work as intended before execution in target environments.

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
- Monitoring sleep patterns of a beacon processes
- Validating integrity of PE files and detecting runtime modifications

## Integrated Tools

### Static Analyzers
- [YARA](https://github.com/elastic/protections-artifacts/tree/main/yara) - Pattern matching and signature detection
- [CheckPlz](https://github.com/BlackSnufkin/CheckPlz) - AV detection testing

### Dynamic Analyzers
- [YARA](https://github.com/elastic/protections-artifacts/tree/main/yara) (memory scanning) - Runtime pattern detection
- [PE-Sieve](https://github.com/hasherezade/pe-sieve) - Process and memory inspection
- [Moneta](https://github.com/forrest-orr/moneta) - Sleep pattern analysis
- [Patriot](https://github.com/BlackSnufkin/patriot) - Runtime monitoring
- [Hunt-Sleeping-Beacons](https://github.com/thefLink/Hunt-Sleeping-Beacons) - Beacon behavior analysis

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

## Usage
### Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/litterbox.git
   cd litterbox
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Edit `config/config.yaml` to specify file paths and tool settings.


### Running the Application

```bash
python litterbox.py
```

- Accessible at `http://127.0.0.1:1337`
- Requires admin privileges for some features.


## Configuration

The `config.yml` file controls:
- Upload directory and allowed extensions
- Analysis tool paths and Command options
- YARA rule locations
- Analysis timeouts and limits



## Creating Your Own Analyzer

LitterBox supports two types of analyzers:

- **Static Analyzers**: Analyze files directly (e.g., exe, dll, docs).
- **Dynamic Analyzers**: Analyze running processes using PIDs.

---

### Step 1: Choose Your Analyzer Type

Select the type of analyzer based on the target:

```python
# For file analysis (exe, dll, docs)
from .base import StaticAnalyzer

# For process analysis (PIDs)
from .base import DynamicAnalyzer
```

### Step 2: Create Your Analyzer Class


#### Dynamic Analyzer (for PIDs):

```python
class MyProcessAnalyzer(DynamicAnalyzer):
    def analyze(self, pid):
        try:
            tool_config = self.config['analysis']['dynamic']['my_tool']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                pid=pid
            )
            
            process = subprocess.Popen(command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate()
            
            self.results = {
                'status': 'completed',
                'findings': self._parse_output(stdout),
                'errors': stderr
            }
        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }
```

### Step 3: Implement the Output Parser

```python
def _parse_output(self, output):
    findings = {
        'statistics': {},      # For the stats cards
        'detections': [],      # For detailed findings
        'total_detections': 0  # For summary view
    }
    
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            findings['statistics'][key.strip()] = value.strip()
            
    return findings
```

### Step 4: Add Configuration to `config.yml`

```yaml
analysis:
  # For file analysis tools
  static:
    my_tool:
      enabled: true
      tool_path: /path/to/tool
      command: "{tool_path} -f {file_path}"
      timeout: 300

  # For process analysis tools
  dynamic:
    my_tool:
      enabled: true
      tool_path: /path/to/tool
      command: "{tool_path} --pid {pid}"
      timeout: 300
```

### Step 5: Register Your Analyzer

In `manager.py`:

```python
def _initialize_analyzers(self):
    # For file analysis
    if self.config['analysis']['static']['my_tool']['enabled']:
        self.static_analyzers['my_tool'] = MyFileAnalyzer(self.config)
    
    # For process analysis
    if self.config['analysis']['dynamic']['my_tool']['enabled']:
        self.dynamic_analyzers['my_tool'] = MyProcessAnalyzer(self.config)
```

---

## Adding Web UI Components

### Add Your Analyzer Tab in `results.html`

```html
<!-- Add the tab button -->
<button class="tab-button text-base px-4 py-2 text-gray-300 hover:text-white border-b-2" data-tab="myToolResultsTab">
    My Tool
</button>

<!-- Add the content section -->
<div id="myToolResultsTab" class="tab-content hidden">
    <h3 class="text-xl font-medium text-gray-100">My Tool Analysis Results</h3>
    <p class="text-base text-gray-500 mb-6">Details of the static analysis performed by My Tool.</p>
    <div id="myToolStats" class="flex space-x-4 mb-6"></div>
    <div id="myToolResults" class="space-y-4"></div>
</div>
```

### Create Your Renderer in `results.js`

```javascript
tools.my_tool = {
    element: document.getElementById('myToolResults'),
    statsElement: document.getElementById('myToolStats'),
    render: (results) => {
        if (results.status === 'error') {
            tools.my_tool.element.innerHTML = `
                <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                    <div class="flex items-center space-x-2 text-red-500">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span>${results.error}</span>
                    </div>
                </div>`;
            return;
        }

        const findings = results.findings;
        const isClean = findings.total_detections === 0;

        tools.my_tool.statsElement.innerHTML = `
            <div class="grid grid-cols-3 gap-4 mb-6">
                <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-green-500/30' : 'border-red-500/30'} p-4">
                    <div class="text-sm text-gray-500">Status</div>
                    <div class="text-2xl font-semibold ${isClean ? 'text-green-500' : 'text-red-500'}">
                        ${isClean ? 'Clean' : 'Suspicious'}
                    </div>
                </div>
                <!-- Add more stat cards -->
            </div>`;

        let html = '';
        if (isClean) {
            html = `
                <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                    <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span class="text-green-500 font-medium">No threats detected</span>
                </div>`;
        } else {
            html = `<div class="space-y-4">
                ${findings.detections.map(finding => `
                    <!-- Your finding card template -->
                `).join('')}
            </div>`;
        }

        tools.my_tool.element.innerHTML = html;
    }
}
```

---

Now your analyzer's results will be displayed in the web interface following LitterBox's UI pattern! The UI components include:

- **Tab button** to access your results
- **Stats cards** showing an overview
- **Clean/Suspicious status** indicators
- **Detailed findings display**
- **Error handling**
