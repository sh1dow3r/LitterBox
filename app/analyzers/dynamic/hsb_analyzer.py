import subprocess
import re
from .base import DynamicAnalyzer

def remove_ansi_escape_sequences(text):
    """
    Remove ANSI escape sequences (color codes, etc.) from the given text.
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

class HSBAnalyzer(DynamicAnalyzer):
    SEVERITY_LEVELS = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MID': 2,
        'LOW': 1
    }

    def analyze(self, pid):
        """
        Executes the Hunt-Sleeping-Beacons-NG tool against the given PID and parses its output.
        
        Args:
            pid (int): Process ID to analyze
            
        Returns:
            dict: Analysis results including findings and metadata
        """
        self.pid = pid
        try:
            tool_config = self.config['analysis']['dynamic']['hsb']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                pid=pid
            )

            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(timeout=tool_config['timeout'])

            # 1) Strip ANSI color codes
            stdout = remove_ansi_escape_sequences(stdout)

            # 2) Parse output
            parsed_findings = self._parse_output(stdout)
            #print(parsed_findings)
            # 3) Augment with severity counts, etc.
            self._enrich_findings(parsed_findings)

            self.results = {
                'status': 'completed' if process.returncode == 0 else 'failed',
                'findings': parsed_findings,
                'errors': stderr if stderr else None
            }

        except subprocess.TimeoutExpired:
            self.results = {
                'status': 'timeout',
                'error': f'Analysis timed out after {tool_config["timeout"]} seconds'
            }
        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }

    def _enrich_findings(self, sections):
        """Add additional metadata for frontend visualization."""
        if not sections or 'detections' not in sections:
            return
            
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MID': 0,
            'LOW': 0
        }
        
        total_findings = 0
        max_severity = 0
        
        # For each process...
        for process in sections['detections']:
            for finding in process['findings']:
                severity = finding.get('severity', 'LOW')
                severity_counts[severity] += 1
                total_findings += 1

                # Track the highest severity
                severity_score = self.SEVERITY_LEVELS.get(severity, 0)
                if severity_score > max_severity:
                    max_severity = severity_score
                
            # Process-level stats
            process['total_findings'] = len(process['findings'])
            process['max_severity'] = max_severity
            
            # Group by thread for rendering
            findings_by_thread = {}
            for finding in process['findings']:
                thread_id = finding.get('thread_id')
                if thread_id:
                    if thread_id not in findings_by_thread:
                        findings_by_thread[thread_id] = []
                    findings_by_thread[thread_id].append(finding)
            
            process['findings_by_thread'] = findings_by_thread
        
        # Summary stats
        sections['summary'].update({
            'total_findings': total_findings,
            'severity_counts': severity_counts,
            'max_severity': max_severity
        })

    def _parse_output(self, output):
        """
        Convert the raw HSB tool output into structured data.
        """
        sections = {
            'summary': {
                'duration': 0,
                'has_detections': False
            },
            'detections': []
        }
        
        current_process = None
        lines = output.splitlines()
        
        for line in lines:
            line = line.rstrip()
            if not line or line.startswith('_') or line.startswith(' _'):
                continue

            # Process header
            if line.startswith('* Detections for:'):
                match = re.search(r'\* Detections for: (.+?)\s*\(\s*(\d+)\s*\)', line)
                if match:
                    current_process = {
                        'process_name': match.group(1).strip(),
                        'pid': int(match.group(2)),
                        'findings': []
                    }
                    sections['detections'].append(current_process)

            # Finding line
            elif line.strip().startswith('!'):
                if current_process:
                    # Pass the current process name + pid into the finding
                    finding = self._parse_finding(
                        line.strip(),
                        current_process['process_name'],
                        current_process['pid']
                    )
                    if finding:
                        current_process['findings'].append(finding)
                        sections['summary']['has_detections'] = True

            # Summary stats line
            elif line.startswith('* Scanned:'):
                match = re.search(r'Scanned: (\d+) processes and (\d+) threads in (\d+\.?\d*) seconds', line)
                if match:
                    sections['summary'].update({
                        'scanned_processes': int(match.group(1)),
                        'scanned_threads': int(match.group(2)),
                        'duration': float(match.group(3))
                    })

        # ---------------------------------------------------------------------
        # NEW BLOCK: If no processes were parsed from the output (meaning the 
        # tool didn't print "* Detections for: ..." lines at all), we force-add 
        # an entry with the known PID and an empty findings list.
        # ---------------------------------------------------------------------
        if not sections['detections']:
            sections['detections'].append({
                'process_name': f"PID {self.pid}",
                'pid': self.pid,
                'findings': []
            })

        return sections


    def _parse_finding(self, line, process_name, pid):
        """
        Parse a single "!" line into structured data.
        Includes process_name and pid so the front end can reference them.
        """
        # Remove the leading "!"
        line = line[1:].strip()

        finding = {
            'process_name': process_name,
            'pid': pid,
            'type': None,
            'severity': None,
            'description': None,
            'raw_message': line,
            'details': {},
            'timestamp': self._get_timestamp()
        }

        # Remove trailing "| Severity: XYZ"
        severity_match = re.search(r'\|\s*Severity:\s*(\w+)$', line)
        if severity_match:
            finding['severity'] = severity_match.group(1)
            line = line.replace(severity_match.group(0), '').rstrip()

        # Detect "Suspicious Timer" (no thread in the line)
        if line.startswith('Suspicious Timer'):
            finding.update(self._parse_suspicious_timer(line))
            return finding

        # Otherwise, parse thread-based lines
        thread_match = re.search(r'Thread\s+(\d+)\s*\|\s*([^|]+)\s*\|\s*(.+)$', line)
        if not thread_match:
            return None

        thread_id = int(thread_match.group(1))
        finding_type = thread_match.group(2).strip()
        description = thread_match.group(3).strip()

        finding.update({
            'thread_id': thread_id,
            'type': finding_type,
            'description': description
        })

        # Type-specific details
        parser_method = f'_parse_{finding_type.lower().replace(" ", "_")}'
        if hasattr(self, parser_method):
            finding['details'].update(
                getattr(self, parser_method)(description)
            )

        return finding

    def _parse_suspicious_timer(self, line):
        """
        Parse lines that start with "Suspicious Timer ...".
        """
        details = {
            'type': 'Suspicious Timer',
            'details': {}
        }
        
        if 'pointing to' in line:
            target_match = re.search(r'pointing to ([^\s|]+)', line)
            if target_match:
                details['details']['target_function'] = target_match.group(1)
        
        # The portion after "Suspicious Timer"
        description = line.split('|')[0].replace('Suspicious Timer', '').strip()
        if '|' in line:
            description = line.split('|')[1].strip().split('|')[0].strip()
        
        details['description'] = description
        return details

    def _parse_blocking_timer_detected(self, description):
        """
        Parse lines that mention "Blocking Timer detected".
        """
        details = {}
        callback_match = re.search(r'triggered by ([^\s|]+)', description)
        if callback_match:
            details['callback_function'] = callback_match.group(1)
        return details

    def _parse_module_stomping(self, description):
        details = {}
        # This regex finds everything after "stomped module:"
        match = re.search(r'stomped module:\s*(.+)$', description, re.IGNORECASE)
        if match:
            full_module_name = match.group(1).strip()
            details['module_name'] = full_module_name

            # Optionally split hash from base name if you want:
            if '_' in full_module_name:
                parts = full_module_name.rsplit('_', 1)
                if len(parts) == 2:
                    details['hash_prefix'] = parts[0]
                    details['base_name'] = parts[1]

        return details

    def _parse_abnormal_intermodular_call(self, description):
        """
        Example input:
        "ntdll!RtlGetSystemPreferredUILanguages called KERNELBASE!WaitForSingleObjectEx. This indicates module-proxying."
        """
        details = {}
        pattern = re.compile(r'^(.+?)\s+called\s+(.+?)(?:\.\s+This\s+indicates\s+(.*))?$')
        match = pattern.search(description)
        if match:
            details['caller'] = match.group(1).strip()
            callee = match.group(2).rstrip('.').strip()
            details['callee'] = callee
            if match.group(3):
                context = match.group(3).rstrip('.').strip()
                details['context'] = context

        return details

    def _parse_return_address_spoofing(self, description):
        details = {}
        thread_num_match = re.search(r'Thread\s+(\d+)\s+returns', description)
        if thread_num_match:
            details['target_thread'] = int(thread_num_match.group(1))
        
        gadget_match = re.search(r'Gadget in:\s+([^\s|]+)', description)
        if gadget_match:
            details.update({
                'gadget_location': gadget_match.group(1),
                'technique': 'JMP gadget'
            })
        return details

    def _get_timestamp(self):
        """
        Return current UTC timestamp
        """
        from datetime import datetime
        return datetime.utcnow().isoformat()

    def cleanup(self):
        """Optional: Cleanup any artifacts if needed"""
        pass
