# app/analyzers/dynamic/patriot_analyzer.py

import subprocess
import re
from .base import DynamicAnalyzer

class PatriotAnalyzer(DynamicAnalyzer):
    def analyze(self, pid):
        """
        Executes the Patriot tool against the given PID and parses its output,
        then prints the parsed findings to the console.
        """
        self.pid = pid
        try:
            tool_config = self.config['analysis']['dynamic']['patriot']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                pid=pid
            )

            # Run the Patriot tool
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(timeout=tool_config['timeout'])

            # Parse the output into structured data
            parsed_findings = self._parse_output(stdout)

            self.results = {
                'status': 'completed' if process.returncode == 0 else 'failed',
                'findings': parsed_findings,
                'errors': stderr if stderr else None
            }

        except Exception as e:
            # On any error (timeout, parse issue, etc.), record it
            self.results = {
                'status': 'error',
                'error': str(e)
            }

    def cleanup(self):
        """
        If Patriot leaves behind any artifacts or child processes, handle them here.
        Otherwise, no action needed.
        """
        pass

    def _parse_output(self, output):
        sections = {
            'header': {},
            'process_info': {},
            'memory_stats': {},
            'scan_summary': {},
            'findings': []
        }

        MEMORY_PROTECTION_FLAGS = {
            0x01: "PAGE_NOACCESS",
            0x02: "PAGE_READONLY",
            0x04: "PAGE_READWRITE",
            0x08: "PAGE_WRITECOPY",
            0x10: "PAGE_EXECUTE",
            0x20: "PAGE_EXECUTE_READ",
            0x40: "PAGE_EXECUTE_READWRITE",
            0x80: "PAGE_EXECUTE_WRITECOPY",
            0x100: "PAGE_GUARD",
            0x200: "PAGE_NOCACHE",
            0x400: "PAGE_WRITECOMBINE"
        }
        current_section = None
        current_finding = None
        lines = output.splitlines()
        collecting_module_info = False
        
        for line in lines:
            line = line.rstrip()  # Keep leading spaces but remove trailing
            if not line:
                continue

            if line.startswith('== Patriot Memory Scanner =='):
                current_section = 'header'
            elif line == '=== Process Information ===':
                current_section = 'process_info'
            elif line == '=== Memory Statistics ===':
                current_section = 'memory_stats'
            elif line == '=== Scan Summary ===':
                current_section = 'scan_summary'
            elif line == '=== Detailed Findings ===':
                current_section = 'detailed_findings'
            elif line.startswith('--- Finding #'):
                if current_finding:
                    sections['findings'].append(current_finding)
                current_finding = {'finding_number': int(re.search(r'#(\d+)', line).group(1))}
                collecting_module_info = False
            else:
                if current_finding is not None:
                    if line.startswith('Level:'):
                        current_finding['level'] = line.split(':')[1].strip()
                    elif line.startswith('Type:'):
                        current_finding['type'] = line.split(':')[1].strip()
                    elif line.startswith('Process:'):
                        process_info = line.split(':', 1)[1].strip()
                        match = re.search(r'(.+?)\s*\(PID:\s*(\d+)\)', process_info)
                        if match:
                            current_finding['process_name'] = match.group(1).strip()
                            current_finding['pid'] = int(match.group(2))
                    elif line.startswith('Details:'):
                        details = line.split(':', 1)[1].strip()
                        current_finding['details'] = details
                        finding_type = current_finding.get('type', '')
                        
                        if finding_type == 'CONTEXT':
                            match = re.search(r'Target:\s*([\da-fA-F]+)', details)
                            if match:
                                target = match.group(1)
                                current_finding['parsed_details'] = {
                                    'target': target,
                                    'target_decimal': int(target, 16)
                                }
                        elif finding_type == 'peIntegrity':
                            match = re.search(r'Executable\s+region\s+([\da-fA-F]+)', details)
                            if match:
                                region = match.group(1)
                                current_finding['parsed_details'] = {
                                    'region_address': region,
                                    'region_decimal': int(region, 16)
                                }
                        elif finding_type == 'elevatedUnbackedExecute':
                            try:
                                base_match = re.search(r'Base:\s+([\da-fA-F]+)', details)
                                protection_match = re.search(r'Protection:\s+([\da-fA-F]+)', details)
                                size_match = re.search(r'Size:\s+([\da-fA-F]+)', details)
                                
                                if base_match and protection_match and size_match:
                                    base = base_match.group(1)
                                    protection = protection_match.group(1)
                                    size = size_match.group(1)
                                    
                                    protection_int = int(protection, 16)
                                    protection_flags = []
                                    
                                    # Convert protection value to human-readable flags
                                    for flag_value, flag_name in MEMORY_PROTECTION_FLAGS.items():
                                        if protection_int & flag_value:
                                            protection_flags.append(flag_name)
                                    
                                    current_finding['parsed_details'] = {
                                        'base': base.zfill(16),
                                        'base_decimal': int(base, 16),
                                        'protection': protection.zfill(8),
                                        'protection_decimal': protection_int,
                                        'protection_flags': protection_flags if protection_flags else ["UNKNOWN"],
                                        'size': size.zfill(16),
                                        'size_decimal': int(size, 16)
                                    }
                            except (AttributeError, ValueError) as e:
                                current_finding['parsed_details'] = None


                    elif line.startswith('Timestamp:'):
                        current_finding['timestamp'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Module Information:'):
                        current_finding['module_information'] = {}
                        collecting_module_info = True
                    elif collecting_module_info and line.startswith('  '):
                        # Handle module information with proper indent preservation
                        key, value = line.strip().split(':', 1)
                        current_finding['module_information'][key.strip()] = value.strip()
                else:
                    if line.startswith('PID:'):
                        sections['process_info']['pid'] = int(line.split(':')[1].strip())
                    elif line.startswith('Process Name:'):
                        sections['process_info']['process_name'] = line.split(':')[1].strip()
                    elif line.startswith('Elevation Status:'):
                        sections['process_info']['elevation_status'] = line.split(':')[1].strip()
                    elif line.startswith('Total Memory Regions:'):
                        sections['memory_stats']['total_regions'] = int(line.split(':')[1].strip())
                    elif line.startswith('Total Private Memory:'):
                        value = line.split(':')[1].strip().replace('MB', '').strip()
                        sections['memory_stats']['private_memory'] = float(value)
                    elif line.startswith('Total Executable Memory:'):
                        value = line.split(':')[1].strip().replace('MB', '').strip()
                        sections['memory_stats']['executable_memory'] = float(value)
                    elif line.startswith('Scan Duration:'):
                        value = line.split(':')[1].strip().replace('seconds', '').strip()
                        sections['scan_summary']['duration'] = float(value)
                    elif line.startswith('Total Findings:'):
                        sections['scan_summary']['total_findings'] = int(line.split(':')[1].strip())

        # Add last finding if exists
        if current_finding:
            sections['findings'].append(current_finding)

        return sections