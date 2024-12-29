# app/analyzers/static/checkplz_analyzer.py

import subprocess
import re
import os
from .base import StaticAnalyzer

class CheckPlzAnalyzer(StaticAnalyzer):
    def analyze(self, file_path):
        """
        Analyzes a file using ThreatCheck tool specified in the config.
        """
        try:
            tool_config = self.config['analysis']['static']['checkplz']
            command = tool_config['command'].format(
                tool_path=os.path.abspath(tool_config['tool_path']),
                file_path=os.path.abspath(file_path)
            )

            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                cwd=os.path.dirname(os.path.abspath(tool_config['tool_path']))  # Added working directory
            )

            stdout, stderr = process.communicate(timeout=tool_config.get('timeout', 300))
            results = self._parse_output(stdout)

            self.results = {
                'status': 'completed' if process.returncode == 0 else 'failed',
                'scan_info': {
                    'target': file_path,
                    'tool': 'CheckPlz'
                },
                'findings': results,
                'errors': stderr if stderr else None
            }

        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }
        
    def _parse_output(self, output):
        """
        Parse the ThreatCheck output into structured data.
        """
        results = {
            'initial_threat': None,
            'scan_results': {
                'file_path': None,
                'file_size': None,
                'scan_duration': None,
                'search_iterations': None,
                'detection_offset': None,
                'relative_location': None,
                'final_threat_detection': None,
                'hex_dump': None
            }
        }

        if not output:
            return results

        lines = output.splitlines()
        current_section = None
        hex_dump_lines = []

        for line in lines:
            line = line.strip()

            if not line:
                continue

            # Detect file path and size on clean scans
            if line.startswith("File Path:"):
                results['scan_results']['file_path'] = line.split(":", 1)[1].strip()
                continue

            if line.startswith("File Size:"):
                results['scan_results']['file_size'] = line.split(":", 1)[1].strip()
                continue

            # Initial threat detection
            if "Threat found in the original file:" in line:
                results['initial_threat'] = line.split(":", 1)[1].strip()
                continue

            # Start of results section
            if "Windows Defender Scan Results" in line:
                current_section = "results"
                continue

            # Start of hex dump section
            if "Hex Dump Analysis" in line:
                current_section = "hex_dump"
                continue

            # Skip separator lines
            if all(c in "=-" for c in line):
                continue

            # Parse main results section
            if current_section == "results" and ":" in line:
                key, value = [x.strip() for x in line.split(":", 1)]

                if "Scan Duration" in key:
                    try:
                        results['scan_results']['scan_duration'] = float(value.replace('s', ''))
                    except (ValueError, TypeError):
                        results['scan_results']['scan_duration'] = value
                elif "Search Iterations" in key:
                    try:
                        results['scan_results']['search_iterations'] = int(value)
                    except (ValueError, TypeError):
                        results['scan_results']['search_iterations'] = value
                elif "Detection Offset" in key:
                    results['scan_results']['detection_offset'] = value
                elif "Relative Location" in key:
                    results['scan_results']['relative_location'] = value
                elif "Final threat detection" in key:
                    results['scan_results']['final_threat_detection'] = value

            # Collect hex dump
            elif current_section == "hex_dump" and not line.startswith("Showing"):
                hex_dump_lines.append(line)

        if hex_dump_lines:
            results['scan_results']['hex_dump'] = '\n'.join(hex_dump_lines)

        return results


    def cleanup(self):
        """
        Cleanup any temporary files or processes.
        """
        pass