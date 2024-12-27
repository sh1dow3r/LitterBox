# app/analyzers/static/yara_analyzer.py
import subprocess
import re
import os
from .base import StaticAnalyzer

class YaraStaticAnalyzer(StaticAnalyzer):
    def analyze(self, file_path):
        """
        Analyzes a file using YARA rules specified in the config.
        """
        try:
            tool_config = self.config['analysis']['static']['yara']
            command = tool_config['command'].format(
                tool_path=tool_config['tool_path'],
                rules_path=tool_config['rules_path'],
                file_path=file_path
            )

            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            stdout, stderr = process.communicate(timeout=tool_config['timeout'])
            matches = self._parse_output(stdout)

            # Map the matched strings to the rule definitions
            self._map_output_to_rule_strings(matches)


            self.results = {
                'status': 'completed' if process.returncode == 0 else 'failed',
                'scan_info': {
                    'target': file_path,
                    'rules_file': tool_config['rules_path']
                },
                'matches': matches,
                'errors': stderr if stderr else None
            }

        except Exception as e:
            self.results = {
                'status': 'error',
                'error': str(e)
            }

    def _parse_rule_strings(self, rule_filepath, rule_name):
        """
        Parse a YARA rule file to extract string definitions for a specific rule.
        """
        strings = {}
        try:
            with open(rule_filepath, 'r') as f:
                lines = f.readlines()

            inside_rule = False
            for line in lines:
                stripped = line.strip()

                if stripped.startswith(f"rule {rule_name}"):
                    inside_rule = True
                elif inside_rule and stripped.startswith("strings:"):
                    continue
                elif inside_rule and stripped.startswith("$"):
                    match = re.match(r'^\$([a-zA-Z0-9_]+)\s*=\s*("(.*?)"|{.*?})', stripped)
                    if match:
                        identifier = match.group(1)
                        value = match.group(2).strip()
                        strings[identifier] = value
                elif inside_rule and stripped.startswith("condition:"):
                    break

        except Exception as e:
            print(f"Error parsing rule file: {e}")

        return strings

    def _map_output_to_rule_strings(self, matches):
        """
        Map strings from the YARA output to their definitions in the rule file.
        """
        for match in matches:
            rule_name = match['rule']
            rule_filepath = match['metadata'].get('rule_filepath')
            if not rule_filepath:
                continue

            rule_strings = self._parse_rule_strings(rule_filepath, rule_name)

            for string in match['strings']:
                identifier = string['identifier'].lstrip('$')
                if identifier in rule_strings:
                    # Replace raw data with mapped definition
                    string['data'] = rule_strings[identifier]

    def _parse_output(self, output):
        """
        Parse the YARA scan output and extract matches with their details.
        """
        matches = []
        current_match = None
        current_strings = []
        lines = output.split('\n')

        for line in lines:
            line = line.strip()
            if not line or line.startswith('YARA Scan Results') or line == 'Static pattern matching analysis results.':
                continue

            if '[' in line and ']' in line and ' [author=' in line:
                if current_match:
                    current_match['strings'] = current_strings
                    matches.append(current_match)
                    current_strings = []

                try:
                    before_bracket = line.split(' [', 1)
                    rule_name = before_bracket[0].strip()

                    bracket_content = line[line.find('[')+1:line.rfind(']')]
                    target = line[line.rfind(']')+1:].strip()

                    metadata = self._parse_metadata(bracket_content)
                    metadata['rule_filepath'] = self._get_rule_filepath(metadata.get('threat_name'))

                    current_match = {
                        'rule': rule_name,
                        'metadata': metadata,
                        'strings': [],
                        'target_file': target
                    }
                except Exception as e:
                    print(f"Error parsing rule line: {e}")
                    continue

            elif line.startswith('0x'):
                try:
                    parts = line.split(':', 2)
                    if len(parts) >= 2:
                        offset = parts[0].strip()
                        identifier = parts[1].strip()
                        string_data = parts[2].strip() if len(parts) > 2 else ''

                        current_strings.append({
                            'offset': offset,
                            'identifier': identifier,
                            'data': string_data
                        })
                except Exception as e:
                    print(f"Error parsing string match: {e}")
                    continue

        if current_match:
            current_match['strings'] = current_strings
            matches.append(current_match)

        return matches

    def _parse_metadata(self, metadata_str):
        """
        Parse the metadata section from YARA rule match, including essential fields
        and the path to the triggered rule file.
        """
        metadata = {}
        essential_fields = {'id', 'creation_date', 'threat_name', 'severity'}

        pairs = re.findall(r'([^,\s]+?)\s*=\s*(?:"([^\"]+)"|(\d+)|([^,\s]+))', metadata_str)
        for pair in pairs:
            key = pair[0]
            if key in essential_fields:
                value = next(v for v in pair[1:] if v)
                if key == 'severity':
                    try:
                        value = int(value)
                    except ValueError:
                        value = 0
                metadata[key] = value

        return metadata

    def _get_rule_filepath(self, threat_name):
        """
        Convert threat_name to corresponding rule filepath using the config's rules_path.
        """
        if not threat_name:
            return None

        rules_dir = os.path.dirname(self.config['analysis']['static']['yara']['rules_path'])
        rule_filename = threat_name.replace('.', '_')
        if not rule_filename.endswith('.yar'):
            rule_filename += '.yar'

        return os.path.join(rules_dir, rule_filename)

    def cleanup(self):
        """
        No cleanup needed as process management is handled by manager.
        """
        pass
