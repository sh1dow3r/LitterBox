# app/routes.py
import datetime
import glob
import hashlib
import math
import mimetypes
import os
import shutil
import psutil
import pefile
import json
from .analyzers.manager import AnalysisManager
from flask import render_template, request, jsonify
from werkzeug.utils import secure_filename
from oletools.olevba import VBA_Parser

def allowed_file(filename, config):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in config['upload']['allowed_extensions']

def calculate_entropy(data):
    """Calculate Shannon entropy of data with detection insights"""
    if len(data) == 0:
        return 0
    
    # Convert to bytes if not already
    if isinstance(data, str):
        data = data.encode()

    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1

    # Calculate entropy
    entropy = 0
    for count in byte_counts.values():
        p_x = count / len(data)
        entropy += -p_x * math.log2(p_x)

    return round(entropy, 2)

def get_pe_info(filepath):
    """Enhanced PE file analysis with deep import analysis and detection vectors"""
    try:
        pe = pefile.PE(filepath)
        
        # Enhanced section analysis
        sections_info = []
        suspicious_imports = []
        high_risk_imports = {
            'kernel32.dll': {
                'createremotethread': 'Process Injection capability detected',
                'virtualallocex': 'Memory allocation in remote process detected',
                'writeprocessmemory': 'Process memory manipulation detected',
                'getprocaddress': 'Dynamic API resolution - possible evasion technique',
                'loadlibrarya': 'Dynamic library loading - possible evasion technique',
                'openprocess': 'Process manipulation capability',
                'createtoolhelp32snapshot': 'Process enumeration capability',
                'process32first': 'Process enumeration capability',
                'process32next': 'Process enumeration capability'
            },
            'user32.dll': {
                'getasynckeystate': 'Potential keylogging capability',
                'getdc': 'Screen capture capability',
                'getforegroundwindow': 'Window/Process monitoring capability'
            },
            'wininet.dll': {
                'internetconnect': 'Network communication capability',
                'internetopen': 'Network communication capability',
                'ftpputfile': 'FTP upload capability',
                'ftpopenfile': 'FTP communication capability'
            },
            'urlmon.dll': {
                'urldownloadtofile': 'File download capability'
            }
        }
        """
        https://practicalsecurityanalytics.com/threat-hunting-with-function-imports/
        """
        # Check imports for suspicious behavior
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode().lower()
                
                # Check each imported function
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode().lower()
                        
                        # Check if this is a high-risk import
                        if dll_name in high_risk_imports and func_name in high_risk_imports[dll_name]:
                            suspicious_imports.append({
                                'dll': dll_name,
                                'function': func_name,
                                'note': high_risk_imports[dll_name][func_name],
                                'hint': imp.hint if hasattr(imp, 'hint') else 0
                            })
        
        """
        https://practicalsecurityanalytics.com/file-entropy/
        """
        # Section Analysis with entropy
        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            section_data = section.get_data()
            section_entropy = calculate_entropy(section_data)
            
            # Standard PE sections
            standard_sections = ['.text', '.data', '.bss', '.rdata', '.edata', '.idata', '.pdata', '.reloc', '.rsrc', '.tls', '.debug']
            is_standard = section_name in standard_sections
            
            sections_info.append({
                'name': section_name,
                'entropy': section_entropy,
                'size': len(section_data),
                'characteristics': section.Characteristics,
                'is_standard': is_standard,
                'detection_notes': []
            })
            
            # Add section-specific detection notes
            if section_entropy > 7.2:
                sections_info[-1]['detection_notes'].append('High entropy may trigger detection')
            if section_name == '.text' and section_entropy > 7.0:
                sections_info[-1]['detection_notes'].append('Unusual entropy for code section')
            if not is_standard:
                sections_info[-1]['detection_notes'].append('Non-standard section name - may trigger detection')

        """
        https://practicalsecurityanalytics.com/pe-checksum/
        """
        # Check PE Checksum
        is_valid_checksum = pe.verify_checksum()
        calculated_checksum = pe.generate_checksum()
        stored_checksum = pe.OPTIONAL_HEADER.CheckSum
        
        info = {
            'file_type': 'PE32+ executable' if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 'PE32 executable',
            'machine_type': pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine].replace('IMAGE_FILE_MACHINE_', ''),
            'compile_time': datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S'),
            'subsystem': pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem].replace('IMAGE_SUBSYSTEM_', ''),
            'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'sections': sections_info,
            'imports': list(set(entry.dll.decode() for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))),
            'suspicious_imports': suspicious_imports,
            'detection_notes': [],
            'checksum_info': {
                'is_valid': is_valid_checksum,
                'stored_checksum': hex(stored_checksum),
                'calculated_checksum': hex(calculated_checksum),
                'needs_update': calculated_checksum != stored_checksum
            }
        }
        
        # Add overall detection insights
        if not is_valid_checksum:
            info['detection_notes'].append('Invalid PE checksum - Common in modified/packed files (~83% correlation with malware)')

        if suspicious_imports:
            info['detection_notes'].append(f'Found {len(suspicious_imports)} suspicious API imports - Review import analysis')
            
        if any(section['entropy'] > 7.2 for section in sections_info):
            info['detection_notes'].append('High entropy sections detected - Consider entropy reduction techniques')
        
        if '.text' in [section['name'] for section in sections_info]:
            text_section = next(s for s in sections_info if s['name'] == '.text')
            if text_section['entropy'] > 7.0:
                info['detection_notes'].append('Packed/encrypted code section may trigger heuristics')

        if any(not section['is_standard'] for section in sections_info):
            info['detection_notes'].append('Non-standard PE sections detected - May trigger static analysis')
                
        pe.close()
        return {'pe_info': info}
    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return {'pe_info': None}

def get_office_info(filepath):
    """Enhanced Office document analysis with detection insights"""
    try:
        vbaparser = VBA_Parser(filepath)
        detection_notes = []
        
        info = {
            'file_type': 'Microsoft Office Document',
            'has_macros': vbaparser.detect_vba_macros(),
            'macro_info': None,
            'detection_notes': detection_notes
        }
        
        if vbaparser.detect_vba_macros():
            macro_analysis = vbaparser.analyze_macros()
            info['macro_info'] = macro_analysis
            
            # Analyze macros for detection vectors
            macro_text = str(macro_analysis).lower()
            detection_patterns = {
                'shell': 'Shell command execution detected',
                'wscript': 'WScript execution detected',
                'powershell': 'PowerShell execution detected',
                'http': 'Network communication detected',
                'auto': 'Auto-execution mechanism detected',
                'document_open': 'Document open auto-execution',
                'windowshide': 'Hidden window execution',
                'createobject': 'COM object creation detected'
            }
            
            for pattern, note in detection_patterns.items():
                if pattern in macro_text:
                    detection_notes.append(note)
        
        vbaparser.close()
        return {'office_info': info}
    except Exception as e:
        print(f"Error analyzing Office file: {e}")
        return {'office_info': None}

def save_uploaded_file(file, upload_folder, result_folder):
    file_content = file.read()
    file.close()
    md5_hash = hashlib.md5(file_content).hexdigest()
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    
    original_filename = secure_filename(file.filename)
    extension = os.path.splitext(original_filename)[1].lower()
    filename = f"{md5_hash}_{original_filename}"
    
    os.makedirs(upload_folder, exist_ok=True)
    filepath = os.path.join(upload_folder, filename)
    os.makedirs(result_folder, exist_ok=True)
    os.makedirs(os.path.join(result_folder, filename), exist_ok=True)
    
    with open(filepath, 'wb') as f:
        f.write(file_content)

    entropy_value = calculate_entropy(file_content)
    
    file_info = {
        'original_name': original_filename,
        'md5': md5_hash,
        'sha256': sha256_hash,
        'size': len(file_content),
        'extension': extension,
        'mime_type': mimetypes.guess_type(original_filename)[0] or 'application/octet-stream',
        'upload_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'entropy': entropy_value,
        'entropy_analysis': {
            'value': entropy_value,
            'detection_risk': 'High' if entropy_value > 7.2 else 
                            'Medium' if entropy_value > 6.8 else 'Low',
            'notes': []
        }
    }
    
    # Add entropy-based detection notes
    if entropy_value > 7.2:
        file_info['entropy_analysis']['notes'].append(
            'High entropy indicates encryption/packing - consider entropy reduction')
    elif entropy_value > 6.8:
        file_info['entropy_analysis']['notes'].append(
            'Moderate entropy - may trigger basic detection')
    
    # Add specific file type information for PE files
    if extension in ['.exe', '.dll', '.sys']:
        file_info.update(get_pe_info(filepath))

    # Add specific file type information for Office documents
    if extension in ['.docx', '.xlsx', '.doc', '.xls', '.xlsm', '.docm']:
        office_result = get_office_info(filepath)
        if 'error' in office_result:
            print(f"Warning: {office_result['error']}")
        file_info.update(office_result)

    # save file info to result folder
    with open(os.path.join(result_folder, filename, 'file_info.json'), 'w') as f:
        json.dump(file_info, f)

    return file_info

def find_file_by_hash(file_hash, upload_folder):
    for filename in os.listdir(upload_folder):
        if filename.startswith(file_hash):
            return os.path.join(upload_folder, filename)
    return None

def check_tool(tool_path):
    """Check if a tool is accessible and presumably executable."""
    return os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)


def validate_pid(pid):
    """
    Validate if a PID exists and is accessible.
    
    Args:
        pid (int): Process ID to validate
        
    Returns:
        tuple: (bool, str) - (is_valid, error_message)
    """
    try:
        pid = int(pid)
        if pid <= 0:
            return False, "Invalid PID: must be a positive integer"
            
        # Check if process exists
        if not psutil.pid_exists(pid):
            return False, f"Process with PID {pid} does not exist"
            
        # Try to get process info to check accessibility
        try:
            process = psutil.Process(pid)
            process.name()  # Try to access process name to verify permissions
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return False, f"Cannot access process {pid}: {str(e)}"
            
        return True, None
        
    except ValueError:
        return False, "Invalid PID: must be a number"
    except Exception as e:
        return False, f"Error validating PID: {str(e)}"


def get_entropy_risk_level(entropy):
    if entropy > 7.2:
        return 'High'
    elif entropy > 6.8:
        return 'Medium'
    return 'Low'

def format_hex(value):
    if isinstance(value, str) and value.startswith('0x'):
        return value.lower()
    try:
        return f"0x{int(value):x}"
    except (ValueError, TypeError):
        return str(value)

def calculate_file_risk(file_info, static_results=None, dynamic_results=None):
    """
    Calculate overall file risk score based on all available analysis results.
    Returns a tuple of (risk_score, risk_factors) where:
    - risk_score is a float between 0 and 100
    - risk_factors is a list of contributing risk factors
    """
    risk_score = 0
    risk_factors = []
    
    # Base weights for different analysis types
    WEIGHTS = {
        'pe_info': 0.3,
        'static': 0.3,
        'dynamic': 0.4
    }
    
    # 1. PE Information Risk Calculation
    if file_info.get('pe_info'):
        pe_risk = 0
        pe_info = file_info['pe_info']
        
        # Check section entropy
        high_entropy_sections = 0
        for section in pe_info.get('sections', []):
            if section.get('entropy', 0) > 7.2:  # High risk threshold
                high_entropy_sections += 1
                risk_factors.append(f"High entropy in section {section.get('name', 'UNKNOWN')}")
        
        pe_risk += min(high_entropy_sections * 20, 40)  # Cap at 40 points
        
        # Check suspicious imports
        suspicious_imports = len(pe_info.get('suspicious_imports', []))
        if suspicious_imports > 0:
            pe_risk += min(suspicious_imports * 10, 30)  # Cap at 30 points
            risk_factors.append(f"Found {suspicious_imports} suspicious imports")
        
        # Check checksum mismatch
        if pe_info.get('checksum_info'):
            checksum = pe_info['checksum_info']
            if checksum.get('stored_checksum') != checksum.get('calculated_checksum'):
                pe_risk += 30
                risk_factors.append("PE checksum mismatch detected")
        
        risk_score += (pe_risk / 100) * WEIGHTS['pe_info'] * 100

    # 2. Static Analysis Risk Calculation
    if static_results:
        static_risk = 0
        
        # YARA detections (static)
        yara_matches = static_results.get('yara', {}).get('matches', [])
        unique_yara_rules = len({match.get('rule') for match in yara_matches if match.get('rule')})
        if unique_yara_rules > 0:
            static_risk += min(unique_yara_rules * 15, 50)  # Cap at 50 points
            risk_factors.append(f"Found {unique_yara_rules} YARA rule matches (static)")
        
        # CheckPLZ findings
        checkplz_findings = static_results.get('checkplz', {}).get('findings', {})
        if checkplz_findings.get('initial_threat'):
            static_risk += 50
            risk_factors.append("CheckPLZ detected initial threat indicators")
        
        risk_score += (static_risk / 100) * WEIGHTS['static'] * 100

    # 3. Dynamic Analysis Risk Calculation
    if dynamic_results:
        dynamic_risk = 0
        
        # YARA detections (dynamic)
        yara_matches = dynamic_results.get('yara', {}).get('matches', [])
        unique_yara_rules = len({match.get('rule') for match in yara_matches if match.get('rule')})
        if unique_yara_rules > 0:
            dynamic_risk += min(unique_yara_rules * 15, 40)  # Cap at 40 points
            risk_factors.append(f"Found {unique_yara_rules} YARA rule matches (dynamic)")
        
        # PE-Sieve detections
        pesieve_suspicious = int(dynamic_results.get('pe_sieve', {})
            .get('findings', {}).get('total_suspicious', 0))
        if pesieve_suspicious > 0:
            dynamic_risk += min(pesieve_suspicious * 20, 40)  # Cap at 40 points
            risk_factors.append(f"PE-Sieve found {pesieve_suspicious} suspicious indicators")
        
        # Moneta memory anomalies
        moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
        memory_anomalies = sum([
            int(moneta_findings.get('total_private_rwx', 0) or 0),
            int(moneta_findings.get('total_private_rx', 0) or 0),
            int(moneta_findings.get('total_modified_code', 0) or 0),
            int(moneta_findings.get('total_heap_executable', 0) or 0),
            int(moneta_findings.get('total_modified_pe_header', 0) or 0),
            int(moneta_findings.get('total_inconsistent_x', 0) or 0),
            int(moneta_findings.get('total_missing_peb', 0) or 0),
            int(moneta_findings.get('total_mismatching_peb', 0) or 0)
        ])
        if memory_anomalies > 0:
            dynamic_risk += min(memory_anomalies * 10, 30)  # Cap at 30 points
            risk_factors.append(f"Found {memory_anomalies} memory anomalies")
        
        # Patriot detections
        patriot_findings = len(dynamic_results.get('patriot', {})
            .get('findings', {}).get('findings', []))
        if patriot_findings > 0:
            dynamic_risk += min(patriot_findings * 15, 30)  # Cap at 30 points
            risk_factors.append(f"Found {patriot_findings} suspicious behaviors")
        
        # HSB detections
        hsb_findings = dynamic_results.get('hsb', {}).get('findings', {})
        if hsb_findings and hsb_findings.get('detections'):
            hsb_detections = len(hsb_findings['detections'][0].get('findings', []))
            if hsb_detections > 0:
                dynamic_risk += min(hsb_detections * 20, 40)  # Cap at 40 points
                risk_factors.append(f"Found {hsb_detections} HSB detections")
        
        risk_score += (dynamic_risk / 100) * WEIGHTS['dynamic'] * 100
    
    # Normalize final score to 0-100 range and round to 2 decimal places
    risk_score = round(min(max(risk_score, 0), 100), 2)
    
    return risk_score, risk_factors

def get_risk_level(risk_score):
    """
    Convert numerical risk score to categorical risk level
    """
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    else:
        return "Low"


def register_routes(app):
    analysis_manager = AnalysisManager(app.config)

    @app.route('/')
    def index():
        return render_template('upload.html')

    @app.route('/upload', methods=['POST'])
    def upload_file():
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file and allowed_file(file.filename, app.config):
            try:
                file_info = save_uploaded_file(file, app.config['upload']['upload_folder'], app.config['upload']['result_folder'])
                return jsonify({
                    'message': 'File uploaded successfully',
                    'file_info': file_info
                }), 200
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        return jsonify({'error': 'File type not allowed'}), 400
    
    @app.route('/validate/<pid>', methods=['POST'])
    def validate_process(pid):
        """Endpoint just for PID validation"""
        is_valid, error_msg = validate_pid(pid)
        if not is_valid:
            return jsonify({'error': error_msg}), 404
        return jsonify({'status': 'valid'}), 200
    
    @app.route('/analyze/<analysis_type>/<target>', methods=['GET', 'POST'])
    def analyze_file(analysis_type, target):
        try:
            is_pid = False
            file_path = None

            # Check if this is a PID-based analysis
            if analysis_type == 'dynamic' and target.isdigit():
                is_pid = True
                # Validate PID before proceeding
                is_valid, error_msg = validate_pid(target)
                if not is_valid:
                    return jsonify({'error': error_msg}), 404
            else:
                # Look for file as before
                file_path = find_file_by_hash(target, app.config['upload']['upload_folder'])
                result_path = find_file_by_hash(target, app.config['upload']['result_folder'])
                if not file_path:
                    return jsonify({'error': 'File not found'}), 404
            if request.method == 'GET':
                return render_template('results.html', 
                                    analysis_type=analysis_type,
                                    file_hash=target)

            # POST request - perform analysis
            if analysis_type == 'static':
                if is_pid:
                    return jsonify({'error': 'Cannot perform static analysis on PID'}), 400
                results = analysis_manager.run_static_analysis(file_path)
                # save results to result folder
                with open(os.path.join(result_path, 'static_analysis_results.json'), 'w') as f:
                    json.dump(results, f)
            elif analysis_type == 'dynamic':
                target_for_analysis = target if is_pid else file_path
                results = analysis_manager.run_dynamic_analysis(target_for_analysis, is_pid)
                # save results to result folder
                with open(os.path.join(result_path, 'dynamic_analysis_results.json'), 'w') as f:
                    json.dump(results, f)
            else:
                return jsonify({'error': 'Invalid analysis type'}), 400

            return jsonify({
                'status': 'success',
                'results': results
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/file/<target>/<analysis_type>', methods=['GET'])
    def get_analysis_results(target, analysis_type):
        try:
            result_path = find_file_by_hash(target, app.config['upload']['result_folder'])
            if not result_path:
                return render_template('error.html', error='Results not found'), 404

            # Load file info
            file_info_path = os.path.join(result_path, 'file_info.json')
            if not os.path.exists(file_info_path):
                return render_template('error.html', error='File info not found'), 404
            
            with open(file_info_path, 'r') as f:
                file_info = json.load(f)
                
            # Load static and dynamic results if they exist
            static_results = None
            dynamic_results = None
            
            static_path = os.path.join(result_path, 'static_analysis_results.json')
            if os.path.exists(static_path):
                with open(static_path, 'r') as f:
                    static_results = json.load(f)
                    
            dynamic_path = os.path.join(result_path, 'dynamic_analysis_results.json')
            if os.path.exists(dynamic_path):
                with open(dynamic_path, 'r') as f:
                    dynamic_results = json.load(f)
            
            # Calculate overall risk
            risk_score, risk_factors = calculate_file_risk(file_info, static_results, dynamic_results)
            risk_level = get_risk_level(risk_score)
            
            # Add risk information to file_info
            file_info['risk_assessment'] = {
                'score': risk_score,
                'level': risk_level,
                'factors': risk_factors
            }


            if analysis_type == 'info':
                # Add helper data for the template
                if 'pe_info' in file_info:
                    # Calculate section entropy risk levels
                    for section in file_info['pe_info']['sections']:
                        section['entropy_risk'] = get_entropy_risk_level(section['entropy'])
                    
                    # Group suspicious imports by DLL
                    grouped_imports = {}
                    for imp in file_info['pe_info'].get('suspicious_imports', []):
                        dll = imp['dll']
                        if dll not in grouped_imports:
                            grouped_imports[dll] = []
                        grouped_imports[dll].append(imp)
                    file_info['pe_info']['grouped_suspicious_imports'] = grouped_imports

                    # Format checksum values
                    if 'checksum_info' in file_info['pe_info']:
                        checksum = file_info['pe_info']['checksum_info']
                        checksum['stored_checksum'] = format_hex(checksum['stored_checksum'])
                        checksum['calculated_checksum'] = format_hex(checksum['calculated_checksum'])

                return render_template('file_info.html', 
                                    file_info=file_info,
                                    entropy_risk_levels={
                                        'High': 7.2,
                                        'Medium': 6.8,
                                        'Low': 0
                                    })
                
            elif analysis_type in ['static', 'dynamic']:
                results_file = f'{analysis_type}_analysis_results.json'
                results_path = os.path.join(result_path, results_file)
                if not os.path.exists(results_path):
                    return render_template('error.html', error=f'No {analysis_type} analysis results found'), 404
                
                with open(results_path, 'r') as f:
                    analysis_results = json.load(f)

                if analysis_type == 'static':
                    # Calculate detection counts for static analysis with safe defaults and proper error handling
                    try:
                        yara_matches = analysis_results.get('yara', {}).get('matches', [])
                        yara_detections = len({match.get('rule') for match in yara_matches}) if isinstance(yara_matches, list) else 0
                    except (TypeError, ValueError):
                        yara_detections = 0

                    checkplz_detections = 0
                    checkplz_findings = analysis_results.get('checkplz', {}).get('findings', {})
                    if isinstance(checkplz_findings, dict):
                        checkplz_detections = 1 if checkplz_findings.get('initial_threat') else 0

                    # Format scan duration with proper error handling
                    formatted_duration = "00:00.000"
                    try:
                        scan_duration = float(analysis_results.get('checkplz', {}).get('findings', {})
                                           .get('scan_results', {}).get('scan_duration', 0))
                        minutes = int(scan_duration // 60)
                        seconds = int(scan_duration % 60)
                        milliseconds = int((scan_duration % 1) * 1000)
                        formatted_duration = f"{minutes:02d}:{seconds:02d}.{milliseconds:03d}"
                    except (TypeError, ValueError, AttributeError):
                        pass

                    return render_template('static_analysis.html',
                                         file_info=file_info,
                                         analysis_results=analysis_results,
                                         yara_detections=yara_detections,
                                         checkplz_detections=checkplz_detections,
                                         scan_duration=formatted_duration)
                
                elif analysis_type == 'dynamic':
                    # YARA: Count unique rule matches
                    try:
                        yara_matches = analysis_results.get('yara', {}).get('matches', [])
                        yara_detections = len({match.get('rule') for match in yara_matches}) if yara_matches else 0
                    except (TypeError, ValueError):
                        yara_detections = 0

                    # PE-Sieve: Get total suspicious count
                    try:
                        pesieve_findings = analysis_results.get('pe_sieve', {}).get('findings', {})
                        pesieve_detections = int(pesieve_findings.get('total_suspicious', 0) or 0)
                    except (TypeError, ValueError):
                        pesieve_detections = 0

                    # Moneta: Count memory anomalies including PEB violations
                    try:
                        moneta_findings = analysis_results.get('moneta', {}).get('findings', {})
                        moneta_detections = sum([
                            int(moneta_findings.get('total_private_rwx', 0) or 0),
                            int(moneta_findings.get('total_private_rx', 0) or 0),
                            int(moneta_findings.get('total_modified_code', 0) or 0),
                            int(moneta_findings.get('total_heap_executable', 0) or 0),
                            int(moneta_findings.get('total_modified_pe_header', 0) or 0),
                            int(moneta_findings.get('total_inconsistent_x', 0) or 0),
                            int(moneta_findings.get('total_missing_peb', 0) or 0),
                            int(moneta_findings.get('total_mismatching_peb', 0) or 0)
                        ])
                    except (TypeError, ValueError):
                        moneta_detections = 0

                    # Patriot: Get findings directly from findings array length
                    try:
                        patriot_findings = analysis_results.get('patriot', {}).get('findings', {}).get('findings', [])
                        patriot_detections = len(patriot_findings) if isinstance(patriot_findings, list) else 0
                    except (TypeError, ValueError):
                        patriot_detections = 0

                    # HSB: Count findings from severity counts and add any findings in the detections array
                    # HSB: Get total findings directly from detections[0]
                    try:
                        hsb_findings = analysis_results.get('hsb', {}).get('findings', {})
                        if hsb_findings and hsb_findings.get('detections'):
                            hsb_detections = len(hsb_findings['detections'][0].get('findings', []))
                        else:
                            hsb_detections = 0
                    except (TypeError, ValueError, IndexError):
                        hsb_detections = 0

                    return render_template('dynamic_analysis.html',
                                         file_info=file_info,
                                         analysis_results=analysis_results,
                                         yara_detections=yara_detections,
                                         pesieve_detections=pesieve_detections,
                                         moneta_detections=moneta_detections,
                                         patriot_detections=patriot_detections,
                                         hsb_detections=hsb_detections)

        except Exception as e:
            return render_template('error.html', error=str(e)), 500

    @app.route('/cleanup', methods=['POST'])
    def cleanup():
        try:
            results = {
                'uploads_cleaned': 0,
                'analysis_cleaned': 0,
                'result_cleaned': 0,
                'errors': []
            }

            # Clean uploads folder
            upload_folder = app.config['upload']['upload_folder']
            if os.path.exists(upload_folder):
                try:
                    files = os.listdir(upload_folder)
                    for f in files:
                        file_path = os.path.join(upload_folder, f)
                        try:
                            if os.path.isfile(file_path):
                                os.unlink(file_path)
                                results['uploads_cleaned'] += 1
                        except Exception as e:
                            results['errors'].append(f"Error deleting {f}: {str(e)}")
                except Exception as e:
                    results['errors'].append(f"Error accessing uploads folder: {str(e)}")

            # delete all folders in result folder
            result_folder = app.config['upload']['result_folder']
            if os.path.exists(result_folder):
                try:
                    folders = os.listdir(result_folder)
                    for folder in folders:
                        folder_path = os.path.join(result_folder, folder)
                        try:
                            if os.path.isdir(folder_path):
                                shutil.rmtree(folder_path)
                                results['result_cleaned'] += 1
                        except Exception as e:
                            results['errors'].append(f"Error deleting {folder}: {str(e)}")
                except Exception as e:
                    results['errors'].append(f"Error accessing result folder: {str(e)}")

            # Clean analysis folders
            analysis_path = os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis')
            if os.path.exists(analysis_path):
                try:
                    # Find all process_* folders
                    process_folders = glob.glob(os.path.join(analysis_path, 'process_*'))
                    for folder in process_folders:
                        try:
                            shutil.rmtree(folder)
                            results['analysis_cleaned'] += 1
                        except Exception as e:
                            results['errors'].append(f"Error deleting {folder}: {str(e)}")
                except Exception as e:
                    results['errors'].append(f"Error accessing analysis folder: {str(e)}")

            # Determine status based on whether there were any errors
            status = 'warning' if results['errors'] else 'success'
            message = 'Cleanup completed with some errors' if results['errors'] else 'Cleanup completed successfully'

            return jsonify({
                'status': status,
                'message': message,
                'details': results
            }), 200 if status == 'success' else 207  # 207 Multi-Status for partial success

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Cleanup failed',
                'error': str(e)
            }), 500

    @app.route('/health', methods=['GET'])
    def health_check():
        try:
            # Get configurations
            config = app.config
            upload_config = config.get('upload', {})
            analysis_config = config.get('analysis', {})
            
            # We'll gather any health issues in a list
            issues = []
            
            # Check upload folder accessibility
            upload_folder = upload_config.get('upload_folder')
            
            # Check both upload and temp folders
            folders_to_check = {
                'upload_folder': upload_folder,
            }
            
            for folder_name, folder_path in folders_to_check.items():
                if not folder_path:
                    issues.append(f"{folder_name} path is not configured")
                elif not os.path.isdir(folder_path):
                    issues.append(f"{folder_name} does not exist: {folder_path}")
                elif not os.access(folder_path, os.W_OK):
                    issues.append(f"{folder_name} is not writable: {folder_path}")
            
            # Function to check tool configuration and availability
            def check_analysis_tool(section, tool_name):
                tool_config = section.get(tool_name, {})
                if tool_config.get('enabled', False):
                    tool_path = tool_config.get('tool_path')
                    if not tool_path:
                        issues.append(f"{tool_name}: tool path not configured")
                    elif not os.path.isfile(tool_path):
                        issues.append(f"{tool_name}: tool not found at {tool_path}")
                    elif not os.access(tool_path, os.X_OK):
                        issues.append(f"{tool_name}: tool not executable at {tool_path}")
                    
                    # Check rules file if applicable
                    rules_path = tool_config.get('rules_path')
                    if rules_path and not os.path.isfile(rules_path):
                        issues.append(f"{tool_name}: rules not found at {rules_path}")
            
            # Check static analysis tools
            static_config = analysis_config.get('static', {})
            for tool in ['yara', 'threatcheck']:
                check_analysis_tool(static_config, tool)
            
            # Check dynamic analysis tools
            dynamic_config = analysis_config.get('dynamic', {})
            for tool in ['yara', 'pe_sieve', 'moneta', 'patriot', 'hsb']:
                check_analysis_tool(dynamic_config, tool)
            
            # Determine overall status
            status = 'ok' if not issues else 'degraded'
            http_code = 200 if status == 'ok' else 503
            
            health_status = {
                'status': status,
                'timestamp': datetime.datetime.now().isoformat(),
                'upload_folder_accessible': os.path.isdir(upload_folder) and os.access(upload_folder, os.W_OK) if upload_folder else False,
                'issues': issues,
                'configuration': {
                    'static_analysis': {tool: static_config.get(tool, {}).get('enabled', False) for tool in ['yara', 'threatcheck']},
                    'dynamic_analysis': {tool: dynamic_config.get(tool, {}).get('enabled', False) for tool in ['yara', 'pe_sieve', 'moneta']}
                }
            }
            
            return jsonify(health_status), http_code
            
        except Exception as e:
            return jsonify({
                'status': 'error',
                'timestamp': datetime.datetime.now().isoformat(),
                'issues': [str(e)]
            }), 500

    @app.route('/summary', methods=['GET'])
    def summary_page():
        """Route for the summary page"""
        return render_template('summary.html')

    @app.route('/files', methods=['GET'])
    def get_files_summary():
        try:
            results_dir = app.config['upload']['result_folder']
            summary = {}
            # Iterate through all subdirectories in the results folder
            for md5_dir in os.listdir(results_dir):
                dir_path = os.path.join(results_dir, md5_dir)
                if not os.path.isdir(dir_path):
                    continue
                    
                # Read file_info.json
                file_info_path = os.path.join(dir_path, 'file_info.json')
                if not os.path.exists(file_info_path):
                    continue
                
                with open(file_info_path, 'r') as f:
                    file_info = json.load(f)

                # Load static analysis results if they exist
                static_results = None
                static_path = os.path.join(dir_path, 'static_analysis_results.json')
                if os.path.exists(static_path):
                    with open(static_path, 'r') as f:
                        static_results = json.load(f)

                # Load dynamic analysis results if they exist
                dynamic_results = None
                dynamic_path = os.path.join(dir_path, 'dynamic_analysis_results.json')
                if os.path.exists(dynamic_path):
                    with open(dynamic_path, 'r') as f:
                        dynamic_results = json.load(f)

                # Calculate risk score using our comprehensive function
                risk_score, risk_factors = calculate_file_risk(file_info, static_results, dynamic_results)
                risk_level = get_risk_level(risk_score)

                # Create summary for this file
                summary[md5_dir] = {
                    'md5': file_info.get('md5', 'unknown'),
                    'sha256': file_info.get('sha256', 'unknown'),
                    'filename': file_info.get('original_name', 'unknown'),
                    'file_size': file_info.get('size', 0),
                    'upload_time': file_info.get('upload_time', 'unknown'),
                    'result_dir_full_path': os.path.abspath(dir_path),
                    'entropy_value': file_info.get('entropy_analysis', {}).get('value', 0),
                    'detection_risk': file_info.get('entropy_analysis', {}).get('detection_risk', 'Unknown'),
                    'has_static_analysis': os.path.exists(static_path),
                    'has_dynamic_analysis': os.path.exists(dynamic_path),
                    # Add the new risk assessment
                    'risk_assessment': {
                        'score': risk_score,
                        'level': risk_level,
                        'factors': risk_factors
                    }
                }

            return jsonify({
                'status': 'success',
                'count': len(summary),
                'files': summary
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500

    @app.route('/file/<target>', methods=['DELETE'])
    def delete_file(target):
        try:
            # Find file in uploads folder
            upload_path = find_file_by_hash(target, app.config['upload']['upload_folder'])
            result_path = find_file_by_hash(target, app.config['upload']['result_folder'])
            analysis_path = os.path.join('.', 'Scanners', 'PE-Sieve', 'Analysis')
            
            deleted = {
                'upload': False,
                'result': False,
                'analysis': False
            }

            # Delete from uploads if exists
            if upload_path:
                try:
                    if os.path.isfile(upload_path):
                        os.unlink(upload_path)
                    deleted['upload'] = True
                except Exception as e:
                    app.logger.error(f"Error deleting upload file: {str(e)}")

            # Delete result folder if exists
            if result_path:
                try:
                    if os.path.isdir(result_path):
                        shutil.rmtree(result_path)
                    deleted['result'] = True
                except Exception as e:
                    app.logger.error(f"Error deleting result folder: {str(e)}")

            # Delete analysis folders if they exist
            if os.path.exists(analysis_path):
                try:
                    # Find all process_* folders related to this file
                    process_folders = glob.glob(os.path.join(analysis_path, f'*_{target}_*'))
                    for folder in process_folders:
                        if os.path.isdir(folder):
                            shutil.rmtree(folder)
                            deleted['analysis'] = True
                except Exception as e:
                    app.logger.error(f"Error deleting analysis folders: {str(e)}")

            # Check if anything was deleted
            if not any(deleted.values()):
                return jsonify({
                    'status': 'error',
                    'message': 'File not found'
                }), 404

            return jsonify({
                'status': 'success',
                'message': 'File deleted successfully',
                'details': deleted
            })

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500

    return app
