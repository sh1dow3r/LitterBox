# app/routes.py

import datetime
import glob
import json
import os
import shutil
from flask import render_template, request, jsonify
from .utils import Utils
from .analyzers.manager import AnalysisManager

def register_routes(app):
    analysis_manager = AnalysisManager(app.config)
    utils = Utils(app.config)  # Initialize Utils with app configuration


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
        
        if file and utils.allowed_file(file.filename):
            try:
                file_info = utils.save_uploaded_file(file)
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
        is_valid, error_msg = utils.validate_pid(pid)
        if not is_valid:
            return jsonify({'error': error_msg}), 404
        return jsonify({'status': 'valid'}), 200


    @app.route('/analyze/<analysis_type>/<target>', methods=['GET', 'POST'])
    def analyze_file(analysis_type, target):
        try:
            is_pid = False
            file_path = None
            result_path = None

            # Check if this is a PID-based analysis
            if analysis_type == 'dynamic' and target.isdigit():
                is_pid = True
                pid = target
                # Validate PID before proceeding
                is_valid, error_msg = utils.validate_pid(pid)
                if not is_valid:
                    return jsonify({'error': error_msg}), 404
                # Define result_path for PID-based dynamic analysis
                # For example: results_folder/dynamic_<pid>
                result_folder = os.path.join(utils.config['upload']['result_folder'], f'dynamic_{pid}')
                os.makedirs(result_folder, exist_ok=True)
                result_path = result_folder
            else:
                # Look for file as before
                file_path = utils.find_file_by_hash(target, app.config['upload']['upload_folder'])
                result_path = utils.find_file_by_hash(target, app.config['upload']['result_folder'])
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
                # Save results to result folder
                static_results_path = os.path.join(result_path, 'static_analysis_results.json')
                with open(static_results_path, 'w') as f:
                    json.dump(results, f)
            elif analysis_type == 'dynamic':
                target_for_analysis = pid if is_pid else file_path
                results = analysis_manager.run_dynamic_analysis(target_for_analysis, is_pid)
                # Save results to result folder
                dynamic_results_path = os.path.join(result_path, 'dynamic_analysis_results.json')
                with open(dynamic_results_path, 'w') as f:
                    json.dump(results, f)
            else:
                return jsonify({'error': 'Invalid analysis type'}), 400

            return jsonify({
                'status': 'success',
                'results': results
            })

        except Exception as e:
            # Log the exception for debugging purposes
            app.logger.error(f"Error in analyze_file route: {e}")
            return jsonify({'error': str(e)}), 500


    @app.route('/results/<target>/<analysis_type>', methods=['GET'])
    def get_analysis_results(target, analysis_type):
        try:
            # Check if the target is a PID (all digits) and analysis_type is 'dynamic'
            if target.isdigit() and analysis_type == 'dynamic':
                pid = target
                # Define the folder path for PID-based dynamic analysis
                result_folder = os.path.join(app.config['upload']['result_folder'], f'dynamic_{pid}')
                
                # Check if the result folder exists
                if not os.path.exists(result_folder):
                    error_message = f'Process with PID {pid} does not exist'
                    return render_template('error.html', error=error_message), 404

                # Define the path to dynamic_analysis_results.json
                dynamic_path = os.path.join(result_folder, 'dynamic_analysis_results.json')
                
                # Check if dynamic_analysis_results.json exists
                if not os.path.exists(dynamic_path):
                    error_message = f'Dynamic analysis results for PID {pid} not found.'
                    return render_template('error.html', error=error_message), 404

                # Load dynamic_analysis_results.json
                with open(dynamic_path, 'r') as f:
                    dynamic_results = json.load(f)

                # Calculate overall risk using the provided calculate_process_risk function
                risk_score, risk_factors = utils.calculate_process_risk(dynamic_results)
                risk_level = utils.get_risk_level(risk_score)

                # Add risk information to dynamic_results
                dynamic_results['risk_assessment'] = {
                    'score': risk_score,
                    'level': risk_level,
                    'factors': risk_factors
                }

                # Extract detection counts as in original code
                try:
                    yara_matches = dynamic_results.get('yara', {}).get('matches', [])
                    yara_detections = len({match.get('rule') for match in yara_matches if match.get('rule')}) if isinstance(yara_matches, list) else 0
                except (TypeError, ValueError):
                    yara_detections = 0

                try:
                    pesieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
                    pesieve_detections = int(pesieve_findings.get('total_suspicious', 0) or 0)
                except (TypeError, ValueError):
                    pesieve_detections = 0

                try:
                    moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
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

                try:
                    patriot_findings = dynamic_results.get('patriot', {}).get('findings', {}).get('findings', [])
                    patriot_detections = len(patriot_findings) if isinstance(patriot_findings, list) else 0
                except (TypeError, ValueError):
                    patriot_detections = 0

                try:
                    hsb_findings = dynamic_results.get('hsb', {}).get('findings', {})
                    if hsb_findings and hsb_findings.get('detections'):
                        hsb_detections = len(hsb_findings['detections'][0].get('findings', []))
                    else:
                        hsb_detections = 0
                except (TypeError, ValueError, IndexError):
                    hsb_detections = 0

                # Render dynamic_results.html for PID-based target
                return render_template(
                    'dynamic_results.html',
                    file_info=None,  # No file_info for PID-based targets
                    analysis_results=dynamic_results,
                    yara_detections=yara_detections,
                    pesieve_detections=pesieve_detections,
                    moneta_detections=moneta_detections,
                    patriot_detections=patriot_detections,
                    hsb_detections=hsb_detections,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    risk_factors=risk_factors
                )

            else:
                # Treat target as a hash for file-based analysis
                result_path = utils.find_file_by_hash(target, app.config['upload']['result_folder'])
                if not result_path:
                    return render_template('error.html', error='Results not found'), 404

                # Load file_info.json
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
                risk_score, risk_factors = utils.calculate_file_risk(file_info, static_results, dynamic_results)
                risk_level = utils.get_risk_level(risk_score)

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
                            section['entropy_risk'] = utils.get_entropy_risk_level(section['entropy'])

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
                            checksum['stored_checksum'] = utils.format_hex(checksum['stored_checksum'])
                            checksum['calculated_checksum'] = utils.format_hex(checksum['calculated_checksum'])

                    return render_template(
                        'file_info.html',
                        file_info=file_info,
                        entropy_risk_levels={
                            'High': 7.2,
                            'Medium': 6.8,
                            'Low': 0
                        }
                    )

                elif analysis_type in ['static', 'dynamic']:
                    # Process 'static' or 'dynamic' analysis types
                    results_file = f'{analysis_type}_analysis_results.json'
                    results_path = os.path.join(result_path, results_file)
                    if not os.path.exists(results_path):
                        return render_template('error.html', error=f'No {analysis_type} analysis results found'), 404

                    with open(results_path, 'r') as f:
                        analysis_results = json.load(f)

                    if analysis_type == 'static':
                        # Extract static analysis detections
                        try:
                            yara_matches = analysis_results.get('yara', {}).get('matches', [])
                            yara_detections = len({match.get('rule') for match in yara_matches}) if isinstance(yara_matches, list) else 0
                        except (TypeError, ValueError):
                            yara_detections = 0

                        checkplz_detections = 0
                        checkplz_findings = analysis_results.get('checkplz', {}).get('findings', {})
                        if isinstance(checkplz_findings, dict):
                            checkplz_detections = 1 if checkplz_findings.get('initial_threat') else 0

                        # Format scan duration
                        formatted_duration = "00:00.000"
                        try:
                            scan_duration = float(
                                analysis_results.get('checkplz', {}).get('findings', {})
                                .get('scan_results', {}).get('scan_duration', 0)
                            )
                            minutes = int(scan_duration // 60)
                            seconds = int(scan_duration % 60)
                            milliseconds = int((scan_duration % 1) * 1000)
                            formatted_duration = f"{minutes:02d}:{seconds:02d}.{milliseconds:03d}"
                        except (TypeError, ValueError, AttributeError):
                            pass

                        return render_template(
                            'static_results.html',
                            file_info=file_info,
                            analysis_results=analysis_results,
                            yara_detections=yara_detections,
                            checkplz_detections=checkplz_detections,
                            scan_duration=formatted_duration
                        )

                    elif analysis_type == 'dynamic':
                        # Extract dynamic analysis detections
                        try:
                            yara_matches = analysis_results.get('yara', {}).get('matches', [])
                            yara_detections = len({match.get('rule') for match in yara_matches}) if yara_matches else 0
                        except (TypeError, ValueError):
                            yara_detections = 0

                        try:
                            pesieve_findings = analysis_results.get('pe_sieve', {}).get('findings', {})
                            pesieve_detections = int(pesieve_findings.get('total_suspicious', 0) or 0)
                        except (TypeError, ValueError):
                            pesieve_detections = 0

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

                        try:
                            patriot_findings = analysis_results.get('patriot', {}).get('findings', {}).get('findings', [])
                            patriot_detections = len(patriot_findings) if isinstance(patriot_findings, list) else 0
                        except (TypeError, ValueError):
                            patriot_detections = 0

                        try:
                            hsb_findings = analysis_results.get('hsb', {}).get('findings', {})
                            if hsb_findings and hsb_findings.get('detections'):
                                hsb_detections = len(hsb_findings['detections'][0].get('findings', []))
                            else:
                                hsb_detections = 0
                        except (TypeError, ValueError, IndexError):
                            hsb_detections = 0

                        return render_template(
                            'dynamic_results.html',
                            file_info=file_info,
                            analysis_results=analysis_results,
                            yara_detections=yara_detections,
                            pesieve_detections=pesieve_detections,
                            moneta_detections=moneta_detections,
                            patriot_detections=patriot_detections,
                            hsb_detections=hsb_detections
                        )

                else:
                    return render_template('error.html', error='Invalid analysis type.'), 400

        except Exception as e:
            # Log the exception for debugging purposes
            app.logger.error(f"Error in get_analysis_results route: {e}")
            return render_template('error.html', error=str(e)), 500


    @app.route('/summary', methods=['GET'])
    def summary_page():
        """Route for the summary page"""
        return render_template('summary.html')


    @app.route('/files', methods=['GET'])
    def get_files_summary():
        try:
            results_dir = app.config['upload']['result_folder']
            file_based_summary = {}
            pid_based_summary = {}

            all_items = os.listdir(results_dir)

            # Iterate through all items in the results folder
            for item in all_items:
                item_path = os.path.join(results_dir, item)
                
                if not os.path.isdir(item_path):
                    continue

                # Handle PID-based analysis (dynamic_pid directories)
                if item.startswith('dynamic_'):
                    pid = item.replace('dynamic_', '')
                    
                    dynamic_results_path = os.path.join(item_path, 'dynamic_analysis_results.json')
                    
                    if os.path.exists(dynamic_results_path):
                        with open(dynamic_results_path, 'r') as f:
                            dynamic_results = json.load(f)
                        
                        # Extract scanner-specific results
                        yara_matches = dynamic_results.get('yara', {}).get('matches', [])
                        pe_sieve_findings = dynamic_results.get('pe_sieve', {}).get('findings', {})
                        moneta_findings = dynamic_results.get('moneta', {}).get('findings', {})
                        hsb_detections = dynamic_results.get('hsb', {}).get('findings', {}).get('detections', [])

                        # Get process details from Moneta if available
                        process_info = moneta_findings.get('process_info', {})

                        # Calculate risk score for PID-based analysis
                        risk_score, risk_factors = utils.calculate_process_risk(dynamic_results)
                        risk_level = utils.get_risk_level(risk_score)

                        pid_based_summary[pid] = {
                            'pid': pid,
                            'process_name': process_info.get('name', 'unknown'),
                            'process_path': process_info.get('path', 'unknown'),
                            'architecture': process_info.get('arch', 'unknown'),
                            'analysis_time': dynamic_results.get('analysis_time', 'unknown'),
                            'result_dir_full_path': os.path.abspath(item_path),
                            'risk_assessment': {
                                'score': risk_score,
                                'level': risk_level,
                                'factors': risk_factors
                            },
                            'analysis_summary': {
                                'yara': {
                                    'match_count': len(yara_matches),
                                    'critical_rules': sum(1 for match in yara_matches 
                                                       if match.get('metadata', {}).get('severity', 0) >= 90)
                                },
                                'pe_sieve': {
                                    'total_suspicious': pe_sieve_findings.get('total_suspicious', 0),
                                    'implanted': pe_sieve_findings.get('implanted', 0),
                                    'hooked': pe_sieve_findings.get('hooked', 0)
                                },
                                'moneta': {
                                    'abnormal_exec': moneta_findings.get('total_abnormal_private_exec', 0),
                                    'unsigned_modules': moneta_findings.get('total_unsigned_modules', 0),
                                    'rwx_regions': moneta_findings.get('total_private_rwx', 0)
                                },
                                'hsb': {
                                    'total_findings': sum(len(det.get('findings', [])) 
                                                        for det in hsb_detections if det.get('pid') == int(pid)),
                                    'max_severity': max((det.get('max_severity', 0) 
                                                       for det in hsb_detections if det.get('pid') == int(pid)), 
                                                      default=0)
                                }
                            }
                        }

                    continue
                # Handle file-based analysis (existing logic)
                file_info_path = os.path.join(item_path, 'file_info.json')
                if not os.path.exists(file_info_path):
                    continue
                    
                with open(file_info_path, 'r') as f:
                    file_info = json.load(f)

                # Load static analysis results if they exist
                static_results = None
                static_path = os.path.join(item_path, 'static_analysis_results.json')
                if os.path.exists(static_path):
                    with open(static_path, 'r') as f:
                        static_results = json.load(f)

                # Load dynamic analysis results if they exist
                dynamic_results = None
                dynamic_path = os.path.join(item_path, 'dynamic_analysis_results.json')
                if os.path.exists(dynamic_path):
                    with open(dynamic_path, 'r') as f:
                        dynamic_results = json.load(f)

                # Calculate risk score using our comprehensive function
                risk_score, risk_factors = utils.calculate_file_risk(file_info, static_results, dynamic_results)
                risk_level = utils.get_risk_level(risk_score)

                # Create summary for this file
                file_based_summary[item] = {
                    'md5': file_info.get('md5', 'unknown'),
                    'sha256': file_info.get('sha256', 'unknown'),
                    'filename': file_info.get('original_name', 'unknown'),
                    'file_size': file_info.get('size', 0),
                    'upload_time': file_info.get('upload_time', 'unknown'),
                    'result_dir_full_path': os.path.abspath(item_path),
                    'entropy_value': file_info.get('entropy_analysis', {}).get('value', 0),
                    'detection_risk': file_info.get('entropy_analysis', {}).get('detection_risk', 'Unknown'),
                    'has_static_analysis': os.path.exists(static_path),
                    'has_dynamic_analysis': os.path.exists(dynamic_path),
                    'risk_assessment': {
                        'score': risk_score,
                        'level': risk_level,
                        'factors': risk_factors
                    }
                }

            return jsonify({
                'status': 'success',
                'file_based': {
                    'count': len(file_based_summary),
                    'files': file_based_summary
                },
                'pid_based': {
                    'count': len(pid_based_summary),
                    'processes': pid_based_summary
                }
            })

        except Exception as e:
            print(f"Error in get_files_summary: {str(e)}")
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500


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

            # Delete all folders in result folder
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


    @app.route('/file/<target>', methods=['DELETE'])
    def delete_file(target):
        try:
            # Find file in uploads folder
            upload_path = utils.find_file_by_hash(target, app.config['upload']['upload_folder'])
            result_path = utils.find_file_by_hash(target, app.config['upload']['result_folder'])
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
