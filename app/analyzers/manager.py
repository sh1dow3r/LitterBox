# app/analyzers/manager.py
from .static.yara_analyzer import YaraStaticAnalyzer
from .static.checkplz_analyzer import CheckPlzAnalyzer
from .dynamic.yara_analyzer import YaraDynamicAnalyzer
from .dynamic.pe_sieve_analyzer import PESieveAnalyzer
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.patriot_analyzer import PatriotAnalyzer
from .dynamic.hsb_analyzer import HSBAnalyzer
import subprocess
import time
import psutil

class AnalysisManager:
    def __init__(self, config):
        self.config = config
        self.static_analyzers = {}
        self.dynamic_analyzers = {}
        self._initialize_analyzers()

    def _initialize_analyzers(self):
        """Initialize enabled analyzers"""
        # Static analyzers
        if self.config['analysis']['static']['yara']['enabled']:
            self.static_analyzers['yara'] = YaraStaticAnalyzer(self.config)
        if self.config['analysis']['static']['checkplz']['enabled']:
            self.static_analyzers['checkplz'] = CheckPlzAnalyzer(self.config)

        # Dynamic analyzers
        if self.config['analysis']['dynamic']['yara']['enabled']:
            self.dynamic_analyzers['yara'] = YaraDynamicAnalyzer(self.config)            
        if self.config['analysis']['dynamic']['pe_sieve']['enabled']:
            self.dynamic_analyzers['pe_sieve'] = PESieveAnalyzer(self.config)
        if self.config['analysis']['dynamic']['moneta']['enabled']:
            self.dynamic_analyzers['moneta'] = MonetaAnalyzer(self.config)
        if self.config['analysis']['dynamic']['patriot']['enabled']:
            self.dynamic_analyzers['patriot'] = PatriotAnalyzer(self.config)
        if self.config['analysis']['dynamic']['hsb']['enabled']:
            self.dynamic_analyzers['hsb'] = HSBAnalyzer(self.config)
            
    def run_static_analysis(self, file_path):
        """Run all enabled static analyzers"""
        results = {}
        for name, analyzer in self.static_analyzers.items():
            try:
                analyzer.analyze(file_path)
                results[name] = analyzer.get_results()
            except Exception as e:
                results[name] = {
                    'status': 'error',
                    'error': str(e)
                }
        return results

    def run_dynamic_analysis(self, target, is_pid=False):
        """
        Run all enabled dynamic analyzers
        Args:
            target: Either a file path or PID
            is_pid: Boolean indicating if target is a PID
        """
        results = {}
        process = None
        pid = None
        
        try:
            if is_pid:
                # Verify PID exists and is valid
                try:
                    pid = int(target)
                    process = psutil.Process(pid)
                    if not process.is_running():
                        raise Exception("Process is not running")
                except (ValueError, psutil.NoSuchProcess):
                    raise Exception("Invalid or non-existent PID")
            else:
                # Start the payload process
                process = subprocess.Popen(
                    target,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                pid = process.pid
                # Wait for process initialization
                time.sleep(5)
            
            # Run all dynamic analyzers
            for name, analyzer in self.dynamic_analyzers.items():
                try:
                    analyzer.analyze(pid)
                    results[name] = analyzer.get_results()
                except Exception as e:
                    results[name] = {
                        'status': 'error',
                        'error': str(e)
                    }
                    
        except Exception as e:
            results['process'] = {
                'status': 'error',
                'error': str(e)
            }
        
        finally:
            # Only cleanup if we created the process
            if process and not is_pid:
                try:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.terminate()
                    parent.terminate()
                except:
                    pass
            
        return results