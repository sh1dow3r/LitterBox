import logging
import subprocess
import time
import psutil
from .static.yara_analyzer import YaraStaticAnalyzer
from .static.checkplz_analyzer import CheckPlzAnalyzer
from .dynamic.yara_analyzer import YaraDynamicAnalyzer
from .dynamic.pe_sieve_analyzer import PESieveAnalyzer
from .dynamic.moneta_analyzer import MonetaAnalyzer
from .dynamic.patriot_analyzer import PatriotAnalyzer
from .dynamic.hsb_analyzer import HSBAnalyzer

class AnalysisManager:
    def __init__(self, config, logger=None):
        # Use provided logger or create new one
        self.logger = logger or logging.getLogger(__name__)
        self.logger.debug("Initializing AnalysisManager")
        self.logger.debug(f"Analysis configuration: {config['analysis']}")
        
        self.config = config
        self.static_analyzers = {}
        self.dynamic_analyzers = {}
        self._initialize_analyzers()
        
        self.logger.debug(f"Initialized static analyzers: {list(self.static_analyzers.keys())}")
        self.logger.debug(f"Initialized dynamic analyzers: {list(self.dynamic_analyzers.keys())}")
        self.logger.debug("AnalysisManager initialization completed")

    def _initialize_analyzers(self):
        """Initialize enabled analyzers"""
        self.logger.debug("Beginning analyzer initialization")
        
        # Static analyzers
        static_config = self.config['analysis']['static']
        self.logger.debug(f"Static analysis configuration: {static_config}")
        
        if static_config['yara']['enabled']:
            self.logger.debug("Initializing YaraStaticAnalyzer with config: " + 
                          f"{static_config['yara']}")
            try:
                self.static_analyzers['yara'] = YaraStaticAnalyzer(self.config)
                self.logger.debug("YaraStaticAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize YaraStaticAnalyzer: {e}")

        if static_config['checkplz']['enabled']:
            self.logger.debug("Initializing CheckPlzAnalyzer with config: " + 
                          f"{static_config['checkplz']}")
            try:
                self.static_analyzers['checkplz'] = CheckPlzAnalyzer(self.config)
                self.logger.debug("CheckPlzAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize CheckPlzAnalyzer: {e}")

        # Dynamic analyzers
        dynamic_config = self.config['analysis']['dynamic']
        self.logger.debug(f"Dynamic analysis configuration: {dynamic_config}")
        
        if dynamic_config['yara']['enabled']:
            self.logger.debug("Initializing YaraDynamicAnalyzer with config: " + 
                          f"{dynamic_config['yara']}")
            try:
                self.dynamic_analyzers['yara'] = YaraDynamicAnalyzer(self.config)
                self.logger.debug("YaraDynamicAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize YaraDynamicAnalyzer: {e}")
                
        if dynamic_config['pe_sieve']['enabled']:
            self.logger.debug("Initializing PESieveAnalyzer with config: " + 
                          f"{dynamic_config['pe_sieve']}")
            try:
                self.dynamic_analyzers['pe_sieve'] = PESieveAnalyzer(self.config)
                self.logger.debug("PESieveAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize PESieveAnalyzer: {e}")

        if dynamic_config['moneta']['enabled']:
            self.logger.debug("Initializing MonetaAnalyzer with config: " + 
                          f"{dynamic_config['moneta']}")
            try:
                self.dynamic_analyzers['moneta'] = MonetaAnalyzer(self.config)
                self.logger.debug("MonetaAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize MonetaAnalyzer: {e}")

        if dynamic_config['patriot']['enabled']:
            self.logger.debug("Initializing PatriotAnalyzer with config: " + 
                          f"{dynamic_config['patriot']}")
            try:
                self.dynamic_analyzers['patriot'] = PatriotAnalyzer(self.config)
                self.logger.debug("PatriotAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize PatriotAnalyzer: {e}")

        if dynamic_config['hsb']['enabled']:
            self.logger.debug("Initializing HSBAnalyzer with config: " + 
                          f"{dynamic_config['hsb']}")
            try:
                self.dynamic_analyzers['hsb'] = HSBAnalyzer(self.config)
                self.logger.debug("HSBAnalyzer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize HSBAnalyzer: {e}")

        self.logger.debug("Analyzer initialization completed")

    def run_static_analysis(self, file_path):
        """Run all enabled static analyzers"""
        self.logger.debug(f"Starting static analysis for file: {file_path}")
        results = {}
        
        if not self.static_analyzers:
            self.logger.warning("No static analyzers are enabled")
            return results
            
        self.logger.debug(f"Running {len(self.static_analyzers)} static analyzers")
        
        for name, analyzer in self.static_analyzers.items():
            try:
                self.logger.debug(f"Starting static analyzer: {name}")
                start_time = time.time()
                
                analyzer.analyze(file_path)
                results[name] = analyzer.get_results()
                
                duration = time.time() - start_time
                self.logger.debug(f"Static analyzer {name} completed in {duration:.2f} seconds")
                self.logger.debug(f"Results from {name}: {results[name]}")
                
            except Exception as e:
                self.logger.error(f"Error in static analyzer {name}: {str(e)}", exc_info=True)
                results[name] = {
                    'status': 'error',
                    'error': str(e)
                }
                
        self.logger.debug(f"Static analysis completed. Analyzed with {len(results)} analyzers")
        return results

    def run_dynamic_analysis(self, target, is_pid=False):
        """
        Run all enabled dynamic analyzers
        Args:
            target: Either a file path or PID
            is_pid: Boolean indicating if target is a PID
        """
        self.logger.debug(f"Starting dynamic analysis - Target: {target}, is_pid: {is_pid}")
        results = {}
        process = None
        pid = None
        
        if not self.dynamic_analyzers:
            self.logger.warning("No dynamic analyzers are enabled")
            return results
            
        try:
            if is_pid:
                self.logger.debug(f"Validating PID: {target}")
                try:
                    pid = int(target)
                    process = psutil.Process(pid)
                    if not process.is_running():
                        raise Exception(f"Process with PID {pid} is not running")
                    self.logger.debug(f"Successfully validated PID {pid}, process is running")
                except (ValueError, psutil.NoSuchProcess) as e:
                    self.logger.error(f"Invalid or non-existent PID {target}: {e}")
                    raise Exception(f"Invalid or non-existent PID: {e}")
            else:
                self.logger.debug(f"Starting new process for target: {target}")
                process = subprocess.Popen(
                    target,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                pid = process.pid
                self.logger.debug(f"Process started with PID: {pid}")
                self.logger.debug("Waiting 5 seconds for process initialization")
                time.sleep(5)
            
            self.logger.debug(f"Running {len(self.dynamic_analyzers)} dynamic analyzers")
            
            # Run all dynamic analyzers
            for name, analyzer in self.dynamic_analyzers.items():
                try:
                    self.logger.debug(f"Starting dynamic analyzer: {name}")
                    start_time = time.time()
                    
                    analyzer.analyze(pid)
                    results[name] = analyzer.get_results()
                    
                    duration = time.time() - start_time
                    self.logger.debug(f"Dynamic analyzer {name} completed in {duration:.2f} seconds")
                    self.logger.debug(f"Results from {name}: {results[name]}")
                    
                except Exception as e:
                    self.logger.error(f"Error in dynamic analyzer {name}: {str(e)}", exc_info=True)
                    results[name] = {
                        'status': 'error',
                        'error': str(e)
                    }
                    
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {str(e)}", exc_info=True)
            results['process'] = {
                'status': 'error',
                'error': str(e)
            }
        
        finally:
            # Only cleanup if we created the process
            if process and not is_pid:
                self.logger.debug(f"Cleaning up created process with PID: {process.pid}")
                try:
                    parent = psutil.Process(process.pid)
                    
                    child_count = len(parent.children(recursive=True))
                    self.logger.debug(f"Found {child_count} child processes to terminate")
                    
                    for child in parent.children(recursive=True):
                        self.logger.debug(f"Terminating child process: {child.pid}")
                        child.terminate()
                        
                    self.logger.debug(f"Terminating parent process: {parent.pid}")
                    parent.terminate()
                    self.logger.debug("Process cleanup completed successfully")
                    
                except Exception as e:
                    self.logger.error(f"Error during process cleanup: {str(e)}", exc_info=True)
            
        self.logger.debug("Dynamic analysis completed")
        return results