// app/static/js/resutls.js
// UI Components and Constants
const UI = {
    icons: {
        running: `
            <svg class="w-6 h-6 text-red-500 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>`,
        complete: `
            <svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>`,
        error: `
            <svg class="w-6 h-6 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>`
    }
};


// Tab Manager
class TabManager {
    constructor() {
        this.tabs = document.querySelectorAll('.tab-button');
        this.tabContents = document.querySelectorAll('.tab-content');
        this.setupTabs();
    }

    setupTabs() {
        this.tabs.forEach(tab => {
            tab.addEventListener('click', () => this.switchTab(tab));
        });

        // Activate first tab by default
        if (this.tabs.length > 0) {
            this.tabs[0].click();
        }
    }

    switchTab(selectedTab) {
        const target = selectedTab.dataset.tab;
        
        // Hide all tab content and deactivate tabs
        this.tabContents.forEach(content => content.classList.add('hidden'));
        this.tabs.forEach(tab => tab.classList.remove('border-red-500', 'text-white'));
        
        // Show target content and activate tab
        document.getElementById(target).classList.remove('hidden');
        selectedTab.classList.add('border-red-500', 'text-white');
    }
}

// Analysis Type Handler
class AnalysisTypeHandler {
    constructor() {
        this.setupAnalysisType();
    }

    isNumeric(str) {
        return /^\d+$/.test(str);
    }

    setupAnalysisType() {
        const pathSegments = window.location.pathname.split('/').filter(segment => segment.length > 0);
        const identifier = pathSegments[pathSegments.length - 1];
        
        // If PID, hide static analysis button
        if (this.isNumeric(identifier)) {
            const staticButton = document.getElementById('staticAnalysisButton');
            if (staticButton) {
                staticButton.style.display = 'none';
            }
        }
    }
}


// Analysis Core Logic
class AnalysisCore {
    constructor() {
        this.elements = {
            analysisStatus: document.getElementById('analysisStatus'),
            statusIcon: document.getElementById('statusIcon'),
            analysisTimer: document.getElementById('analysisTimer'),
            stageLine: document.getElementById('stageLine'),
            analysisStage: document.getElementById('analysisStage')
        };
        this.startTime = Date.now();
        this.timerInterval = null;

        const pathParts = window.location.pathname.split('/');
        this.analysisType = pathParts[2];
        this.fileHash = pathParts[3];
    }

    updateTimer() {
        const elapsed = Date.now() - this.startTime;
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        const milliseconds = elapsed % 1000;
        this.elements.analysisTimer.textContent = 
            `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}.${milliseconds.toString().padStart(3, '0')}`;
        // Update summary scan duration
        document.getElementById('scanDuration').textContent = this.elements.analysisTimer.textContent;
    }
    startTimer() {
        this.timerInterval = setInterval(() => this.updateTimer(), 1000);
    }

    stopTimer() {
        clearInterval(this.timerInterval);
    }

    updateStatusIcon(status) {
        this.elements.statusIcon.innerHTML = UI.icons[status] || '';
    }

    updateStageToComplete() {
        this.elements.stageLine.classList.remove('bg-gray-800');
        this.elements.stageLine.classList.add('bg-green-500/20');
        
        this.elements.analysisStage.innerHTML = `
            <div class="w-10 h-10 rounded-full bg-green-500/10 border-2 border-green-500 flex items-center justify-center">
                <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
            </div>
            <span class="text-gray-400">Analysis</span>`;
    }

    async startAnalysis() {
        this.updateStatusIcon('running');
        this.elements.analysisStatus.textContent = 'Running analysis...';
        this.startTimer();

        try {
            const response = await fetch(`/analyze/${this.analysisType}/${this.fileHash}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            
            // Update final time and UI
            this.updateTimer();
            this.stopTimer();
            this.updateStatusIcon('complete');
            this.elements.analysisStatus.textContent = 'Analysis completed';
            this.updateStageToComplete();

            // First update the summary with all results
            if (tools.summary && data.results) {
                tools.summary.render(data.results);
            }

            // Then process individual tool results
            Object.entries(data.results).forEach(([toolKey, results]) => {
                if (results && tools[toolKey] && toolKey !== 'summary') {
                    tools[toolKey].render(results);
                }
            });

        } catch (error) {
            this.stopTimer();
            this.updateStatusIcon('error');
            this.elements.analysisStatus.textContent = `Error: ${error.message}`;
        }
    }
}

// Modal Handler
class ModalHandler {
    constructor() {
        this.modal = document.getElementById('dynamicWarningModal');
        this.dialog = this.modal.querySelector('.bg-gray-900');
        this.setupListeners();
    }

    setupListeners() {
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.hide();
            }
        });
    }

    show() {
        this.modal.classList.remove('hidden');
        setTimeout(() => {
            this.dialog.classList.remove('scale-95', 'opacity-0');
        }, 50);
    }

    hide() {
        this.dialog.classList.add('scale-95', 'opacity-0');
        setTimeout(() => {
            this.modal.classList.add('hidden');
        }, 300);
    }
}

// Tools Registry Object (keeping reference to tools)
const tools = {
    yara: {
            element: document.getElementById('yaraResults'),
            statsElement: document.getElementById('yaraStats'),
            render: (results) => {
                if (results.status === 'error') {
                    tools.yara.element.innerHTML = `
                        <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                            <div class="flex items-center space-x-2 text-red-500">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <span>${results.error}</span>
                            </div>
                        </div>`;
                    return;
                }

                // Ensure matches is always an array
                const matches = Array.isArray(results.matches) ? results.matches : [];
                const matchCount = matches.length;
                const isClean = matchCount === 0;

                // Stats Section
                const highestSeverity = Math.max(...matches.map(m => parseInt(m.metadata?.severity || 0)));
                tools.yara.statsElement.innerHTML = `
                    <div class="grid grid-cols-3 gap-4 mb-4">
                        <div class="px-4 py-3 bg-gray-900/50 rounded-lg border ${isClean ? 'border-green-500/30' : 'border-red-500/30'}">
                            <div class="text-sm text-gray-500">Rule Matches</div>
                            <div class="text-2xl font-semibold ${isClean ? 'text-green-500' : 'text-red-500'}">${matchCount}</div>
                        </div>
                        <div class="px-4 py-3 bg-gray-900/50 rounded-lg border border-gray-800">
                            <div class="text-sm text-gray-500">Total Strings</div>
                            <div class="text-2xl font-semibold text-gray-400">
                                ${matches.reduce((acc, match) => acc + (Array.isArray(match.strings) ? match.strings.length : 0), 0)}
                            </div>
                        </div>
                        <div class="px-4 py-3 bg-gray-900/50 rounded-lg border ${isClean ? 'border-green-500/30' : highestSeverity > 50 ? 'border-red-500/30' : 'border-yellow-500/30'}">
                            <div class="text-sm text-gray-500">Status</div>
                            <div class="text-2xl font-semibold ${isClean ? 'text-green-500' : highestSeverity > 50 ? 'text-red-500' : 'text-yellow-500'}">
                                ${isClean ? 'Clean' : `Severity ${highestSeverity}`}
                            </div>
                        </div>
                    </div>`;

                // Start building HTML content
                let html = '';

                // Scan Info Section
                if (results.scan_info && results.scan_info.target) {
                    html += `
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4 mb-4">
                        <div class="text-sm text-gray-400">
                            <div class="font-medium text-gray-300 mb-1">Target Information</div>
                            <div class="font-mono break-all">${results.scan_info.target}</div>
                            ${results.scan_info.rules_file ? 
                                `<div class="mt-1 text-gray-500">Rules: ${results.scan_info.rules_file}</div>` : ''}
                        </div>
                    </div>`;
                }

                // Clean State Message
                if (isClean) {
                    html += `
                    <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                        <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span class="text-green-500 font-medium">No threats detected - File is clean</span>
                        <span class="text-green-400 text-sm mt-1">All YARA rules passed successfully</span>
                    </div>`;
                    tools.yara.element.innerHTML = html;
                    return;
                }

                // Sort matches by severity for threat cases
                const sortedMatches = [...matches].sort((a, b) => 
                    (parseInt(b.metadata?.severity) || 0) - (parseInt(a.metadata?.severity) || 0)
                );

                // Format metadata labels
                const formatMetadataLabel = (key) => {
                    const labels = {
                        'threat_name': 'Threat',
                        'rule_filepath': 'Rule File',
                        'creation_date': 'Created',
                        'id': 'Rule ID'
                    };
                    return labels[key] || key;
                };

                // Matches Section
                html += sortedMatches.map((match, index) => {
                    const strings = Array.isArray(match.strings) ? match.strings : [];
                    const severity = parseInt(match.metadata?.severity || 0);
                    const metadataOrder = ['threat_name', 'rule_filepath', 'creation_date', 'id'];
            
                    return `
                    <div class="bg-gray-900/30 rounded-lg border ${severity > 50 ? 'border-red-500/20' : 'border-yellow-500/20'} 
                               hover:${severity > 50 ? 'border-red-500/30' : 'border-yellow-500/30'} transition-colors mb-4">
                        <div class="p-4">
                            <div class="flex items-center justify-between mb-2">
                                <div class="flex items-center space-x-2">
                                    <div class="w-6 h-6 flex items-center justify-center ${severity > 50 ? 'bg-red-500/10' : 'bg-yellow-500/10'} rounded">
                                        <span class="${severity > 50 ? 'text-red-500' : 'text-yellow-500'} text-xs">#${index + 1}</span>
                                    </div>
                                    <span class="${severity > 50 ? 'text-red-500' : 'text-yellow-500'} text-sm">${match.rule}</span>
                                </div>
                                <div class="flex items-center space-x-2">
                                    <span class="px-1.5 py-0.5 text-xs ${severity > 50 ? 'bg-red-500/10 text-red-500' : 'bg-yellow-500/10 text-yellow-500'} rounded">
                                        Severity: ${severity}
                                    </span>
                                </div>
                            </div>

                            <!-- Metadata Section -->
                            ${Object.keys(match.metadata || {}).length > 0 ? `
                                <div class="mb-6 pl-11">
                                    <div class="p-4 bg-gray-900/50 rounded-lg border border-gray-800">
                                        <div class="grid grid-cols-2 gap-2">
                                            ${metadataOrder
                                                .filter(key => match.metadata[key])
                                                .map(key => `
                                                    <div class="bg-gray-900/30 rounded p-1.5">
                                                        <div class="flex justify-between items-center">
                                                            <span class="text-gray-500 text-xs">${formatMetadataLabel(key)}:</span>
                                                            <span class="text-gray-300 ml-2 text-xs font-mono">${match.metadata[key]}</span>
                                                        </div>
                                                    </div>
                                                `).join('')}
                                        </div>
                                    </div>
                                </div>
                            ` : ''}

                            <!-- Strings Section -->
                            ${strings.length > 0 ? `
                                <div class="pl-11">
                                    <div class="text-sm font-medium text-gray-400 mb-3">String Matches</div>
                                    <div class="space-y-3">
                                        ${strings.map(str => `
                                            <div class="bg-gray-900/30 rounded p-3">
                                                <div class="flex items-center justify-between mb-2">
                                                    <div class="flex items-center space-x-2">
                                                        <span class="text-xs text-gray-500 font-mono">${str.offset}</span>
                                                        ${str.identifier ? 
                                                            `<span class="text-xs px-2 py-0.5 bg-gray-800 rounded text-gray-400">${str.identifier}</span>` : ''}
                                                        ${str.data_type ? 
                                                            `<span class="text-xs px-2 py-0.5 bg-gray-800 rounded text-gray-400">${str.data_type}</span>` : ''}
                                                    </div>
                                                    <button 
                                                        onclick="navigator.clipboard.writeText('${str.data.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;')}')"
                                                        class="px-2 py-0.5 text-xs text-gray-500 hover:text-gray-300 transition-colors">
                                                        Copy
                                                    </button>
                                                </div>
                                                <pre class="text-sm text-gray-300 font-mono whitespace-pre-wrap break-all max-h-32 overflow-y-auto">${str.data}</pre>
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>`;
                }).join('');

                tools.yara.element.innerHTML = html;
            },
    },

    pe_sieve: {
            element: document.getElementById('peSieveResults'),
            render: (results) => {
                if (results.status === 'error') {
                    tools.pe_sieve.element.innerHTML = `
                        <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                            <div class="flex items-center space-x-2 text-red-500">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <span>${results.error}</span>
                            </div>
                        </div>`;
                    return;
                }

                const findings = results.findings;
                const isClean = findings.total_suspicious === 0;

                // Stats Section with Clean State
                const statsHtml = `
                    <div class="grid grid-cols-3 gap-4 mb-6">
                        <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-green-500/30' : 'border-red-500/30'} p-4">
                            <div class="text-sm text-gray-500">Status</div>
                            <div class="text-2xl font-semibold ${isClean ? 'text-green-500' : 'text-red-500'}">
                                ${isClean ? 'Clean' : 'Suspicious'}
                            </div>
                        </div>
                        <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                            <div class="text-sm text-gray-500">Total Scanned</div>
                            <div class="text-2xl font-semibold text-gray-300">${findings.total_scanned}</div>
                        </div>
                        <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-gray-800' : 'border-red-500/30'} p-4">
                            <div class="text-sm text-gray-500">Suspicious</div>
                            <div class="text-2xl font-semibold ${isClean ? 'text-gray-300' : 'text-red-500'}">
                                ${findings.total_suspicious}
                            </div>
                        </div>
                    </div>`;

                // Clean State Message
                if (isClean) {
                    tools.pe_sieve.element.innerHTML = statsHtml + `
                        <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                            <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <span class="text-green-500 font-medium">No suspicious activities detected - Process is clean</span>
                            <span class="text-green-400 text-sm mt-1">PE analysis completed successfully</span>
                        </div>`;
                    return;
                }

                // Detailed Findings Section (only shown when suspicious activities are detected)
                const detailsHtml = `
                    <div class="grid grid-cols-3 gap-4">
                        ${[
                            { label: 'Hooked', value: findings.hooked },
                            { label: 'Replaced', value: findings.replaced },
                            { label: 'Headers Modified', value: findings.hdrs_modified },
                            { label: 'IAT Hooks', value: findings.iat_hooks },
                            { label: 'Implanted', value: findings.implanted },
                            { label: 'Implanted PE', value: findings.implanted_pe },
                            { label: 'Implanted shc', value: findings.implanted_shc },
                            { label: 'Unreachable', value: findings.unreachable },
                            { label: 'Other', value: findings.other },
                        ]
                            .map(item => `
                                <div class="bg-gray-900/30 rounded-lg border ${item.value > 0 ? 'border-red-500/30' : 'border-red-900/10'} p-4">
                                    <div class="text-sm text-gray-500">${item.label}</div>
                                    <div class="text-xl font-semibold ${item.value > 0 ? 'text-red-500' : 'text-gray-300'}">${item.value}</div>
                                </div>`)
                            .join('')}
                    </div>`;

                tools.pe_sieve.element.innerHTML = statsHtml + detailsHtml;

                // Raw Output Section (only shown when suspicious activities are detected)
                if (findings.raw_output) {
                    tools.pe_sieve.element.innerHTML += `
                    <div class="mt-6 bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="flex items-center justify-between mb-2">
                            <span class="text-sm font-medium text-gray-300">Raw Analysis Output</span>
                            <button 
                                onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.textContent).then(() => { this.textContent = 'Copied!'; setTimeout(() => { this.textContent = 'Copy'; }, 2000); })" 
                                class="px-2 py-1 text-xs text-gray-400 hover:text-white border border-gray-700 rounded hover:border-gray-600 transition-colors">
                                Copy
                            </button>
                        </div>
                        <pre class="text-xs font-mono text-gray-400 whitespace-pre-wrap overflow-x-auto">${findings.raw_output}</pre>
                    </div>`;
                }
            },
    },

    moneta: {
            element: document.getElementById('monetaResults'),
            render: (results) => {
                if (results.status === 'error') {
                    tools.moneta.element.innerHTML = `
                        <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                            <div class="flex items-center space-x-2 text-red-500">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <span>${results.error}</span>
                            </div>
                        </div>`;
                    return;
                }

                const findings = results.findings;
                const isClean = (!findings.total_private_rx && !findings.total_private_rwx && 
                    !findings.total_modified_code && !findings.total_inconsistent_x &&
                    !findings.total_heap_executable && !findings.total_modified_pe_header &&
                    !findings.total_missing_peb && !findings.total_mismatching_peb) ||
                    (findings.total_unsigned_modules > 0 && 
                     !findings.total_private_rx && !findings.total_private_rwx && 
                     !findings.total_modified_code && !findings.total_inconsistent_x &&
                     !findings.total_heap_executable && !findings.total_modified_pe_header &&
                     !findings.total_missing_peb && !findings.total_mismatching_peb);

                let html = '';

                // Process Info Section
                if (findings.process_info) {
                    html += `
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4 mb-4">
                        <div class="flex items-center justify-between mb-2">
                            <div class="text-sm text-gray-500">Process Information</div>
                            ${findings.scan_duration ? 
                                `<div class="text-sm text-gray-500">Scan Duration: ${findings.scan_duration.toFixed(2)}s</div>` : ''}
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <div class="text-sm text-gray-500">Process Name</div>
                                <div class="text-base text-gray-300">${findings.process_info.name}</div>
                            </div>
                            <div>
                                <div class="text-sm text-gray-500">Process ID</div>
                                <div class="text-base text-gray-300">${findings.process_info.pid}</div>
                            </div>
                            <div>
                                <div class="text-sm text-gray-500">Architecture</div>
                                <div class="text-base text-gray-300">${findings.process_info.arch}</div>
                            </div>
                            <div>
                                <div class="text-sm text-gray-500">Path</div>
                                <div class="text-base text-gray-300 truncate" title="${findings.process_info.path}">${findings.process_info.path}</div>
                            </div>
                        </div>
                    </div>`;
                }

                // Stats Overview with Status
                html += `
                <div class="grid grid-cols-3 gap-4 mb-6">
                    <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-green-500/30' : 'border-red-500/30'} p-4">
                        <div class="text-sm text-gray-500">Status</div>
                        <div class="text-2xl font-semibold ${isClean ? 'text-green-500' : 'text-red-500'}">
                            ${isClean ? 'Clean' : 'Suspicious'}
                        </div>
                    </div>
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Total Regions</div>
                        <div class="text-2xl font-semibold text-gray-300">${findings.total_regions}</div>
                    </div>
                    <div class="bg-gray-900/30 rounded-lg border ${findings.threads.length > 0 ? 'border-blue-500/30' : 'border-gray-800'} p-4">
                        <div class="text-sm text-gray-500">Threads</div>
                        <div class="text-2xl font-semibold text-blue-500">${findings.threads.length}</div>
                    </div>
                </div>`;

                // For clean scans, show success message and return
                if (isClean) {
                    html += `
                    <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                        <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span class="text-green-500 font-medium">No suspicious activities detected - Process is clean</span>
                        <span class="text-green-400 text-sm mt-1">
                            ${findings.total_unsigned_modules > 0 ? 
                                `Note: ${findings.total_unsigned_modules} unsigned module(s) found, but no suspicious behavior detected` : 
                                'Memory analysis completed successfully'}
                        </span>
                    </div>`;
                    
                    tools.moneta.element.innerHTML = html;
                    return;
                }

                // Detailed Findings - Only shown for suspicious scans
                html += `
                <div class="grid grid-cols-3 gap-4">
                    ${[
                        { label: 'Private RWX', value: findings.total_private_rwx },
                        { label: 'Private RX', value: findings.total_private_rx },
                        { label: 'Modified Code', value: findings.total_modified_code },
                        { label: 'Heap Executable', value: findings.total_heap_executable },
                        { label: 'Modified PE Header', value: findings.total_modified_pe_header },
                        { label: 'Inconsistent X', value: findings.total_inconsistent_x },
                        { label: 'Missing PEB', value: findings.total_missing_peb },
                        { label: 'Mismatching PEB', value: findings.total_mismatching_peb },
                        { label: 'Unsigned Modules', value: findings.total_unsigned_modules },
                    ]
                        .map(item => `
                            <div class="bg-gray-900/30 rounded-lg border ${item.value > 0 ? 'border-red-500/30' : 'border-red-900/10'} p-4">
                                <div class="text-sm text-gray-500">${item.label}</div>
                                <div class="text-xl font-semibold ${item.value > 0 ? 'text-red-500' : 'text-gray-300'}">${item.value}</div>
                            </div>`)
                        .join('')}
                </div>`;

                // Suspicious Findings Summary
                html += `
                <div class="mt-6 bg-red-500/10 rounded-lg border border-red-900/20 p-4">
                    <div class="flex items-center space-x-2 mb-3">
                        <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <span class="text-sm font-medium text-red-500">Suspicious Activity Detected</span>
                    </div>
                    <div class="space-y-2 text-sm text-gray-400">
                        ${[
                            { condition: findings.total_private_rwx > 0, message: `Critical: Found ${findings.total_private_rwx} private RWX region(s)`, type: 'critical' },
                            { condition: findings.total_heap_executable > 0, message: `Critical: Found ${findings.total_heap_executable} executable heap region(s)`, type: 'critical' },
                            { condition: findings.total_modified_code > 0, message: `Critical: Detected ${findings.total_modified_code} modified code region(s)`, type: 'critical' },
                            { condition: findings.total_modified_pe_header > 0, message: `Critical: Found ${findings.total_modified_pe_header} modified PE header(s)`, type: 'critical' },
                            { condition: findings.total_private_rx > 0, message: `Warning: Found ${findings.total_private_rx} private RX region(s)`, type: 'warning' },
                            { condition: findings.total_inconsistent_x > 0, message: `Warning: Found ${findings.total_inconsistent_x} region(s) with inconsistent executable permissions`, type: 'warning' },
                            { condition: findings.total_missing_peb > 0, message: `Warning: Found ${findings.total_missing_peb} missing PEB module(s)`, type: 'warning' },
                            { condition: findings.total_mismatching_peb > 0, message: `Warning: Found ${findings.total_mismatching_peb} mismatching PEB module(s)`, type: 'warning' }
                        ]
                            .filter(item => item.condition)
                            .map(item => `
                                <div class="flex items-center space-x-2">
                                    <svg class="w-4 h-4 ${item.type === 'critical' ? 'text-red-500' : 'text-yellow-500'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                    <span>${item.message}</span>
                                </div>`)
                            .join('')}
                    </div>
                </div>`;
                // Add raw output for suspicious scans
                if (!isClean && findings.raw_output) {
                    html += `
                    <div class="mt-6 bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="flex items-center justify-between mb-2">
                            <span class="text-sm font-medium text-gray-300">Raw Analysis Output</span>
                            <button 
                                onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.textContent).then(() => { this.textContent = 'Copied!'; setTimeout(() => { this.textContent = 'Copy'; }, 2000); })" 
                                class="px-2 py-1 text-xs text-gray-400 hover:text-white border border-gray-700 rounded hover:border-gray-600 transition-colors">
                                Copy
                            </button>
                        </div>
                        <pre class="text-xs font-mono text-gray-400 whitespace-pre-wrap overflow-x-auto">${findings.raw_output}</pre>
                    </div>`;
                }
                tools.moneta.element.innerHTML = html;
            }
    },

    checkplz: {
        element: document.getElementById('threatCheckResults'),
        statsElement: document.getElementById('threatCheckStats'),
        render: (results) => {
            if (results.status === 'error') {
                tools.checkplz.element.innerHTML = `
                    <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                        <div class="flex items-center space-x-2 text-red-500">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <span>${results.error}</span>
                        </div>
                    </div>`;
                return;
            }

            const findings = results.findings || {};
            const scanResults = findings.scan_results || {};
            const isClean = !findings.initial_threat && !scanResults.detection_offset;

            // Stats Section
            tools.checkplz.statsElement.innerHTML = `
                <div class="grid grid-cols-3 gap-4 mb-6">
                    <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-green-500/30' : 'border-red-500/30'} p-4">
                        <div class="text-sm text-gray-500">Status</div>
                        <div class="text-xl font-semibold ${isClean ? 'text-green-500' : 'text-red-500'}">
                            ${isClean ? 'Clean' : (findings.initial_threat || 'Unknown Threat')}
                        </div>
                    </div>
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Scan Duration</div>
                        <div class="text-xl font-semibold text-gray-400">
                            ${typeof scanResults.scan_duration === 'number' ? scanResults.scan_duration.toFixed(3) + 's' : 'N/A'}
                        </div>
                    </div>
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Search Iterations</div>
                        <div class="text-xl font-semibold text-gray-400">
                            ${scanResults.search_iterations || 'N/A'}
                        </div>
                    </div>
                </div>`;

            let html = '';

            // File Information Section
            html += `
            <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4 mb-6">
                <div class="text-sm font-medium text-gray-300 mb-3">File Information</div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <div class="text-sm text-gray-500">File Path</div>
                        <div class="text-sm text-gray-300 font-mono break-all">
                            ${scanResults.file_path || 'N/A'}
                        </div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-500">File Size</div>
                        <div class="text-sm text-gray-300">
                            ${scanResults.file_size || 'N/A'}
                        </div>
                    </div>
                </div>
            </div>`;

            // Clean State Message
            if (isClean) {
                html += `
                <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                    <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span class="text-green-500 font-medium">No threats detected - File is clean</span>
                    <span class="text-green-400 text-sm mt-1">Security scan completed successfully</span>
                </div>`;
            } else {
                // Detection Details Section
                if (scanResults.detection_offset) {
                    html += `
                    <div class="bg-red-500/10 rounded-lg border border-red-900/20 p-4 mb-6">
                        <div class="flex items-center space-x-2 mb-3">
                            <svg class="w-5 h-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                            </svg>
                            <span class="text-sm font-medium text-red-500">Threat Detection Details</span>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <div class="text-sm text-gray-500">Detection Offset</div>
                                <div class="text-sm text-red-500 font-mono">${scanResults.detection_offset}</div>
                            </div>
                            <div>
                                <div class="text-sm text-gray-500">Relative Location</div>
                                <div class="text-sm text-red-500">${scanResults.relative_location}</div>
                            </div>
                            <div class="col-span-2">
                                <div class="text-sm text-gray-500">Final Threat Detection</div>
                                <div class="text-sm text-red-500">${scanResults.final_threat_detection}</div>
                            </div>
                        </div>
                    </div>`;
                }

                // Hex Dump Section (only shown when threats are detected)
                if (scanResults.hex_dump) {
                    html += `
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-sm font-medium text-gray-300">Showing ±128 bytes around detection point</span>
                            <button 
                                onclick="navigator.clipboard.writeText(this.parentElement.nextElementSibling.textContent)"
                                class="px-2 py-1 text-xs text-gray-400 hover:text-white border border-gray-700 rounded hover:border-gray-600 transition-colors">
                                Copy
                            </button>
                        </div>
                        <pre class="text-base font-mono text-gray-400 whitespace-pre-wrap overflow-x-auto p-4 bg-gray-900/50 rounded-lg leading-relaxed">${scanResults.hex_dump}</pre>
                    </div>`;
                }
            }

            tools.checkplz.element.innerHTML = html;
        }
    },


    patriot: {
        element: document.getElementById('patriotResults'),
        statsElement: document.getElementById('patriotStats'),
        render: (results) => {
            if (results.status === 'error') {
                return tools.patriot.element.innerHTML = `
                    <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                        <div class="flex items-center space-x-2 text-red-500">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <span>${results.error}</span>
                        </div>
                    </div>`;
            }

            const data = results.findings;
            const processInfo = data.process_info || {};
            const memoryStats = data.memory_stats || {};
            const scanSummary = data.scan_summary || {};
            const detailedFindings = data.findings || [];
            const isClean = detailedFindings.length === 0;

            tools.patriot.statsElement.innerHTML = `
                <div class="grid grid-cols-3 gap-4 mb-6">
                    <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-green-500/30' : 'border-red-500/30'} p-4">
                        <div class="text-sm text-gray-500">Status</div>
                        <div class="text-2xl font-semibold ${isClean ? 'text-green-500' : 'text-red-500'}">
                            ${isClean ? 'Clean' : 'Suspicious'}
                        </div>
                    </div>
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Memory Regions</div>
                        <div class="text-2xl font-semibold text-gray-300">${memoryStats.total_regions || 0}</div>
                    </div>
                    <div class="bg-gray-900/30 rounded-lg border ${isClean ? 'border-gray-800' : 'border-red-500/30'} p-4">
                        <div class="text-sm text-gray-500">Total Findings</div>
                        <div class="text-2xl font-semibold ${isClean ? 'text-gray-300' : 'text-red-500'}">${scanSummary.total_findings || 0}</div>
                    </div>
                </div>`;

            let html = `
            <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4 mb-6">
                <div class="text-sm font-medium text-gray-300 mb-3">Process Information</div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <div class="text-sm text-gray-500">PID</div>
                        <div class="text-sm text-gray-300">${processInfo.pid || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-500">Process Name</div>
                        <div class="text-sm text-gray-300">${processInfo.process_name || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-500">Elevation Status</div>
                        <div class="text-sm text-gray-300">${processInfo.elevation_status || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-500">Memory Usage</div>
                        <div class="text-sm text-gray-300">
                            Private: ${memoryStats.private_memory} MB | 
                            Executable: ${memoryStats.executable_memory} MB
                        </div>
                    </div>
                </div>
            </div>`;

            if (isClean) {
                html += `
                <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                    <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <span class="text-green-500 font-medium">No threats detected - Process is clean</span>
                    <span class="text-green-400 text-sm mt-1">Scan completed in ${scanSummary.duration || 0} seconds</span>
                </div>`;
            } else {
                // Findings Type Summary
                const findingTypes = scanSummary.findings_by_type || {};
                html += `
                <div class="mb-6">
                    <div class="grid grid-cols-3 gap-4">
                        ${Object.entries(findingTypes).map(([type, count]) => `
                            <div class="bg-gray-900/30 rounded-lg border border-red-500/30 p-4">
                                <div class="text-sm text-gray-500">${type}</div>
                                <div class="text-xl font-semibold text-red-500">${count}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="space-y-4">
                    ${detailedFindings.map(finding => `
                        <div class="bg-gray-900/30 rounded-lg border border-red-500/20 hover:border-red-500/30 transition-colors">
                            <div class="p-4">
                                <div class="flex items-center justify-between mb-2">
                                    <div class="flex items-center space-x-2">
                                        <div class="w-6 h-6 flex items-center justify-center bg-red-500/10 rounded">
                                            <span class="text-red-500 text-xs">#${finding.finding_number}</span>
                                        </div>
                                        <span class="text-red-500 text-sm">${finding.type}</span>
                                    </div>
                                    <span class="text-xs text-gray-500">${finding.timestamp}</span>
                                </div>

                                <div class="pl-8 space-y-2">
                                    <div class="flex items-center space-x-2 text-sm">
                                        <span class="text-gray-500">Process:</span>
                                        <span class="text-gray-300">${finding.process_name} (PID: ${finding.pid})</span>
                                    </div>
                                    <div class="flex items-center space-x-2 text-sm">
                                        <span class="text-gray-500">Level:</span>
                                        <span class="text-gray-300">${finding.level}</span>
                                    </div>
                                    <div class="text-sm">
                                        <div class="text-gray-500 mb-1">Details:</div>
                                        <div class="text-gray-300 font-mono">${finding.details}</div>
                                    </div>

                                    ${finding.parsed_details ? `
                                        <div class="text-sm">
                                            <div class="text-gray-500 mb-1">Parsed Details:</div>
                                            <div class="grid grid-cols-2 gap-2">
                                                ${Object.entries(finding.parsed_details).map(([key, value]) => `
                                                    <div class="bg-gray-900/50 rounded p-2">
                                                        <span class="text-gray-500">${key}:</span>
                                                        <span class="text-gray-300 font-mono ml-2">${value}</span>
                                                    </div>
                                                `).join('')}
                                            </div>
                                        </div>
                                    ` : ''}

                                    ${finding.module_information ? `
                                        <div class="mt-4 bg-gray-900/50 rounded p-3">
                                            <div class="text-sm text-gray-500 mb-2">Module Information</div>
                                            ${Object.entries(finding.module_information).map(([key, value]) => `
                                                <div class="flex items-center space-x-2 text-sm">
                                                    <span class="text-gray-500">${key}:</span>
                                                    <span class="text-gray-300 font-mono">${value}</span>
                                                </div>
                                            `).join('')}
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>`;
            }

            tools.patriot.element.innerHTML = html;
        }
    },
    
    hsb: {
        element: document.getElementById('hsbResults'),
        statsElement: document.getElementById('hsbStats'),
        render: (results) => {
            // 1) Handle errors
            if (results.status === 'error') {
                return tools.hsb.element.innerHTML = `
                    <div class="bg-red-500/10 border border-red-900/20 rounded-lg p-4">
                        <div class="flex items-center space-x-2 text-red-500">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                    d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            <span>${results.error}</span>
                        </div>
                    </div>`;
            }

            // 2) Pull parsed data from the Python output
            const data = results.findings || {};
            const summary = data.summary || {};

            // Use the first detection (if any) to show process_name and PID in UI
            const firstDetection = (data.detections && data.detections.length > 0)
                ? data.detections[0]
                : null;

            // Safely check if there's any process or any findings
            const hasFindings = !!(
                firstDetection &&
                firstDetection.findings &&
                firstDetection.findings.length > 0
            );

            // Extract process_name and pid if we do have a detection
            const processName = firstDetection?.process_name ?? 'N/A';
            const processPid  = firstDetection?.pid ?? 'N/A';

            // 3) Severity styling & icons
            const severityConfig = {
                'CRITICAL': {
                    color: 'text-red-600 border-red-600/30 bg-red-500/10',
                    icon: `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>`
                },
                'HIGH': {
                    color: 'text-red-500 border-red-500/30 bg-red-400/10',
                    icon: `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>`
                },
                'MID': {
                    color: 'text-yellow-500 border-yellow-500/30 bg-yellow-500/10',
                    icon: `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                    </svg>`
                },
                'LOW': {
                    color: 'text-blue-500 border-blue-500/30 bg-blue-500/10',
                    icon: `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>`
                }
            };

            // 4) Render stats section
            //    We'll display (a) total findings, (b) threads, (c) optional PID, etc.
            tools.hsb.statsElement.innerHTML = `
                <div class="grid grid-cols-5 gap-4 mb-6">
                    <!-- Status tile -->
                    <div class="bg-gray-900/30 rounded-lg border
                        ${hasFindings ? 'border-red-500/30' : 'border-green-500/30'} p-4">
                        <div class="text-sm text-gray-500">Status</div>
                        <div class="text-2xl font-semibold ${hasFindings ? 'text-red-500' : 'text-green-500'}">
                            ${hasFindings ? 'Suspicious' : 'Clean'}
                        </div>
                    </div>
                    
                    <!-- Total findings -->
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Findings</div>
                        <div class="text-2xl font-semibold text-gray-300">${summary.total_findings || 0}</div>
                    </div>

                    <!-- Threads analyzed -->
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Threads Analyzed</div>
                        <div class="text-2xl font-semibold text-gray-300">${summary.scanned_threads || 0}</div>
                    </div>

                    <!-- PID from the first detection (or N/A) -->
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">PID</div>
                        <div class="text-2xl font-semibold text-gray-300">${processPid}</div>
                    </div>

                    <!-- Scan Duration -->
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4">
                        <div class="text-sm text-gray-500">Scan Duration</div>
                        <div class="text-2xl font-semibold text-gray-300">
                            ${(summary.duration || 0).toFixed(3)}s
                        </div>
                    </div>
                </div>
            `;

            // 5) Render the findings section
            let html = '';

            if (!hasFindings) {
                // No suspicious findings => show a "clean" message
                html = `
                    <div class="flex flex-col items-center justify-center py-8 bg-green-500/10 rounded-lg border border-green-500/20">
                        <svg class="w-12 h-12 text-green-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span class="text-green-500 font-medium">No suspicious behavior detected</span>
                        <span class="text-green-400 text-sm mt-1">
                            Process ${processName} (PID: ${processPid}) is clean
                        </span>
                    </div>`;
            } else {
                // If we do have findings, build them out
                const findingsByThread = {};
                firstDetection.findings.forEach(finding => {
                    const threadId = finding.thread_id || 'process';
                    if (!findingsByThread[threadId]) {
                        findingsByThread[threadId] = [];
                    }
                    findingsByThread[threadId].push(finding);
                });

                html = `
                    <div class="space-y-4">
                        <div class="flex items-center space-x-2 mb-4">
                            <span class="text-red-500 font-medium text-lg">${processName}</span>
                            <span class="text-sm text-gray-500">(PID: ${processPid})</span>
                        </div>
                        
                        ${Object.entries(findingsByThread).map(([threadId, findings]) => `
                            <div class="bg-gray-900/30 rounded-lg border border-red-500/20">
                                <div class="p-3 border-b border-gray-800">
                                    <span class="text-gray-300 font-medium">
                                        ${threadId === 'process' ? 'Process-wide Findings' : `Thread ${threadId}`}
                                    </span>
                                </div>
                                <div class="p-4 space-y-3">
                                    ${findings.map(finding => {
                                        const severity = severityConfig[finding.severity] || severityConfig.LOW;
                                        return `
                                            <div class="bg-gray-900/50 rounded border ${severity.color.split(' ')[1]} p-4">
                                                <div class="flex items-center justify-between mb-2">
                                                    <div class="flex items-center space-x-2">
                                                        ${severity.icon}
                                                        <span class="font-medium ${severity.color.split(' ')[0]}">
                                                            ${finding.type}
                                                        </span>
                                                    </div>
                                                    <span class="px-2 py-0.5 text-xs rounded-full ${severity.color}">
                                                        ${finding.severity}
                                                    </span>
                                                </div>
                                                ${finding.description ? `
                                                    <div class="text-sm text-gray-300 mt-2">${finding.description}</div>
                                                ` : ''}

                                                ${finding.details && Object.keys(finding.details).length > 0 ? `
                                                    <div class="mt-2 pt-2 border-t border-gray-800">
                                                        ${Object.entries(finding.details)
                                                            .filter(([key]) => key !== 'issue' && key !== 'condition')
                                                            .map(([key, value]) => `
                                                                <div class="text-sm">
                                                                    <span class="text-gray-500">
                                                                        ${key.replace(/_/g, ' ')}:
                                                                    </span>
                                                                    <span class="text-gray-300 font-mono ml-2">
                                                                        ${value}
                                                                    </span>
                                                                </div>
                                                            `).join('')}
                                                    </div>
                                                ` : ''}
                                            </div>
                                        `;
                                    }).join('')}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `;
            }

            tools.hsb.element.innerHTML = html;
        }
    },
    
    summary: {
        element: document.getElementById('summaryWrapper'),
        statsElement: document.getElementById('scannerResultsBody'),
        render: (results) => {
            // 1) Grab the new container where we'll show file/process info
            const targetDetailsEl = document.getElementById('targetDetails');
            
            const filePath = results.checkplz?.findings?.scan_results?.file_path || 
                           
                           'No file path available';
            
            targetDetailsEl.innerHTML = `
                <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4 mb-4">
                    <h4 class="text-base font-medium text-gray-100 mb-2">Target File</h4>
                    <p class="text-gray-300">
                        <span class="font-semibold">File Path:</span> 
                        ${filePath}
                    </p>
                </div>
                `;
            // or if we have process info (Moneta’s approach)
            if (results.moneta?.findings?.process_info) {
                const info = results.moneta.findings.process_info;
                targetDetailsEl.innerHTML = `
                    <div class="bg-gray-900/30 rounded-lg border border-gray-800 p-4 mb-4">
                        <h4 class="text-base font-medium text-gray-100 mb-2">Target Process</h4>
                        <p class="text-gray-300">
                            <span class="font-semibold">Name:</span> ${info.name}<br />
                            <span class="font-semibold">PID:</span> ${info.pid}<br />
                            <span class="font-semibold">Path:</span> <span class="text-gray-400">${info.path}</span>
                        </p>
                    </div>
                `;
            }

            // 4) Now proceed with existing logic to build the table rows
            let totalDetections = 0;
            const rows = [];

            // Example for YARA results
            if (results.yara) {
                const matches = Array.isArray(results.yara.matches) ? results.yara.matches : [];
                totalDetections += matches.length;
                rows.push(`
                    <tr>
                        <td class="px-6 py-4 text-base text-gray-300">YARA</td> <!-- Updated font size -->
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-base rounded ${matches.length > 0 ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}">
                                ${matches.length > 0 ? 'Suspicious' : 'Clean'}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-base ${matches.length > 0 ? 'text-red-500' : 'text-gray-400'}">${matches.length}</td> <!-- Updated font size -->
                        <td class="px-6 py-4 text-base text-gray-400"> <!-- Updated font size -->
                            ${matches.length > 0 ? `${matches.length} rule matches found` : 'No threats detected'}
                        </td>
                    </tr>
                `);
            }
            // PE-sieve results
            if (results.pe_sieve) {
                const findings = results.pe_sieve.findings || {};
                const suspicious = findings.total_suspicious || 0;
                totalDetections += suspicious;
                rows.push(`
                    <tr>
                        <td class="px-6 py-4 text-base text-gray-300">PE-sieve</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-base rounded ${suspicious > 0 ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}">
                                ${suspicious > 0 ? 'Suspicious' : 'Clean'}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-base ${suspicious > 0 ? 'text-red-500' : 'text-gray-400'}">${suspicious}</td>
                        <td class="px-6 py-4 text-base text-gray-400">
                            ${suspicious > 0 ? `${suspicious} suspicious modifications found` : 'No modifications detected'}
                        </td>
                    </tr>
                `);
            }

            // Moneta results
            if (results.moneta) {
                const findings = results.moneta.findings || {};
                // Count all possible suspicious indicators
                const suspicious = (findings.total_private_rwx || 0) + 
                                  (findings.total_private_rx || 0) + 
                                  (findings.total_modified_code || 0) + 
                                  (findings.total_heap_executable || 0) + 
                                  (findings.total_modified_pe_header || 0) + 
                                  (findings.total_inconsistent_x || 0) + 
                                  (findings.total_missing_peb || 0) + 
                                  (findings.total_mismatching_peb || 0);
                                  
                // Check if scan is clean (same logic as moneta.render)
                const isClean = (!findings.total_private_rx && !findings.total_private_rwx && 
                                !findings.total_modified_code && !findings.total_inconsistent_x &&
                                !findings.total_heap_executable && !findings.total_modified_pe_header &&
                                !findings.total_missing_peb && !findings.total_mismatching_peb) ||
                                (findings.total_unsigned_modules > 0 && 
                                 !findings.total_private_rx && !findings.total_private_rwx && 
                                 !findings.total_modified_code && !findings.total_inconsistent_x &&
                                 !findings.total_heap_executable && !findings.total_modified_pe_header &&
                                 !findings.total_missing_peb && !findings.total_mismatching_peb);

                totalDetections += suspicious;
                rows.push(`
                    <tr>
                        <td class="px-6 py-4 text-v text-gray-300">Moneta</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-base rounded ${!isClean ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}">
                                ${!isClean ? 'Suspicious' : 'Clean'}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-base ${!isClean ? 'text-red-500' : 'text-gray-400'}">${suspicious}</td>
                        <td class="px-6 py-4 text-base text-gray-400">
                            ${!isClean ? `Memory anomalies found` : 'No anomalies detected'}
                        </td>
                    </tr>
                `);
            }

            // ThreatCheck results
            if (results.checkplz) {
                const findings = results.checkplz.findings || {};
                const hasDetection = findings.scan_results?.detection_offset;
                if (hasDetection) totalDetections++;
                rows.push(`
                    <tr>
                        <td class="px-6 py-4 text-base text-gray-300">CheckPlz</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-base rounded ${hasDetection ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}">
                                ${hasDetection ? 'Suspicious' : 'Clean'}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-base ${hasDetection ? 'text-red-500' : 'text-gray-400'}">${hasDetection ? '1' : '0'}</td>
                        <td class="px-6 py-4 text-base text-gray-400">
                            ${hasDetection ? findings.initial_threat || 'Threat detected' : 'No threats detected'}
                        </td>
                    </tr>
                `);
            }

            // Patriot results
            if (results.patriot) {
                const findings = results.patriot.findings || {};
                const totalFindings = findings.findings?.length || 0;
                totalDetections += totalFindings;
                rows.push(`
                    <tr>
                        <td class="px-6 py-4 text-base text-gray-300">Patriot</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-base rounded ${totalFindings > 0 ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}">
                                ${totalFindings > 0 ? 'Suspicious' : 'Clean'}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-base ${totalFindings > 0 ? 'text-red-500' : 'text-gray-400'}">${totalFindings}</td>
                        <td class="px-6 py-4 text-base text-gray-400">
                            ${totalFindings > 0 ? `${totalFindings} suspicious activities found` : 'No suspicious activities'}
                        </td>
                    </tr>
                `);
            }

            // HSB results
            if (results.hsb) {
                const findings = results.hsb.findings || {};
                const totalFindings = findings.summary?.total_findings || 0;
                totalDetections += totalFindings;
                rows.push(`
                    <tr>
                        <td class="px-6 py-4 text-base text-gray-300">Hunt-Sleeping-Beacons</td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 text-base rounded ${totalFindings > 0 ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'}">
                                ${totalFindings > 0 ? 'Suspicious' : 'Clean'}
                            </span>
                        </td>
                        <td class="px-6 py-4 text-base ${totalFindings > 0 ? 'text-red-500' : 'text-gray-400'}">${totalFindings}</td>
                        <td class="px-6 py-4 text-base text-gray-400">
                            ${totalFindings > 0 ? 'Suspicious behavior detected' : 'No suspicious behavior'}
                        </td>
                    </tr>
                `);
            }

            // Update stats
            document.getElementById('totalDetections').textContent = totalDetections;
            document.getElementById('overallStatus').textContent = totalDetections > 0 ? 'Threats Detected' : 'Clean';
            document.getElementById('overallStatus').className = totalDetections > 0 ? 'text-2xl font-semibold text-red-500' : 'text-2xl font-semibold text-green-500';

            // Set table content
            tools.summary.statsElement.innerHTML = rows.join('');
            document.getElementById('scanDuration').textContent = document.getElementById('analysisTimer').textContent;

        }
    },
};

// Initialize Everything
document.addEventListener('DOMContentLoaded', function() {
    const modal = new ModalHandler();
    const analysis = new AnalysisCore();

    // Make modal functions globally available
    window.showDynamicWarning = () => modal.show();
    window.hideDynamicWarning = () => modal.hide();

    // Start analysis if parameters exist
    if (analysis.analysisType && analysis.fileHash) {
        analysis.startAnalysis();
    }
});