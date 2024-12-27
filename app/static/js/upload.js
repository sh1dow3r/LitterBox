// app/static/js/upload.js

// Upload configurations
const UPLOAD_CONFIG = {
    maxFileSize: 16 * 1024 * 1024, // 16MB
    toastDuration: 3000,
    transitionDelay: 300,
    fadeDelay: 50
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const elements = {
        dropZone: document.getElementById('dropZone'),
        fileInput: document.getElementById('fileInput'),
        uploadStatus: document.getElementById('uploadStatus'),
        uploadArea: document.getElementById('uploadArea'),
        fileAnalysisArea: document.getElementById('fileAnalysisArea'),
        fileName: document.getElementById('fileName'),
        fileSize: document.getElementById('fileSize'),
        fileType: document.getElementById('fileType'),
        fileFormat: document.getElementById('fileFormat'),
        fileCategory: document.getElementById('fileCategory'),
        fileEntropy: document.getElementById('fileEntropy'),
        uploadTime: document.getElementById('uploadTime'),
        md5Hash: document.getElementById('md5Hash'),
        sha256Hash: document.getElementById('sha256Hash'),
        fileSpecificInfo: document.getElementById('fileSpecificInfo'),
        step1Circle: document.getElementById('step1Circle'),
        step1Text: document.getElementById('step1Text'),
        step2Circle: document.getElementById('step2Circle'),
        step2Text: document.getElementById('step2Text'),
        progressLine: document.getElementById('progressLine'),
        toastContainer: document.getElementById('toastContainer')
    };

    let currentFileHash = null;
    let dragCounter = 0;

    // Event Listeners
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        elements.dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    elements.dropZone.addEventListener('dragenter', () => {
        dragCounter++;
        if (dragCounter === 1) highlight();
    });

    elements.dropZone.addEventListener('dragleave', () => {
        dragCounter--;
        if (dragCounter === 0) unhighlight();
    });

    elements.dropZone.addEventListener('drop', (e) => {
        dragCounter = 0;
        unhighlight();
        handleDrop(e);
    });

    elements.fileInput.addEventListener('change', handleFiles);

    // Utility Functions
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight() {
        const label = elements.dropZone.querySelector('label');
        const icon = elements.dropZone.querySelector('.upload-icon');

        label.classList.add('scale-[1.02]', 'border-red-500/50');
        icon.classList.add('scale-110');
    }

    function unhighlight() {
        const label = elements.dropZone.querySelector('label');
        const icon = elements.dropZone.querySelector('.upload-icon');

        label.classList.remove('scale-[1.02]', 'border-red-500/50');
        icon.classList.remove('scale-110');
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        const colors = {
            success: 'border-green-900/20 bg-green-500/10 text-green-500',
            error: 'border-red-900/20 bg-red-500/10 text-red-500',
            info: 'border-blue-900/20 bg-blue-500/10 text-blue-500'
        };

        toast.className = `flex items-center space-x-2 p-4 rounded-lg border ${colors[type]} transform translate-y-2 opacity-0 transition-all duration-300 text-base`;
        toast.innerHTML = `
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="${type === 'success' ? 'M5 13l4 4L19 7' : 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'}"/>
            </svg>
            <span>${message}</span>
        `;

        elements.toastContainer.appendChild(toast);
        requestAnimationFrame(() => {
            toast.classList.remove('translate-y-2', 'opacity-0');
        });

        setTimeout(() => {
            toast.classList.add('translate-y-2', 'opacity-0');
            setTimeout(() => toast.remove(), UPLOAD_CONFIG.fadeDelay);
        }, UPLOAD_CONFIG.toastDuration);
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    function updateProgress(step, completed = false) {
        const stepCircle = step === 1 ? elements.step1Circle : elements.step2Circle;
        const stepText = step === 1 ? elements.step1Text : elements.step2Text;

        if (completed && step === 1) {
            stepCircle.classList.remove('bg-red-500/10', 'border-red-500', 'bg-black/50', 'border-gray-700');
            stepCircle.classList.add('bg-green-500/10', 'border-green-500');

            stepText.innerHTML = `
                <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
            `;

            elements.progressLine.classList.remove('to-gray-800');
            elements.progressLine.classList.add('to-red-500/20');

            elements.step2Circle.classList.remove('bg-black/50', 'border-gray-700');
            elements.step2Circle.classList.add('bg-red-500/10', 'border-red-500');
            elements.step2Text.classList.remove('text-gray-500');
            elements.step2Text.classList.add('text-red-500');
        }
    }

    // File Info Functions
    function renderFileTypeSpecificInfo(fileInfo) {
        let html = '';

        if (fileInfo.pe_info) {
            const pe = fileInfo.pe_info;
            html = `
                <div class="space-y-4">
                    <div class="flex items-center justify-between">
                        <h6 class="text-base font-medium text-gray-300">PE File Information</h6>
                        <span class="text-sm text-gray-400">File Type: ${pe.file_type}</span>
                        <span class="text-sm text-gray-400">Compile Time: ${pe.compile_time}</span>
                    </div>
                    <div class="grid grid-cols-3 gap-4">
                        <div>
                            <div class="text-base text-gray-400 mb-1">Machine Type</div>
                            <div class="text-base text-gray-300">${pe.machine_type}</div>
                        </div>
                        <div>
                            <div class="text-base text-gray-400 mb-1">Subsystem</div>
                            <div class="text-base text-gray-300">${pe.subsystem}</div>
                        </div>
                        <div>
                            <div class="text-base text-gray-400 mb-1">Entry Point</div>
                            <div class="text-base font-mono text-gray-300">${pe.entry_point}</div>
                        </div>
                    </div>
                    <div class="space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-base text-gray-400">PE Sections</span>
                            <span class="text-sm text-gray-400">${pe.sections.length} sections</span>
                        </div>
                        <div class="flex flex-wrap gap-2">
                            ${pe.sections.map(section => `
                                <span class="px-2 py-1 text-sm bg-gray-900/50 rounded-lg border border-gray-800 text-gray-400">
                                    ${section}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                    ${pe.imports && pe.imports.length > 0 ? `
                        <div class="space-y-2">
                            <div class="flex items-center justify-between">
                                <span class="text-base text-gray-400">Imported DLLs</span>
                                <span class="text-sm text-gray-400">${pe.imports.length} imports</span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                ${pe.imports.map(imp => `
                                    <span class="px-2 py-1 text-sm bg-gray-900/50 rounded-lg border border-gray-800 text-gray-400">
                                        ${imp}
                                    </span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        } else if (fileInfo.office_info) {
            const office = fileInfo.office_info;
            html = `
                <div class="space-y-4">
                    <h6 class="text-base font-medium text-gray-300">Office Document Information</h6>
                    <div class="flex items-center space-x-4">
                        <div class="flex items-center space-x-2">
                            <span class="text-base text-gray-400">Macros:</span>
                            <span class="px-2 py-1 text-sm rounded-lg ${office.has_macros ? 
                                'bg-red-500/10 text-red-500 border-red-900/20' : 
                                'bg-gray-900/50 text-gray-400 border-gray-800'} border">
                                ${office.has_macros ? 'Present' : 'None'}
                            </span>
                        </div>
                    </div>
                    ${office.macro_info ? `
                        <div class="space-y-2">
                            <div class="text-base text-gray-400">Macro Information</div>
                            <pre class="text-base text-gray-300 bg-gray-900/50 rounded-lg p-4 overflow-x-auto">
                                ${JSON.stringify(office.macro_info, null, 2)}
                            </pre>
                        </div>
                    ` : ''}
                </div>
            `;
        } else {
            html = `
                <div class="text-base text-gray-400 text-center py-4">
                    No specific file information available
                </div>
            `;
        }

        elements.fileSpecificInfo.innerHTML = html;
    }

    function updateFileInfo(fileInfo) {
        currentFileHash = fileInfo.md5;

        elements.fileName.textContent = fileInfo.original_name;
        elements.fileSize.textContent = formatFileSize(fileInfo.size);
        elements.fileType.textContent = fileInfo.extension.toUpperCase();
        elements.fileFormat.textContent = fileInfo.mime_type;
        elements.fileCategory.textContent = fileInfo.extension.toUpperCase();
        elements.fileEntropy.textContent = fileInfo.entropy;
        elements.uploadTime.textContent = formatTimestamp(fileInfo.upload_time);
        elements.md5Hash.textContent = fileInfo.md5;

        elements.sha256Hash.textContent = `${fileInfo.sha256.substring(0, 32)}...`;
        document.getElementById('sha256HashFull').textContent = fileInfo.sha256;

        renderFileTypeSpecificInfo(fileInfo);

        elements.uploadArea.classList.add('opacity-0', 'scale-95');
        setTimeout(() => {
            elements.uploadArea.classList.add('hidden');
            elements.fileAnalysisArea.classList.remove('hidden');
            setTimeout(() => {
                elements.fileAnalysisArea.classList.remove('opacity-0', 'scale-95');
            }, UPLOAD_CONFIG.fadeDelay);
        }, UPLOAD_CONFIG.transitionDelay);

        updateProgress(1, true);
    }

    // File Handling Functions
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 1) {
            showToast('Please upload only one file at a time', 'error');
            return;
        }

        handleFiles({ target: { files } });
    }

    function handleFiles(e) {
        const file = e.target.files[0];
        if (!file) return;

        const extension = file.name.split('.').pop().toLowerCase();
        const allowedExtensions = Array.from(document.querySelectorAll('#dropZone .font-mono'))
            .map(el => el.textContent.trim().substring(1));

        if (!allowedExtensions.includes(extension)) {
            showToast(`Unsupported file type. Allowed types: ${allowedExtensions.join(', ')}`, 'error');
            return;
        }

        if (file.size > UPLOAD_CONFIG.maxFileSize) {
            showToast('File size exceeds 16MB limit', 'error');
            return;
        }

        uploadFile(file);
    }

    function uploadFile(file) {
        showToast('Uploading file...', 'info');

        const formData = new FormData();
        formData.append('file', file);

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) throw new Error(data.error);

            showToast('File uploaded successfully', 'success');
            if (data.file_info) updateFileInfo(data.file_info);
        })
        .catch(error => {
            showToast(error.message, 'error');
        });
    }

    // Global Functions
    window.copyHash = function(elementId) {
        const hashType = elementId === 'md5Hash' ? 'md5' : 'sha256';
        const fullHash = document.getElementById(`${hashType}HashFull`).textContent;

        navigator.clipboard.writeText(fullHash).then(() => {
            showToast(`${hashType.toUpperCase()} hash copied to clipboard`, 'success');
        });
    }

    window.selectAnalysisType = function(type) {
        if (!currentFileHash) return;

        updateProgress(2, true);
        elements.fileAnalysisArea.classList.add('opacity-0', 'scale-95');

        setTimeout(() => {
            window.location.href = `/analyze/${type}/${currentFileHash}`;
        }, UPLOAD_CONFIG.transitionDelay);
    };
});