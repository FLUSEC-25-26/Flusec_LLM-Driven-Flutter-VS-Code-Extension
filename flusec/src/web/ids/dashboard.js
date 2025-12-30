// IDS Dashboard JavaScript
// Handles chart rendering, filtering, search, and interactions

// Wrap in IIFE to prevent execution during Node.js loading
(function () {
    // Only execute in webview context
    if (typeof acquireVsCodeApi === 'undefined') {
        console.warn('acquireVsCodeApi not available - skipping dashboard initialization');
        return;
    }

    const vscode = acquireVsCodeApi();
    let allFindings = [];
    let filteredFindings = [];

    // Chart instances
    let riskChart = null;
    let dataTypeChart = null;
    let storageChart = null;

    // Helper function to normalize risk level from severity
    function getRiskLevel(finding) {
        const risk = finding.riskLevel || finding.severity || '';
        return risk.toUpperCase();
    }

    // Helper function to extract storage context from ruleId
    function getStorageContext(finding) {
        if (finding.storageContext) return finding.storageContext;

        const ruleId = finding.ruleId || '';
        if (ruleId.includes('IDS-001')) return 'SharedPreferences';
        if (ruleId.includes('IDS-002')) return 'File Storage';
        if (ruleId.includes('IDS-003')) return 'SQLite Database';
        if (ruleId.includes('IDS-004')) return 'External Storage';
        if (ruleId.includes('IDS-005')) return 'Cache';
        if (ruleId.includes('IDS-006')) return 'WebView Storage';
        if (ruleId.includes('IDS-007')) return 'Clipboard';
        if (ruleId.includes('IDS-008')) return 'Logs';
        return 'Unknown';
    }

    // Helper function to get data type
    function getDataType(finding) {
        if (finding.dataType) return finding.dataType;
        return 'SENSITIVE_DATA';
    }

    // ============================================
    // Initialize Dashboard
    // ============================================
    window.addEventListener('message', (event) => {
        const { command, data } = event.data || {};

        if (command === 'loadFindings') {
            allFindings = Array.isArray(data) ? data : [];
            filteredFindings = [...allFindings];
            renderDashboard();
            populateFilterOptions();
        }
    });

    // ============================================
    // Render Dashboard
    // ============================================
    function renderDashboard() {
        updateSummaryCards();
        renderCharts();
        renderFindingsTable();
    }

    // ============================================
    // Summary Cards
    // ============================================
    function updateSummaryCards() {
        const total = filteredFindings.length;

        const critical = filteredFindings.filter(f => getRiskLevel(f) === 'CRITICAL').length;
        const high = filteredFindings.filter(f => getRiskLevel(f) === 'HIGH').length;
        const medium = filteredFindings.filter(f => getRiskLevel(f) === 'MEDIUM').length;
        const low = filteredFindings.filter(f => getRiskLevel(f) === 'LOW').length;

        document.getElementById('total-count').textContent = total;
        document.getElementById('critical-count').textContent = critical;
        document.getElementById('high-count').textContent = high;
        document.getElementById('medium-count').textContent = medium;
        document.getElementById('low-count').textContent = low;
    }

    // ============================================
    // Charts
    // ============================================
    function renderCharts() {
        renderRiskChart();
        renderDataTypeChart();
        renderStorageChart();
    }

    function renderRiskChart() {
        const ctx = document.getElementById('riskChart').getContext('2d');

        const riskCounts = {
            CRITICAL: filteredFindings.filter(f => getRiskLevel(f) === 'CRITICAL').length,
            HIGH: filteredFindings.filter(f => getRiskLevel(f) === 'HIGH').length,
            MEDIUM: filteredFindings.filter(f => getRiskLevel(f) === 'MEDIUM').length,
            LOW: filteredFindings.filter(f => getRiskLevel(f) === 'LOW').length
        };

        if (riskChart) {
            riskChart.destroy();
        }

        riskChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [riskCounts.CRITICAL, riskCounts.HIGH, riskCounts.MEDIUM, riskCounts.LOW],
                    backgroundColor: ['#ff0000', '#ff6b00', '#ffaa00', '#00aa00'],
                    borderColor: '#1e1e1e',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ddd',
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#252526',
                        titleColor: '#ddd',
                        bodyColor: '#ddd',
                        borderColor: '#444',
                        borderWidth: 1
                    }
                }
            }
        });
    }

    function renderDataTypeChart() {
        const ctx = document.getElementById('dataTypeChart').getContext('2d');

        const dataTypeCounts = {};
        filteredFindings.forEach(f => {
            const type = getDataType(f);
            dataTypeCounts[type] = (dataTypeCounts[type] || 0) + 1;
        });

        const sortedTypes = Object.entries(dataTypeCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8);

        if (dataTypeChart) {
            dataTypeChart.destroy();
        }

        dataTypeChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sortedTypes.map(([type]) => type),
                datasets: [{
                    label: 'Vulnerabilities',
                    data: sortedTypes.map(([, count]) => count),
                    backgroundColor: '#007acc',
                    borderColor: '#005a9e',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#252526',
                        titleColor: '#ddd',
                        bodyColor: '#ddd',
                        borderColor: '#444',
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#ddd',
                            stepSize: 1
                        },
                        grid: { color: '#444' }
                    },
                    x: {
                        ticks: { color: '#ddd' },
                        grid: { display: false }
                    }
                }
            }
        });
    }

    function renderStorageChart() {
        const ctx = document.getElementById('storageChart').getContext('2d');

        const storageCounts = {};
        filteredFindings.forEach(f => {
            const storage = getStorageContext(f);
            storageCounts[storage] = (storageCounts[storage] || 0) + 1;
        });

        const sortedStorage = Object.entries(storageCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8);

        if (storageChart) {
            storageChart.destroy();
        }

        storageChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sortedStorage.map(([storage]) => storage),
                datasets: [{
                    label: 'Vulnerabilities',
                    data: sortedStorage.map(([, count]) => count),
                    backgroundColor: '#4fc1ff',
                    borderColor: '#007acc',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#252526',
                        titleColor: '#ddd',
                        bodyColor: '#ddd',
                        borderColor: '#444',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            color: '#ddd',
                            stepSize: 1
                        },
                        grid: { color: '#444' }
                    },
                    y: {
                        ticks: { color: '#ddd' },
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // ============================================
    // Findings Table
    // ============================================
    function renderFindingsTable() {
        const tbody = document.getElementById('findings-tbody');
        const countEl = document.getElementById('findings-count');

        countEl.textContent = `${filteredFindings.length} finding${filteredFindings.length !== 1 ? 's' : ''}`;

        if (filteredFindings.length === 0) {
            tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 40px;">
          <div class="empty-state">
            <div class="empty-state-icon">🔍</div>
            <div class="empty-state-title">No vulnerabilities found</div>
            <div class="empty-state-message">Try adjusting your filters or run a scan</div>
          </div>
        </td>
      </tr>
    `;
            return;
        }

        tbody.innerHTML = '';

        filteredFindings.forEach(finding => {
            const tr = document.createElement('tr');

            const riskLevel = getRiskLevel(finding);
            const riskClass = `risk-${riskLevel.toLowerCase()}`;
            const riskBadge = `<span class="risk-badge ${riskClass}">${riskLevel || 'N/A'}</span>`;

            const dataType = getDataType(finding);
            const dataTypeBadge = `<span class="data-type-badge">${escapeHtml(dataType)}</span>`;

            const storage = getStorageContext(finding);
            const storageBadge = `<span class="storage-badge">${escapeHtml(storage)}</span>`;

            const fileName = finding.file ? getFileName(finding.file) : 'Unknown';
            const fileLink = `<a href="#" class="file-link" onclick="revealFile('${escapeHtml(finding.file)}', ${finding.line || 1}, ${finding.column || 1}); return false;">${escapeHtml(fileName)}</a>`;

            const recommendation = finding.recommendation
                ? `<div class="recommendation">💡 ${escapeHtml(finding.recommendation)}</div>`
                : '';

            tr.innerHTML = `
      <td>${riskBadge}</td>
      <td>${dataTypeBadge}</td>
      <td>${storageBadge}</td>
      <td>${escapeHtml(finding.message || '')}</td>
      <td>${fileLink}</td>
      <td>${finding.line || 'N/A'}</td>
      <td>${escapeHtml(finding.ruleName || finding.ruleId || 'N/A')}${recommendation}</td>
    `;

            tbody.appendChild(tr);
        });
    }

    // ============================================
    // Filtering
    // ============================================
    function applyFilters() {
        const riskFilter = document.getElementById('risk-filter').value;
        const dataTypeFilter = document.getElementById('datatype-filter').value;
        const severityFilter = document.getElementById('severity-filter').value;
        const storageFilter = document.getElementById('storage-filter').value;
        const searchTerm = document.getElementById('search-input').value.toLowerCase();

        filteredFindings = allFindings.filter(finding => {
            // Risk level filter
            if (riskFilter && getRiskLevel(finding) !== riskFilter) return false;

            // Data type filter
            if (dataTypeFilter && getDataType(finding) !== dataTypeFilter) return false;

            // Severity filter
            if (severityFilter && getRiskLevel(finding).toLowerCase() !== severityFilter) return false;

            // Storage filter
            if (storageFilter && getStorageContext(finding) !== storageFilter) return false;

            // Search filter
            if (searchTerm) {
                const searchableText = [
                    finding.message,
                    finding.file,
                    finding.ruleName,
                    finding.ruleId,
                    getDataType(finding),
                    getStorageContext(finding),
                    finding.recommendation
                ].filter(Boolean).join(' ').toLowerCase();

                if (!searchableText.includes(searchTerm)) return false;
            }

            return true;
        });

        renderDashboard();
    }

    function clearFilters() {
        document.getElementById('risk-filter').value = '';
        document.getElementById('datatype-filter').value = '';
        document.getElementById('severity-filter').value = '';
        document.getElementById('storage-filter').value = '';
        document.getElementById('search-input').value = '';

        filteredFindings = [...allFindings];
        renderDashboard();
    }

    function populateFilterOptions() {
        // Populate data type filter
        const dataTypes = [...new Set(allFindings.map(f => getDataType(f)))].sort();
        const dataTypeSelect = document.getElementById('datatype-filter');
        dataTypeSelect.innerHTML = '<option value="">All Types</option>';
        dataTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type;
            option.textContent = type;
            dataTypeSelect.appendChild(option);
        });

        // Populate storage filter
        const storageContexts = [...new Set(allFindings.map(f => getStorageContext(f)))].sort();
        const storageSelect = document.getElementById('storage-filter');
        storageSelect.innerHTML = '<option value="">All Contexts</option>';
        storageContexts.forEach(storage => {
            const option = document.createElement('option');
            option.value = storage;
            option.textContent = storage;
            storageSelect.appendChild(option);
        });
    }

    // ============================================
    // Actions
    // ============================================
    window.revealFile = function (file, line, column) {
        vscode.postMessage({
            command: 'reveal',
            file: file,
            line: line,
            column: column
        });
    };

    function exportFindings() {
        const dataStr = JSON.stringify(filteredFindings, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ids-findings-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function rescanFiles() {
        vscode.postMessage({ command: 'rescan' });
    }

    // ============================================
    // Utilities
    // ============================================
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function getFileName(filePath) {
        if (!filePath) return '';
        const parts = filePath.replace(/\\/g, '/').split('/');
        return parts[parts.length - 1];
    }

    // ============================================
    // Event Listeners
    // ============================================
    document.addEventListener('DOMContentLoaded', () => {
        // Filter change listeners
        document.getElementById('risk-filter').addEventListener('change', applyFilters);
        document.getElementById('datatype-filter').addEventListener('change', applyFilters);
        document.getElementById('severity-filter').addEventListener('change', applyFilters);
        document.getElementById('storage-filter').addEventListener('change', applyFilters);

        // Search input listener (debounced)
        let searchTimeout;
        document.getElementById('search-input').addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(applyFilters, 300);
        });

        // Button listeners
        document.getElementById('clear-filters-btn').addEventListener('click', clearFilters);
        document.getElementById('export-btn').addEventListener('click', exportFindings);
        document.getElementById('rescan-btn').addEventListener('click', rescanFiles);
    });
})();
