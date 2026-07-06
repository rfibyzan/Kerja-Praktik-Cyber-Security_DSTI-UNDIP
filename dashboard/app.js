/**
 * ================================================================
 * PENTEST DASHBOARD — Application Logic
 * ================================================================
 * Loads JSON report data and renders interactive visualizations
 * using Chart.js. Supports filtering, searching, and sorting.
 * ================================================================
 */

// ─── Constants ───
const DATA_FILES = {
    subdomains: 'aset_aktif_undip.json',
    portScan: 'port_scan_results.json',
    techFingerprint: 'tech_fingerprint.json',
    vulnReport: 'vuln_report.json',
};

// Global state
let state = {
    subdomains: [],
    portScan: [],
    techFingerprint: [],
    vulnReport: [],
    allVulns: [],       // flattened list of all vulnerabilities
    sortColumn: null,
    sortDirection: 'asc',
};

// Chart.js global defaults
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;

// ─── Data Loading ───

async function loadJSON(filename) {
    try {
        const response = await fetch(filename);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (err) {
        console.warn(`[!] Could not load ${filename}:`, err.message);
        return null;
    }
}

async function loadAllData() {
    const statusEl = document.getElementById('loading-status');

    statusEl.textContent = 'Memuat data subdomain...';
    state.subdomains = await loadJSON(DATA_FILES.subdomains) || [];

    statusEl.textContent = 'Memuat hasil port scan...';
    state.portScan = await loadJSON(DATA_FILES.portScan) || [];

    statusEl.textContent = 'Memuat data fingerprint...';
    state.techFingerprint = await loadJSON(DATA_FILES.techFingerprint) || [];

    statusEl.textContent = 'Memuat vulnerability report...';
    state.vulnReport = await loadJSON(DATA_FILES.vulnReport) || [];

    // Flatten all vulnerabilities
    state.allVulns = [];
    for (const domain of state.vulnReport) {
        for (const vuln of (domain.vulnerabilities || [])) {
            state.allVulns.push({
                ...vuln,
                domain_name: domain.domain_name,
            });
        }
    }

    // Check if we have at least subdomain data
    if (state.subdomains.length === 0) {
        showError('File aset_aktif_undip.json tidak ditemukan. Jalankan scrapper.py terlebih dahulu.');
        return false;
    }

    return true;
}

function showError(message) {
    document.getElementById('loading-overlay').classList.add('hidden');
    document.getElementById('error-state').classList.remove('hidden');
    document.getElementById('error-message').textContent = message;
}

function showDashboard() {
    document.getElementById('loading-overlay').classList.add('hidden');
    document.getElementById('dashboard-content').classList.remove('hidden');
}

// ─── Stat Cards ───

function renderStatCards() {
    // Total subdomains
    document.getElementById('total-subdomains').textContent = state.subdomains.length;

    // Total open ports
    let totalPorts = 0;
    for (const d of state.portScan) {
        totalPorts += (d.open_ports || []).length;
    }
    document.getElementById('total-open-ports').textContent = totalPorts || '—';

    // Total vulnerabilities
    document.getElementById('total-vulns').textContent = state.allVulns.length || '—';

    // Average risk score
    if (state.vulnReport.length > 0) {
        const avgRisk = state.vulnReport.reduce((sum, d) => sum + (d.risk_score || 0), 0) / state.vulnReport.length;
        document.getElementById('avg-risk-score').textContent = avgRisk.toFixed(1);
    } else {
        document.getElementById('avg-risk-score').textContent = '—';
    }

    // Last scan time
    let latestTime = null;
    for (const d of state.vulnReport) {
        if (d.scan_timestamp && (!latestTime || d.scan_timestamp > latestTime)) {
            latestTime = d.scan_timestamp;
        }
    }
    if (!latestTime) {
        for (const d of state.portScan) {
            if (d.scan_timestamp && (!latestTime || d.scan_timestamp > latestTime)) {
                latestTime = d.scan_timestamp;
            }
        }
    }
    if (latestTime) {
        const date = new Date(latestTime);
        document.getElementById('last-scan-time').textContent =
            date.toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) +
            ' ' + date.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
    }

    // Animate stat numbers
    animateStatNumbers();
}

function animateStatNumbers() {
    document.querySelectorAll('.stat-number').forEach(el => {
        const target = parseInt(el.textContent);
        if (isNaN(target)) return;

        let current = 0;
        const step = Math.max(1, Math.floor(target / 30));
        const interval = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(interval);
            }
            el.textContent = current;
        }, 20);
    });
}

// ─── Charts ───

function renderCharts() {
    renderSeverityChart();
    renderServicesChart();
    renderWebServersChart();
    renderRiskDistChart();
}

function renderSeverityChart() {
    const canvas = document.getElementById('chart-severity');
    if (!canvas) return;

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const v of state.allVulns) {
        if (counts.hasOwnProperty(v.severity)) {
            counts[v.severity]++;
        }
    }

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.85)',
                    'rgba(249, 115, 22, 0.85)',
                    'rgba(234, 179, 8, 0.85)',
                    'rgba(34, 197, 94, 0.85)',
                ],
                borderColor: '#111827',
                borderWidth: 3,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 16,
                        usePointStyle: true,
                        pointStyleWidth: 8,
                        font: { size: 11 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    cornerRadius: 8,
                    padding: 12,
                }
            },
            animation: {
                animateRotate: true,
                duration: 1200,
            }
        }
    });
}

function renderServicesChart() {
    const canvas = document.getElementById('chart-services');
    if (!canvas) return;

    const serviceCounts = {};
    for (const d of state.portScan) {
        for (const p of (d.open_ports || [])) {
            const svc = p.service || `Port ${p.port}`;
            serviceCounts[svc] = (serviceCounts[svc] || 0) + 1;
        }
    }

    // Sort and take top 10
    const sorted = Object.entries(serviceCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    if (sorted.length === 0) {
        canvas.parentElement.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:40px;">No port scan data</p>';
        return;
    }

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: sorted.map(s => s[0]),
            datasets: [{
                label: 'Count',
                data: sorted.map(s => s[1]),
                backgroundColor: 'rgba(59, 130, 246, 0.6)',
                borderColor: 'rgba(59, 130, 246, 0.9)',
                borderWidth: 1,
                borderRadius: 6,
                maxBarThickness: 40,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    cornerRadius: 8,
                    padding: 12,
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { font: { size: 11 } }
                },
                y: {
                    grid: { display: false },
                    ticks: {
                        font: { family: "'JetBrains Mono', monospace", size: 11 }
                    }
                }
            },
            animation: { duration: 1000 }
        }
    });
}

function renderWebServersChart() {
    const canvas = document.getElementById('chart-webservers');
    if (!canvas) return;

    const serverCounts = {};
    for (const d of state.techFingerprint) {
        let server = (d.technologies || {}).web_server || 'Unknown';
        if (server !== 'Unknown') {
            // Normalize: take first part
            server = server.split('/')[0].split(' ')[0];
            serverCounts[server] = (serverCounts[server] || 0) + 1;
        }
    }

    const labels = Object.keys(serverCounts);
    const data = Object.values(serverCounts);

    if (labels.length === 0) {
        canvas.parentElement.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:40px;">No fingerprint data</p>';
        return;
    }

    const colors = [
        'rgba(59, 130, 246, 0.75)',
        'rgba(139, 92, 246, 0.75)',
        'rgba(34, 211, 238, 0.75)',
        'rgba(249, 115, 22, 0.75)',
        'rgba(34, 197, 94, 0.75)',
        'rgba(236, 72, 153, 0.75)',
        'rgba(234, 179, 8, 0.75)',
        'rgba(168, 162, 158, 0.75)',
    ];

    new Chart(canvas, {
        type: 'pie',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: '#111827',
                borderWidth: 3,
                hoverOffset: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 14,
                        usePointStyle: true,
                        pointStyleWidth: 8,
                        font: { size: 11 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    cornerRadius: 8,
                    padding: 12,
                }
            },
            animation: { duration: 1000 }
        }
    });
}

function renderRiskDistChart() {
    const canvas = document.getElementById('chart-risk-dist');
    if (!canvas) return;

    if (state.vulnReport.length === 0) {
        canvas.parentElement.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:40px;">No vulnerability data</p>';
        return;
    }

    // Bucket risk scores
    const buckets = { '0-2 (Safe)': 0, '2-4 (Low)': 0, '4-6 (Medium)': 0, '6-8 (High)': 0, '8-10 (Critical)': 0 };
    for (const d of state.vulnReport) {
        const score = d.risk_score || 0;
        if (score < 2) buckets['0-2 (Safe)']++;
        else if (score < 4) buckets['2-4 (Low)']++;
        else if (score < 6) buckets['4-6 (Medium)']++;
        else if (score < 8) buckets['6-8 (High)']++;
        else buckets['8-10 (Critical)']++;
    }

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: Object.keys(buckets),
            datasets: [{
                label: 'Domains',
                data: Object.values(buckets),
                backgroundColor: [
                    'rgba(6, 182, 212, 0.7)',
                    'rgba(34, 197, 94, 0.7)',
                    'rgba(234, 179, 8, 0.7)',
                    'rgba(249, 115, 22, 0.7)',
                    'rgba(239, 68, 68, 0.7)',
                ],
                borderColor: [
                    'rgba(6, 182, 212, 1)',
                    'rgba(34, 197, 94, 1)',
                    'rgba(234, 179, 8, 1)',
                    'rgba(249, 115, 22, 1)',
                    'rgba(239, 68, 68, 1)',
                ],
                borderWidth: 1,
                borderRadius: 6,
                maxBarThickness: 50,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(17, 24, 39, 0.95)',
                    cornerRadius: 8,
                    padding: 12,
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: {
                        stepSize: 1,
                        font: { size: 11 }
                    }
                },
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 10 } }
                }
            },
            animation: { duration: 1000 }
        }
    });
}

// ─── Vulnerability List ───

function renderVulnList(severityFilter = 'all', checkFilter = 'all') {
    const container = document.getElementById('vuln-list');
    container.innerHTML = '';

    let filtered = state.allVulns;

    if (severityFilter !== 'all') {
        filtered = filtered.filter(v => v.severity === severityFilter);
    }
    if (checkFilter !== 'all') {
        filtered = filtered.filter(v => v.check === checkFilter);
    }

    // Sort by severity priority
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    filtered.sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4));

    if (filtered.length === 0) {
        container.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--text-muted);">
                <p>Tidak ada temuan kerentanan${severityFilter !== 'all' ? ` dengan severity "${severityFilter}"` : ''}.</p>
            </div>
        `;
        return;
    }

    // Limit display to prevent performance issues
    const displayLimit = 200;
    const displayItems = filtered.slice(0, displayLimit);

    for (const vuln of displayItems) {
        const item = document.createElement('div');
        item.className = 'vuln-item';
        item.innerHTML = `
            <span class="vuln-severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            <div class="vuln-info">
                <div class="vuln-title">${escapeHtml(vuln.title)}</div>
                <div class="vuln-detail">${escapeHtml(vuln.detail || vuln.description || '')}</div>
            </div>
            <span class="vuln-domain">${escapeHtml(vuln.domain_name)}</span>
        `;
        container.appendChild(item);
    }

    if (filtered.length > displayLimit) {
        const more = document.createElement('div');
        more.style.cssText = 'text-align:center; padding:16px; color:var(--text-muted); font-size:0.85rem;';
        more.textContent = `... dan ${filtered.length - displayLimit} temuan lainnya`;
        container.appendChild(more);
    }
}

// ─── Subdomain Table ───

function renderDomainTable(searchQuery = '') {
    const tbody = document.getElementById('domain-table-body');
    tbody.innerHTML = '';

    // Build merged data
    const portMap = {};
    for (const d of state.portScan) {
        portMap[d.domain_name] = d.open_ports || [];
    }

    const techMap = {};
    for (const d of state.techFingerprint) {
        techMap[d.domain_name] = d.technologies || {};
    }

    const vulnMap = {};
    for (const d of state.vulnReport) {
        vulnMap[d.domain_name] = { risk_score: d.risk_score, risk_level: d.risk_level };
    }

    let rows = state.subdomains.map((d, idx) => ({
        index: idx + 1,
        domain: d.domain_name,
        ip: d.ip_address,
        ports: portMap[d.domain_name] || [],
        tech: techMap[d.domain_name] || {},
        risk: vulnMap[d.domain_name] || { risk_score: 0, risk_level: 'SAFE' },
    }));

    // Filter by search
    if (searchQuery) {
        const q = searchQuery.toLowerCase();
        rows = rows.filter(r =>
            r.domain.toLowerCase().includes(q) ||
            r.ip.includes(q) ||
            (r.tech.web_server || '').toLowerCase().includes(q) ||
            (r.tech.cms || '').toLowerCase().includes(q)
        );
    }

    // Sort
    if (state.sortColumn) {
        rows.sort((a, b) => {
            let valA, valB;
            switch (state.sortColumn) {
                case 'domain': valA = a.domain; valB = b.domain; break;
                case 'ip': valA = a.ip; valB = b.ip; break;
                case 'ports': valA = a.ports.length; valB = b.ports.length; break;
                case 'server': valA = a.tech.web_server || ''; valB = b.tech.web_server || ''; break;
                case 'cms': valA = a.tech.cms || ''; valB = b.tech.cms || ''; break;
                case 'risk': valA = a.risk.risk_score; valB = b.risk.risk_score; break;
                default: return 0;
            }
            if (typeof valA === 'string') {
                const cmp = valA.localeCompare(valB);
                return state.sortDirection === 'asc' ? cmp : -cmp;
            }
            return state.sortDirection === 'asc' ? valA - valB : valB - valA;
        });
    }

    for (const row of rows) {
        const tr = document.createElement('tr');

        // Port tags
        const portHtml = row.ports.length > 0
            ? row.ports.slice(0, 5).map(p => {
                let cls = '';
                if ([80, 443, 8080, 8443].includes(p.port)) cls = 'http';
                else if (p.port === 22) cls = 'ssh';
                else if ([3306, 5432, 3389, 6379, 27017].includes(p.port)) cls = 'danger';
                return `<span class="port-tag ${cls}">${p.port}</span>`;
            }).join('') + (row.ports.length > 5 ? `<span class="port-tag">+${row.ports.length - 5}</span>` : '')
            : '<span style="color:var(--text-muted)">—</span>';

        // Risk badge
        const riskLevel = row.risk.risk_level || 'SAFE';
        const riskScore = row.risk.risk_score || 0;
        const riskClass = riskLevel.toLowerCase();

        tr.innerHTML = `
            <td>${row.index}</td>
            <td class="td-domain">${escapeHtml(row.domain)}</td>
            <td class="td-ip">${escapeHtml(row.ip)}</td>
            <td class="td-ports">${portHtml}</td>
            <td>${escapeHtml(row.tech.web_server || '—')}</td>
            <td>${escapeHtml(row.tech.cms || '—')}</td>
            <td><span class="risk-badge ${riskClass}">${riskScore.toFixed(1)}</span></td>
        `;
        tbody.appendChild(tr);
    }
}

// ─── Event Handlers ───

function setupEventHandlers() {
    // Severity filter
    document.getElementById('filter-severity').addEventListener('change', (e) => {
        const checkFilter = document.getElementById('filter-check').value;
        renderVulnList(e.target.value, checkFilter);
    });

    // Check type filter
    document.getElementById('filter-check').addEventListener('change', (e) => {
        const sevFilter = document.getElementById('filter-severity').value;
        renderVulnList(sevFilter, e.target.value);
    });

    // Search
    let searchTimeout;
    document.getElementById('search-input').addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            renderDomainTable(e.target.value);
        }, 250);
    });

    // Table sorting
    document.querySelectorAll('.data-table th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.getAttribute('data-sort');
            if (state.sortColumn === col) {
                state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                state.sortColumn = col;
                state.sortDirection = 'asc';
            }

            // Update visual indicators
            document.querySelectorAll('.data-table th').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });
            th.classList.add(state.sortDirection === 'asc' ? 'sort-asc' : 'sort-desc');

            renderDomainTable(document.getElementById('search-input').value);
        });
    });

    // Export button
    document.getElementById('btn-export').addEventListener('click', exportReport);
}

// ─── Export ───

function exportReport() {
    // Generate a simple text report for export
    let report = '';
    report += '═══════════════════════════════════════════════════════\n';
    report += '  PENTEST REPORT — DSTI UNDIP\n';
    report += `  Target: undip.ac.id\n`;
    report += `  Generated: ${new Date().toLocaleString('id-ID')}\n`;
    report += '═══════════════════════════════════════════════════════\n\n';

    report += `EXECUTIVE SUMMARY\n`;
    report += `─────────────────\n`;
    report += `Total Subdomain Aktif: ${state.subdomains.length}\n`;
    report += `Total Port Terbuka: ${state.portScan.reduce((s, d) => s + (d.open_ports || []).length, 0)}\n`;
    report += `Total Kerentanan: ${state.allVulns.length}\n\n`;

    // Severity breakdown
    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const v of state.allVulns) {
        if (sevCounts.hasOwnProperty(v.severity)) sevCounts[v.severity]++;
    }
    report += `SEVERITY BREAKDOWN\n`;
    report += `──────────────────\n`;
    report += `  Critical: ${sevCounts.CRITICAL}\n`;
    report += `  High:     ${sevCounts.HIGH}\n`;
    report += `  Medium:   ${sevCounts.MEDIUM}\n`;
    report += `  Low:      ${sevCounts.LOW}\n\n`;

    // Top findings
    report += `TOP FINDINGS (High & Critical)\n`;
    report += `──────────────────────────────\n`;
    const topFindings = state.allVulns
        .filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH')
        .slice(0, 30);
    for (const v of topFindings) {
        report += `  [${v.severity}] ${v.title}\n`;
        report += `    Domain: ${v.domain_name}\n`;
        report += `    Detail: ${v.detail || ''}\n`;
        if (v.recommendation) report += `    Fix: ${v.recommendation}\n`;
        report += '\n';
    }

    // Download as text file
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pentest_report_undip_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// ─── Utilities ───

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ─── Initialization ───

async function init() {
    const dataLoaded = await loadAllData();
    
    if (!dataLoaded) return;

    showDashboard();
    renderStatCards();
    renderCharts();
    renderVulnList();
    renderDomainTable();
    setupEventHandlers();

    console.log('[✓] Pentest Dashboard initialized successfully');
    console.log(`    Subdomains: ${state.subdomains.length}`);
    console.log(`    Port Scan entries: ${state.portScan.length}`);
    console.log(`    Fingerprint entries: ${state.techFingerprint.length}`);
    console.log(`    Vuln Report entries: ${state.vulnReport.length}`);
    console.log(`    Total vulnerabilities: ${state.allVulns.length}`);
}

// Boot
document.addEventListener('DOMContentLoaded', init);
