"""
HTML Report Generator
Generates beautiful, interactive HTML reports for engineers
"""

from typing import Optional, Dict, List
from datetime import datetime
from collections import defaultdict

from .base import BaseReporter
from ..models import ScanResult, Finding, FindingType


class HTMLReporter(BaseReporter):
    """Generates HTML format reports with interactive features"""
    
    def get_format_name(self) -> str:
        return "HTML"
    
    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate HTML report"""
        if filename is None:
            filename = f"securescan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        output_path = self.get_output_path(filename, "html")
        
        html_content = self.build_html(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def build_html(self, result: ScanResult) -> str:
        """Build the complete HTML report"""
        findings_by_severity = self.group_by_severity(result.findings)
        findings_by_type = self.group_by_type(result.findings)
        findings_by_file = self.group_by_file(result.findings)
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureScan Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .severity-critical {{ background-color: #7f1d1d; color: white; }}
        .severity-high {{ background-color: #dc2626; color: white; }}
        .severity-medium {{ background-color: #f59e0b; color: white; }}
        .severity-low {{ background-color: #3b82f6; color: white; }}
        .severity-info {{ background-color: #6b7280; color: white; }}
        .finding-card {{ transition: all 0.2s ease-in-out; }}
        .finding-card:hover {{ transform: translateY(-2px); box-shadow: 0 10px 25px rgba(0,0,0,0.1); }}
        .code-snippet {{ background-color: #1e293b; color: #e2e8f0; font-family: monospace; }}
        .collapsible-content {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }}
        .collapsible-content.open {{ max-height: 2000px; }}
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <!-- Header -->
    <header class="bg-gradient-to-r from-indigo-600 to-purple-600 text-white py-8 px-6 shadow-lg">
        <div class="max-w-7xl mx-auto">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-3xl font-bold flex items-center gap-3">
                        <i class="fas fa-shield-alt"></i>
                        SecureScan Security Report
                    </h1>
                    <p class="mt-2 text-indigo-100">Application Security Analysis Results</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-indigo-200">Scan ID: {result.scan_id[:8]}...</p>
                    <p class="text-sm text-indigo-200">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8">
        <!-- Summary Cards -->
        <section class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
            <div class="bg-white rounded-xl shadow-md p-6 border-l-4 border-red-900">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 uppercase tracking-wide">Critical</p>
                        <p class="text-3xl font-bold text-red-900">{result.summary.critical_count}</p>
                    </div>
                    <i class="fas fa-exclamation-circle text-4xl text-red-200"></i>
                </div>
            </div>
            <div class="bg-white rounded-xl shadow-md p-6 border-l-4 border-red-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 uppercase tracking-wide">High</p>
                        <p class="text-3xl font-bold text-red-500">{result.summary.high_count}</p>
                    </div>
                    <i class="fas fa-exclamation-triangle text-4xl text-red-200"></i>
                </div>
            </div>
            <div class="bg-white rounded-xl shadow-md p-6 border-l-4 border-amber-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 uppercase tracking-wide">Medium</p>
                        <p class="text-3xl font-bold text-amber-500">{result.summary.medium_count}</p>
                    </div>
                    <i class="fas fa-minus-circle text-4xl text-amber-200"></i>
                </div>
            </div>
            <div class="bg-white rounded-xl shadow-md p-6 border-l-4 border-blue-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 uppercase tracking-wide">Low</p>
                        <p class="text-3xl font-bold text-blue-500">{result.summary.low_count}</p>
                    </div>
                    <i class="fas fa-info-circle text-4xl text-blue-200"></i>
                </div>
            </div>
            <div class="bg-white rounded-xl shadow-md p-6 border-l-4 border-gray-500">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500 uppercase tracking-wide">Info</p>
                        <p class="text-3xl font-bold text-gray-500">{result.summary.info_count}</p>
                    </div>
                    <i class="fas fa-lightbulb text-4xl text-gray-200"></i>
                </div>
            </div>
        </section>

        <!-- Charts Section -->
        <section class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div class="bg-white rounded-xl shadow-md p-6">
                <h3 class="text-lg font-semibold text-gray-800 mb-4">Findings by Severity</h3>
                <canvas id="severityChart" height="200"></canvas>
            </div>
            <div class="bg-white rounded-xl shadow-md p-6">
                <h3 class="text-lg font-semibold text-gray-800 mb-4">Findings by Type</h3>
                <canvas id="typeChart" height="200"></canvas>
            </div>
        </section>

        <!-- Scan Statistics -->
        <section class="bg-white rounded-xl shadow-md p-6 mb-8">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">
                <i class="fas fa-chart-bar mr-2 text-indigo-500"></i>
                Scan Statistics
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div class="text-center p-4 bg-gray-50 rounded-lg">
                    <p class="text-2xl font-bold text-indigo-600">{result.summary.total_findings}</p>
                    <p class="text-sm text-gray-500">Total Findings</p>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg">
                    <p class="text-2xl font-bold text-indigo-600">{result.summary.files_scanned}</p>
                    <p class="text-sm text-gray-500">Files Scanned</p>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg">
                    <p class="text-2xl font-bold text-indigo-600">{result.summary.dependencies_scanned}</p>
                    <p class="text-sm text-gray-500">Dependencies Checked</p>
                </div>
                <div class="text-center p-4 bg-gray-50 rounded-lg">
                    <p class="text-2xl font-bold text-indigo-600">{result.summary.scan_duration_seconds:.1f}s</p>
                    <p class="text-sm text-gray-500">Scan Duration</p>
                </div>
            </div>
        </section>

        <!-- Filter Controls -->
        <section class="bg-white rounded-xl shadow-md p-6 mb-8">
            <div class="flex flex-wrap gap-4 items-center">
                <span class="text-gray-700 font-medium">Filter by:</span>
                <select id="severityFilter" class="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500">
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select id="typeFilter" class="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500">
                    <option value="all">All Types</option>
                    <option value="sast">SAST</option>
                    <option value="sca">SCA</option>
                    <option value="secret">Secrets</option>
                </select>
                <input type="text" id="searchInput" placeholder="Search findings..." 
                       class="px-4 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 flex-grow">
            </div>
        </section>

        <!-- Findings List -->
        <section id="findingsList">
            <h3 class="text-xl font-semibold text-gray-800 mb-4">
                <i class="fas fa-bug mr-2 text-red-500"></i>
                Security Findings ({result.summary.total_findings})
            </h3>
            {self.build_findings_html(result.findings)}
        </section>
    </main>

    <!-- Footer -->
    <footer class="bg-gray-800 text-gray-300 py-6 mt-12">
        <div class="max-w-7xl mx-auto px-6 text-center">
            <p>Generated by SecureScan v1.0.0</p>
            <p class="text-sm text-gray-500 mt-1">SAST • SCA • Secrets Detection</p>
        </div>
    </footer>

    <script>
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [{result.summary.critical_count}, {result.summary.high_count}, {result.summary.medium_count}, {result.summary.low_count}, {result.summary.info_count}],
                    backgroundColor: ['#7f1d1d', '#dc2626', '#f59e0b', '#3b82f6', '#6b7280']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});

        // Type Chart
        new Chart(document.getElementById('typeChart'), {{
            type: 'bar',
            data: {{
                labels: ['SAST', 'SCA', 'Secrets'],
                datasets: [{{
                    label: 'Findings',
                    data: [{result.summary.sast_findings}, {result.summary.sca_findings}, {result.summary.secret_findings}],
                    backgroundColor: ['#6366f1', '#8b5cf6', '#a855f7']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});

        // Filter functionality
        function filterFindings() {{
            const severity = document.getElementById('severityFilter').value;
            const type = document.getElementById('typeFilter').value;
            const search = document.getElementById('searchInput').value.toLowerCase();
            
            document.querySelectorAll('.finding-card').forEach(card => {{
                const cardSeverity = card.dataset.severity;
                const cardType = card.dataset.type;
                const cardText = card.textContent.toLowerCase();
                
                const matchSeverity = severity === 'all' || cardSeverity === severity;
                const matchType = type === 'all' || cardType === type;
                const matchSearch = search === '' || cardText.includes(search);
                
                card.style.display = matchSeverity && matchType && matchSearch ? 'block' : 'none';
            }});
        }}

        document.getElementById('severityFilter').addEventListener('change', filterFindings);
        document.getElementById('typeFilter').addEventListener('change', filterFindings);
        document.getElementById('searchInput').addEventListener('input', filterFindings);

        // Collapsible sections
        document.querySelectorAll('.collapsible-toggle').forEach(toggle => {{
            toggle.addEventListener('click', () => {{
                const content = toggle.nextElementSibling;
                content.classList.toggle('open');
                toggle.querySelector('.toggle-icon').classList.toggle('rotate-180');
            }});
        }});
    </script>
</body>
</html>'''
    
    def build_findings_html(self, findings: List[Finding]) -> str:
        """Build HTML for all findings"""
        if not findings:
            return '''
            <div class="bg-green-50 border border-green-200 rounded-xl p-8 text-center">
                <i class="fas fa-check-circle text-6xl text-green-500 mb-4"></i>
                <h4 class="text-xl font-semibold text-green-800">No Security Issues Found!</h4>
                <p class="text-green-600 mt-2">Your code passed all security checks.</p>
            </div>
            '''
        
        html_parts = []
        for finding in findings:
            html_parts.append(self.build_finding_card(finding))
        
        return '\n'.join(html_parts)
    
    def build_finding_card(self, finding: Finding) -> str:
        """Build HTML card for a single finding"""
        severity_class = f"severity-{finding.severity}"
        type_icon = {
            FindingType.SAST: "fa-code",
            FindingType.SCA: "fa-cube",
            FindingType.SECRET: "fa-key"
        }.get(finding.finding_type, "fa-bug")
        
        snippet_html = ""
        if finding.location.snippet:
            escaped_snippet = finding.location.snippet.replace("<", "&lt;").replace(">", "&gt;")
            snippet_html = f'''
            <div class="mt-4">
                <p class="text-sm font-medium text-gray-600 mb-2">Code Snippet:</p>
                <pre class="code-snippet p-4 rounded-lg overflow-x-auto text-sm">{escaped_snippet}</pre>
            </div>
            '''
        
        remediation_html = ""
        if finding.remediation:
            fix_example = ""
            if finding.remediation.fix_example:
                escaped_fix = finding.remediation.fix_example.replace("<", "&lt;").replace(">", "&gt;")
                fix_example = f'<pre class="code-snippet p-3 rounded-lg mt-2 text-sm">{escaped_fix}</pre>'
            
            refs_html = ""
            if finding.remediation.references:
                refs_html = '<div class="mt-2"><p class="text-sm font-medium text-gray-600">References:</p><ul class="list-disc list-inside text-sm text-blue-600">'
                for ref in finding.remediation.references[:3]:
                    refs_html += f'<li><a href="{ref}" target="_blank" class="hover:underline">{ref[:60]}...</a></li>'
                refs_html += '</ul></div>'
            
            remediation_html = f'''
            <div class="mt-4 bg-green-50 border border-green-200 rounded-lg p-4">
                <p class="text-sm font-medium text-green-800 mb-2">
                    <i class="fas fa-lightbulb mr-1"></i> Remediation
                </p>
                <p class="text-sm text-green-700">{finding.remediation.description}</p>
                {fix_example}
                {refs_html}
            </div>
            '''
        
        cwe_badge = ""
        if finding.cwe_id:
            cwe_badge = f'<span class="px-2 py-1 bg-purple-100 text-purple-700 rounded text-xs">{finding.cwe_id}</span>'
        
        cvss_badge = ""
        if finding.cvss_score:
            cvss_badge = f'<span class="px-2 py-1 bg-orange-100 text-orange-700 rounded text-xs">CVSS: {finding.cvss_score}</span>'
        
        return f'''
        <div class="finding-card bg-white rounded-xl shadow-md mb-4 overflow-hidden" 
             data-severity="{finding.severity}" data-type="{finding.finding_type.value}">
            <div class="flex">
                <div class="{severity_class} w-2"></div>
                <div class="flex-grow p-6">
                    <div class="flex items-start justify-between">
                        <div class="flex items-center gap-3">
                            <span class="{severity_class} px-3 py-1 rounded-full text-xs font-semibold uppercase">
                                {finding.severity}
                            </span>
                            <span class="px-3 py-1 bg-indigo-100 text-indigo-700 rounded-full text-xs font-semibold">
                                <i class="fas {type_icon} mr-1"></i>
                                {finding.finding_type.value.upper()}
                            </span>
                            {cwe_badge}
                            {cvss_badge}
                        </div>
                        <span class="text-xs text-gray-400">{finding.rule_id}</span>
                    </div>
                    
                    <h4 class="text-lg font-semibold text-gray-800 mt-3">{finding.title}</h4>
                    <p class="text-gray-600 mt-2">{finding.description}</p>
                    
                    <div class="mt-3 flex items-center text-sm text-gray-500">
                        <i class="fas fa-file-code mr-2"></i>
                        <span class="font-mono">{finding.location.file_path}</span>
                        <span class="mx-2">•</span>
                        <span>Line {finding.location.start_line}</span>
                    </div>
                    
                    {snippet_html}
                    {remediation_html}
                </div>
            </div>
        </div>
        '''
    
    def group_by_severity(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by severity"""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.severity].append(finding)
        return dict(grouped)
    
    def group_by_type(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by type"""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.finding_type.value].append(finding)
        return dict(grouped)
    
    def group_by_file(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by file"""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[finding.location.file_path].append(finding)
        return dict(grouped)
