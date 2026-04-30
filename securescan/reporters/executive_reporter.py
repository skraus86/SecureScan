"""
Executive Report Generator
Generates high-level summary reports for leadership and management
"""

from typing import Optional, Dict, List
from datetime import datetime
from collections import defaultdict

from .base import BaseReporter
from ..models import ScanResult, Finding, FindingType
from ..config import Severity


class ExecutiveReporter(BaseReporter):
    """Generates executive summary reports for leadership"""
    
    def get_format_name(self) -> str:
        return "Executive HTML"
    
    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate executive summary report"""
        if filename is None:
            filename = f"securescan_executive_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        output_path = self.get_output_path(filename, "html")
        
        html_content = self.build_executive_html(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def calculate_risk_score(self, result: ScanResult) -> int:
        """Calculate overall risk score (0-100)"""
        if result.summary.total_findings == 0:
            return 0
        
        weighted_score = (
            result.summary.critical_count * 40 +
            result.summary.high_count * 25 +
            result.summary.medium_count * 10 +
            result.summary.low_count * 3 +
            result.summary.info_count * 1
        )
        
        # Normalize to 0-100 scale
        max_possible = result.summary.total_findings * 40
        score = min(100, int((weighted_score / max_possible) * 100)) if max_possible > 0 else 0
        
        return score
    
    def get_risk_level(self, score: int) -> tuple:
        """Get risk level label and color based on score"""
        if score >= 75:
            return ("Critical", "#7f1d1d", "#fecaca")
        elif score >= 50:
            return ("High", "#dc2626", "#fee2e2")
        elif score >= 25:
            return ("Medium", "#f59e0b", "#fef3c7")
        elif score > 0:
            return ("Low", "#3b82f6", "#dbeafe")
        else:
            return ("Minimal", "#10b981", "#d1fae5")
    
    def get_top_issues(self, findings: List[Finding], limit: int = 5) -> List[Finding]:
        """Get top issues by severity"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
        return sorted_findings[:limit]
    
    def get_recommendations(self, result: ScanResult) -> List[Dict]:
        """Generate prioritized recommendations"""
        recommendations = []
        
        if result.summary.critical_count > 0:
            recommendations.append({
                "priority": "Immediate",
                "icon": "fa-exclamation-circle",
                "color": "#7f1d1d",
                "title": "Address Critical Vulnerabilities",
                "description": f"There are {result.summary.critical_count} critical security issues that require immediate attention. These could lead to severe security breaches if exploited."
            })
        
        if result.summary.high_count > 0:
            recommendations.append({
                "priority": "High",
                "icon": "fa-exclamation-triangle",
                "color": "#dc2626",
                "title": "Remediate High-Severity Issues",
                "description": f"Address {result.summary.high_count} high-severity vulnerabilities within the next sprint cycle to reduce attack surface."
            })
        
        if result.summary.sca_findings > 0:
            recommendations.append({
                "priority": "High",
                "icon": "fa-cube",
                "color": "#8b5cf6",
                "title": "Update Vulnerable Dependencies",
                "description": f"Found {result.summary.sca_findings} vulnerable dependencies. Implement automated dependency updates and regular security audits."
            })
        
        if result.summary.secret_findings > 0:
            recommendations.append({
                "priority": "Immediate",
                "icon": "fa-key",
                "color": "#f59e0b",
                "title": "Rotate Exposed Secrets",
                "description": f"Detected {result.summary.secret_findings} potential secrets in code. Rotate all exposed credentials immediately and implement secrets management."
            })
        
        if result.summary.medium_count > 5:
            recommendations.append({
                "priority": "Medium",
                "icon": "fa-shield-alt",
                "color": "#3b82f6",
                "title": "Security Training",
                "description": "Consider security awareness training for the development team to reduce common vulnerability patterns."
            })
        
        if not recommendations:
            recommendations.append({
                "priority": "Maintenance",
                "icon": "fa-check-circle",
                "color": "#10b981",
                "title": "Maintain Security Posture",
                "description": "Continue regular security scanning and keep dependencies up to date."
            })
        
        return recommendations
    
    def build_executive_html(self, result: ScanResult) -> str:
        """Build the executive summary HTML"""
        risk_score = self.calculate_risk_score(result)
        risk_level, risk_color, risk_bg = self.get_risk_level(risk_score)
        top_issues = self.get_top_issues(result.findings)
        recommendations = self.get_recommendations(result)
        
        # Calculate trends (mock data for now - in production, compare with previous scans)
        trend_indicator = "→"  # Could be ↑, ↓, or →
        
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureScan Executive Summary</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @media print {{
            .no-print {{ display: none; }}
            body {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
        }}
        .risk-gauge {{ 
            background: conic-gradient(
                {risk_color} 0deg {risk_score * 3.6}deg,
                #e5e7eb {risk_score * 3.6}deg 360deg
            );
        }}
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <!-- Header -->
    <header class="bg-white shadow-sm border-b">
        <div class="max-w-6xl mx-auto px-8 py-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-2xl font-bold text-gray-800">
                        <i class="fas fa-shield-alt text-indigo-600 mr-2"></i>
                        Security Executive Summary
                    </h1>
                    <p class="text-gray-500 mt-1">Application Security Assessment Report</p>
                </div>
                <div class="text-right">
                    <p class="text-sm text-gray-500">Report Date</p>
                    <p class="font-semibold text-gray-800">{datetime.now().strftime('%B %d, %Y')}</p>
                </div>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-8 py-8">
        <!-- Risk Overview -->
        <section class="bg-white rounded-2xl shadow-lg p-8 mb-8">
            <h2 class="text-xl font-bold text-gray-800 mb-6">Risk Overview</h2>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Risk Score Gauge -->
                <div class="flex flex-col items-center">
                    <div class="relative w-48 h-48">
                        <div class="risk-gauge w-full h-full rounded-full flex items-center justify-center">
                            <div class="w-36 h-36 bg-white rounded-full flex flex-col items-center justify-center">
                                <span class="text-4xl font-bold" style="color: {risk_color}">{risk_score}</span>
                                <span class="text-sm text-gray-500">Risk Score</span>
                            </div>
                        </div>
                    </div>
                    <div class="mt-4 px-6 py-2 rounded-full font-semibold" style="background-color: {risk_bg}; color: {risk_color}">
                        {risk_level} Risk
                    </div>
                </div>
                
                <!-- Key Metrics -->
                <div class="lg:col-span-2">
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div class="bg-red-50 rounded-xl p-4 text-center">
                            <p class="text-3xl font-bold text-red-900">{result.summary.critical_count}</p>
                            <p class="text-sm text-red-700">Critical</p>
                        </div>
                        <div class="bg-red-50 rounded-xl p-4 text-center">
                            <p class="text-3xl font-bold text-red-600">{result.summary.high_count}</p>
                            <p class="text-sm text-red-500">High</p>
                        </div>
                        <div class="bg-amber-50 rounded-xl p-4 text-center">
                            <p class="text-3xl font-bold text-amber-600">{result.summary.medium_count}</p>
                            <p class="text-sm text-amber-500">Medium</p>
                        </div>
                        <div class="bg-blue-50 rounded-xl p-4 text-center">
                            <p class="text-3xl font-bold text-blue-600">{result.summary.low_count + result.summary.info_count}</p>
                            <p class="text-sm text-blue-500">Low/Info</p>
                        </div>
                    </div>
                    
                    <div class="mt-6 grid grid-cols-3 gap-4">
                        <div class="bg-gray-50 rounded-lg p-4">
                            <div class="flex items-center gap-2 text-gray-600">
                                <i class="fas fa-code"></i>
                                <span class="text-sm">SAST Issues</span>
                            </div>
                            <p class="text-2xl font-bold text-gray-800 mt-1">{result.summary.sast_findings}</p>
                        </div>
                        <div class="bg-gray-50 rounded-lg p-4">
                            <div class="flex items-center gap-2 text-gray-600">
                                <i class="fas fa-cube"></i>
                                <span class="text-sm">SCA Issues</span>
                            </div>
                            <p class="text-2xl font-bold text-gray-800 mt-1">{result.summary.sca_findings}</p>
                        </div>
                        <div class="bg-gray-50 rounded-lg p-4">
                            <div class="flex items-center gap-2 text-gray-600">
                                <i class="fas fa-key"></i>
                                <span class="text-sm">Secrets</span>
                            </div>
                            <p class="text-2xl font-bold text-gray-800 mt-1">{result.summary.secret_findings}</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Recommendations -->
        <section class="bg-white rounded-2xl shadow-lg p-8 mb-8">
            <h2 class="text-xl font-bold text-gray-800 mb-6">
                <i class="fas fa-tasks text-indigo-600 mr-2"></i>
                Prioritized Recommendations
            </h2>
            <div class="space-y-4">
                {self.build_recommendations_html(recommendations)}
            </div>
        </section>

        <!-- Top Issues -->
        <section class="bg-white rounded-2xl shadow-lg p-8 mb-8">
            <h2 class="text-xl font-bold text-gray-800 mb-6">
                <i class="fas fa-exclamation-triangle text-red-500 mr-2"></i>
                Top Priority Issues
            </h2>
            {self.build_top_issues_html(top_issues)}
        </section>

        <!-- Scan Coverage -->
        <section class="bg-white rounded-2xl shadow-lg p-8 mb-8">
            <h2 class="text-xl font-bold text-gray-800 mb-6">
                <i class="fas fa-search text-indigo-600 mr-2"></i>
                Scan Coverage
            </h2>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
                <div class="text-center">
                    <div class="w-16 h-16 bg-indigo-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i class="fas fa-file-code text-2xl text-indigo-600"></i>
                    </div>
                    <p class="text-2xl font-bold text-gray-800">{result.summary.files_scanned}</p>
                    <p class="text-sm text-gray-500">Files Scanned</p>
                </div>
                <div class="text-center">
                    <div class="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i class="fas fa-cubes text-2xl text-purple-600"></i>
                    </div>
                    <p class="text-2xl font-bold text-gray-800">{result.summary.dependencies_scanned}</p>
                    <p class="text-sm text-gray-500">Dependencies</p>
                </div>
                <div class="text-center">
                    <div class="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i class="fas fa-clock text-2xl text-green-600"></i>
                    </div>
                    <p class="text-2xl font-bold text-gray-800">{result.summary.scan_duration_seconds:.1f}s</p>
                    <p class="text-sm text-gray-500">Scan Duration</p>
                </div>
                <div class="text-center">
                    <div class="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
                        <i class="fas fa-shield-alt text-2xl text-blue-600"></i>
                    </div>
                    <p class="text-2xl font-bold text-gray-800">3</p>
                    <p class="text-sm text-gray-500">Scan Types</p>
                </div>
            </div>
        </section>

        <!-- Footer Actions -->
        <section class="flex justify-between items-center no-print">
            <div class="text-sm text-gray-500">
                <p>Scan ID: {result.scan_id}</p>
                <p>Target: {result.target_path}</p>
            </div>
            <div class="flex gap-4">
                <button onclick="window.print()" class="px-6 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition">
                    <i class="fas fa-print mr-2"></i>Print Report
                </button>
                <a href="securescan_report.html" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition">
                    <i class="fas fa-list mr-2"></i>View Full Details
                </a>
            </div>
        </section>
    </main>

    <footer class="bg-gray-800 text-gray-400 py-6 mt-12">
        <div class="max-w-6xl mx-auto px-8 text-center">
            <p>SecureScan Security Assessment Tool v1.0.0</p>
            <p class="text-sm text-gray-500 mt-1">Confidential - For Internal Use Only</p>
        </div>
    </footer>
</body>
</html>'''
    
    def build_recommendations_html(self, recommendations: List[Dict]) -> str:
        """Build HTML for recommendations"""
        html_parts = []
        for i, rec in enumerate(recommendations, 1):
            html_parts.append(f'''
            <div class="flex items-start gap-4 p-4 bg-gray-50 rounded-xl">
                <div class="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0" style="background-color: {rec['color']}20">
                    <i class="fas {rec['icon']}" style="color: {rec['color']}"></i>
                </div>
                <div class="flex-grow">
                    <div class="flex items-center gap-2">
                        <span class="px-2 py-0.5 text-xs font-semibold rounded" style="background-color: {rec['color']}20; color: {rec['color']}">{rec['priority']}</span>
                        <h4 class="font-semibold text-gray-800">{rec['title']}</h4>
                    </div>
                    <p class="text-gray-600 mt-1">{rec['description']}</p>
                </div>
            </div>
            ''')
        return '\n'.join(html_parts)
    
    def build_top_issues_html(self, issues: List[Finding]) -> str:
        """Build HTML for top issues"""
        if not issues:
            return '''
            <div class="text-center py-8 text-gray-500">
                <i class="fas fa-check-circle text-4xl text-green-500 mb-3"></i>
                <p>No critical issues found</p>
            </div>
            '''
        
        html_parts = ['<div class="overflow-x-auto"><table class="w-full"><thead class="bg-gray-50"><tr>']
        html_parts.append('<th class="px-4 py-3 text-left text-sm font-semibold text-gray-600">Severity</th>')
        html_parts.append('<th class="px-4 py-3 text-left text-sm font-semibold text-gray-600">Issue</th>')
        html_parts.append('<th class="px-4 py-3 text-left text-sm font-semibold text-gray-600">Type</th>')
        html_parts.append('<th class="px-4 py-3 text-left text-sm font-semibold text-gray-600">Location</th>')
        html_parts.append('</tr></thead><tbody>')
        
        severity_colors = {
            "critical": "#7f1d1d",
            "high": "#dc2626",
            "medium": "#f59e0b",
            "low": "#3b82f6",
            "info": "#6b7280"
        }
        
        for issue in issues:
            color = severity_colors.get(issue.severity, "#6b7280")
            file_name = issue.location.file_path.split('/')[-1].split('\\')[-1]
            html_parts.append(f'''
            <tr class="border-b border-gray-100">
                <td class="px-4 py-3">
                    <span class="px-2 py-1 rounded text-xs font-semibold text-white" style="background-color: {color}">
                        {issue.severity.upper()}
                    </span>
                </td>
                <td class="px-4 py-3">
                    <p class="font-medium text-gray-800">{issue.title}</p>
                    <p class="text-sm text-gray-500 truncate max-w-md">{issue.description[:100]}...</p>
                </td>
                <td class="px-4 py-3 text-sm text-gray-600">{issue.finding_type.value.upper()}</td>
                <td class="px-4 py-3 text-sm text-gray-600 font-mono">{file_name}:{issue.location.start_line}</td>
            </tr>
            ''')
        
        html_parts.append('</tbody></table></div>')
        return '\n'.join(html_parts)
