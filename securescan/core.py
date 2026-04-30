"""
Core orchestrator for SecureScan
Coordinates all scanners and report generation
"""

import uuid
import time
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from .config import ScanConfig
from .models import ScanResult, Finding, ScanSummary
from .scanners import SASTScanner, SCAScanner, SecretsScanner
from .reporters import JSONReporter, HTMLReporter, SARIFReporter, ExecutiveReporter


class SecureScan:
    """Main orchestrator for security scanning"""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.scanners = []
        self.reporters = []
        
        # Initialize scanners based on config
        if self.config.sast_enabled:
            self.scanners.append(SASTScanner(self.config))
        if self.config.sca_enabled:
            self.scanners.append(SCAScanner(self.config))
        if self.config.secrets_enabled:
            self.scanners.append(SecretsScanner(self.config))
        
        # Initialize reporters
        output_dir = self.config.output_dir
        if "json" in self.config.output_formats:
            self.reporters.append(JSONReporter(output_dir))
        if "html" in self.config.output_formats:
            self.reporters.append(HTMLReporter(output_dir))
        if "sarif" in self.config.output_formats:
            self.reporters.append(SARIFReporter(output_dir))
        if self.config.generate_executive_summary:
            self.reporters.append(ExecutiveReporter(output_dir))
    
    def scan(self, target_path: Optional[str] = None) -> ScanResult:
        """
        Execute security scan on target path
        
        Args:
            target_path: Path to scan (defaults to config target_path)
        
        Returns:
            ScanResult with all findings
        """
        target = target_path or self.config.target_path
        target_path_obj = Path(target).resolve()
        
        if not target_path_obj.exists():
            raise ValueError(f"Target path does not exist: {target}")
        
        # Initialize result
        result = ScanResult(
            scan_id=str(uuid.uuid4()),
            target_path=str(target_path_obj),
            started_at=datetime.utcnow(),
        )
        
        start_time = time.time()
        files_scanned = set()
        
        print(f"\n{'='*60}")
        print(f"  SecureScan Security Analysis")
        print(f"  Target: {target_path_obj}")
        print(f"{'='*60}\n")
        
        # Run each scanner
        for scanner in self.scanners:
            scanner_name = scanner.get_scanner_name()
            print(f"[*] Running {scanner_name}...")
            
            try:
                findings = scanner.scan(str(target_path_obj))
                
                for finding in findings:
                    result.add_finding(finding)
                    files_scanned.add(finding.location.file_path)
                
                print(f"    Found {len(findings)} issues")
                
            except Exception as e:
                print(f"    Error: {e}")
        
        # Update summary
        result.summary.files_scanned = len(files_scanned)
        result.summary.scan_duration_seconds = time.time() - start_time
        result.completed_at = datetime.utcnow()
        
        # Count dependencies if SCA was run
        if self.config.sca_enabled:
            result.summary.dependencies_scanned = self._count_dependencies(str(target_path_obj))
        
        print(f"\n{'='*60}")
        print(f"  Scan Complete!")
        print(f"  Duration: {result.summary.scan_duration_seconds:.2f}s")
        print(f"  Total Findings: {result.summary.total_findings}")
        print(f"    - Critical: {result.summary.critical_count}")
        print(f"    - High: {result.summary.high_count}")
        print(f"    - Medium: {result.summary.medium_count}")
        print(f"    - Low: {result.summary.low_count}")
        print(f"{'='*60}\n")
        
        return result
    
    def generate_reports(self, result: ScanResult, base_filename: Optional[str] = None) -> List[str]:
        """
        Generate all configured reports
        
        Args:
            result: Scan result to report on
            base_filename: Base name for report files
        
        Returns:
            List of generated report file paths
        """
        if base_filename is None:
            base_filename = f"securescan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        report_paths = []
        
        print("[*] Generating reports...")
        
        for reporter in self.reporters:
            try:
                report_path = reporter.generate(result, base_filename)
                report_paths.append(report_path)
                print(f"    Generated {reporter.get_format_name()}: {report_path}")
            except Exception as e:
                print(f"    Error generating {reporter.get_format_name()} report: {e}")
        
        return report_paths
    
    def run(self, target_path: Optional[str] = None) -> tuple:
        """
        Execute full scan and report generation
        
        Args:
            target_path: Path to scan
        
        Returns:
            Tuple of (ScanResult, list of report paths)
        """
        result = self.scan(target_path)
        report_paths = self.generate_reports(result)
        return result, report_paths
    
    def _count_dependencies(self, target_path: str) -> int:
        """Count total dependencies found in manifest files"""
        import json
        count = 0
        target = Path(target_path)
        
        # Count npm dependencies
        package_json = target / "package.json"
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                    count += len(data.get("dependencies", {}))
                    count += len(data.get("devDependencies", {}))
            except Exception:
                pass
        
        # Count Python dependencies
        requirements = target / "requirements.txt"
        if requirements.exists():
            try:
                with open(requirements) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and not line.startswith('-'):
                            count += 1
            except Exception:
                pass
        
        return count
    
    def should_fail_build(self, result: ScanResult) -> bool:
        """
        Determine if the build should fail based on findings
        
        Returns:
            True if build should fail based on config thresholds
        """
        if self.config.fail_on_critical and result.summary.critical_count > 0:
            return True
        
        if self.config.fail_on_high and result.summary.high_count > 0:
            return True
        
        if self.config.max_issues_threshold > 0:
            if result.summary.total_findings > self.config.max_issues_threshold:
                return True
        
        return False
    
    def get_exit_code(self, result: ScanResult) -> int:
        """
        Get appropriate exit code for CI/CD
        
        Returns:
            0 for success, 1 for failure
        """
        return 1 if self.should_fail_build(result) else 0
