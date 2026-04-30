"""
Tests for Core SecureScan functionality
"""

import pytest
import tempfile
import json
from pathlib import Path

from securescan.config import ScanConfig
from securescan.core import SecureScan
from securescan.models import ScanResult


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestSecureScan:
    
    def test_full_scan_execution(self, temp_dir):
        """Test complete scan execution"""
        # Create test files
        py_file = Path(temp_dir) / "app.py"
        py_file.write_text('''
import os
os.system("rm -rf " + user_input)
password = "hardcoded_secret_123"
''')
        
        config = ScanConfig(
            target_path=temp_dir,
            output_dir=str(Path(temp_dir) / "reports"),
        )
        
        scanner = SecureScan(config)
        result = scanner.scan()
        
        assert isinstance(result, ScanResult)
        assert result.summary.total_findings > 0
        assert result.completed_at is not None
    
    def test_report_generation(self, temp_dir):
        """Test report generation"""
        py_file = Path(temp_dir) / "test.py"
        py_file.write_text('eval(user_input)')
        
        config = ScanConfig(
            target_path=temp_dir,
            output_dir=str(Path(temp_dir) / "reports"),
            output_formats=["json", "html", "sarif"],
        )
        
        scanner = SecureScan(config)
        result = scanner.scan()
        reports = scanner.generate_reports(result)
        
        assert len(reports) >= 3  # json, html, sarif + executive
        
        # Verify JSON report exists and is valid
        json_reports = [r for r in reports if r.endswith(".json")]
        assert len(json_reports) > 0
        
        with open(json_reports[0]) as f:
            data = json.load(f)
            assert "findings" in data
            assert "summary" in data
    
    def test_sarif_output(self, temp_dir):
        """Test SARIF output format"""
        py_file = Path(temp_dir) / "test.py"
        py_file.write_text('cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
        
        config = ScanConfig(
            target_path=temp_dir,
            output_dir=str(Path(temp_dir) / "reports"),
            output_formats=["sarif"],
        )
        
        scanner = SecureScan(config)
        result = scanner.scan()
        reports = scanner.generate_reports(result)
        
        sarif_reports = [r for r in reports if r.endswith(".sarif")]
        assert len(sarif_reports) > 0
        
        with open(sarif_reports[0]) as f:
            data = json.load(f)
            assert "$schema" in data
            assert data["version"] == "2.1.0"
            assert "runs" in data
    
    def test_fail_on_critical(self, temp_dir):
        """Test build failure on critical issues"""
        py_file = Path(temp_dir) / "test.py"
        py_file.write_text('os.system("rm -rf " + user_input)')
        
        config = ScanConfig(
            target_path=temp_dir,
            fail_on_critical=True,
        )
        
        scanner = SecureScan(config)
        result = scanner.scan()
        
        if result.summary.critical_count > 0:
            assert scanner.should_fail_build(result) == True
            assert scanner.get_exit_code(result) == 1
    
    def test_no_fail_mode(self, temp_dir):
        """Test no-fail mode"""
        py_file = Path(temp_dir) / "test.py"
        py_file.write_text('os.system("rm -rf " + user_input)')
        
        config = ScanConfig(
            target_path=temp_dir,
            fail_on_critical=False,
            fail_on_high=False,
        )
        
        scanner = SecureScan(config)
        result = scanner.scan()
        
        assert scanner.should_fail_build(result) == False
        assert scanner.get_exit_code(result) == 0
    
    def test_scanner_toggle(self, temp_dir):
        """Test enabling/disabling individual scanners"""
        py_file = Path(temp_dir) / "test.py"
        py_file.write_text('password = "secret123"')
        
        # Only secrets scanner
        config = ScanConfig(
            target_path=temp_dir,
            sast_enabled=False,
            sca_enabled=False,
            secrets_enabled=True,
        )
        
        scanner = SecureScan(config)
        result = scanner.scan()
        
        # Should only have secret findings
        assert result.summary.sast_findings == 0
        assert result.summary.sca_findings == 0
    
    def test_empty_directory(self, temp_dir):
        """Test scanning empty directory"""
        config = ScanConfig(target_path=temp_dir)
        
        scanner = SecureScan(config)
        result = scanner.scan()
        
        assert result.summary.total_findings == 0
        assert result.completed_at is not None
    
    def test_scan_summary_accuracy(self, temp_dir):
        """Test that summary counts are accurate"""
        py_file = Path(temp_dir) / "test.py"
        py_file.write_text('''
os.system("rm " + x)
cursor.execute("SELECT * FROM t WHERE id=" + id)
password = "secret123"
''')
        
        config = ScanConfig(target_path=temp_dir)
        scanner = SecureScan(config)
        result = scanner.scan()
        
        # Verify counts match
        total = (
            result.summary.critical_count +
            result.summary.high_count +
            result.summary.medium_count +
            result.summary.low_count +
            result.summary.info_count
        )
        assert total == result.summary.total_findings
        
        type_total = (
            result.summary.sast_findings +
            result.summary.sca_findings +
            result.summary.secret_findings
        )
        assert type_total == result.summary.total_findings
