"""
Tests for SAST Scanner
"""

import pytest
import tempfile
import os
from pathlib import Path

from securescan.config import ScanConfig
from securescan.scanners.sast_scanner import SASTScanner
from securescan.models import FindingType


@pytest.fixture
def scanner():
    config = ScanConfig()
    return SASTScanner(config)


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestSASTScanner:
    
    def test_sql_injection_detection(self, scanner, temp_dir):
        """Test SQL injection detection"""
        code = '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
'''
        file_path = Path(temp_dir) / "vulnerable.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        assert len(findings) > 0
        sql_findings = [f for f in findings if "SQL" in f.title]
        assert len(sql_findings) > 0
        assert sql_findings[0].severity in ["critical", "high"]
    
    def test_command_injection_detection(self, scanner, temp_dir):
        """Test command injection detection"""
        code = '''
import os

def run_command(user_input):
    os.system("ls -la " + user_input)
'''
        file_path = Path(temp_dir) / "cmd_injection.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        cmd_findings = [f for f in findings if "Command" in f.title]
        assert len(cmd_findings) > 0
        assert cmd_findings[0].cwe_id == "CWE-78"
    
    def test_eval_detection(self, scanner, temp_dir):
        """Test dangerous eval() detection"""
        code = '''
def process_input(user_data):
    result = eval(user_data)
    return result
'''
        file_path = Path(temp_dir) / "eval_usage.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        eval_findings = [f for f in findings if "eval" in f.title.lower()]
        assert len(eval_findings) > 0
    
    def test_hardcoded_password_detection(self, scanner, temp_dir):
        """Test hardcoded password detection"""
        code = '''
DATABASE_CONFIG = {
    "host": "localhost",
    "password": "super_secret_password_123"
}
'''
        file_path = Path(temp_dir) / "config.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        pwd_findings = [f for f in findings if "Password" in f.title or "password" in f.title.lower()]
        assert len(pwd_findings) > 0
    
    def test_clean_code_no_findings(self, scanner, temp_dir):
        """Test that clean code produces no findings"""
        code = '''
def add_numbers(a: int, b: int) -> int:
    """Add two numbers safely."""
    return a + b

def greet(name: str) -> str:
    """Return a greeting."""
    return f"Hello, {name}!"
'''
        file_path = Path(temp_dir) / "clean.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        # Should have no or minimal findings
        critical_findings = [f for f in findings if f.severity == "critical"]
        assert len(critical_findings) == 0
    
    def test_xss_detection_javascript(self, scanner, temp_dir):
        """Test XSS detection in JavaScript"""
        code = '''
function displayMessage(userInput) {
    document.getElementById("output").innerHTML = userInput;
}
'''
        file_path = Path(temp_dir) / "xss.js"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        xss_findings = [f for f in findings if "XSS" in f.title or "Cross-Site" in f.title]
        assert len(xss_findings) > 0
    
    def test_finding_has_remediation(self, scanner, temp_dir):
        """Test that findings include remediation guidance"""
        code = '''
import os
os.system("rm -rf " + user_input)
'''
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        assert len(findings) > 0
        for finding in findings:
            assert finding.remediation is not None
            assert finding.remediation.description
    
    def test_finding_type_is_sast(self, scanner, temp_dir):
        """Test that all findings are marked as SAST type"""
        code = '''
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
'''
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        for finding in findings:
            assert finding.finding_type == FindingType.SAST
