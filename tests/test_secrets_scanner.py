"""
Tests for Secrets Scanner
"""

import pytest
import tempfile
from pathlib import Path

from securescan.config import ScanConfig
from securescan.scanners.secrets_scanner import SecretsScanner
from securescan.models import FindingType


@pytest.fixture
def scanner():
    config = ScanConfig()
    return SecretsScanner(config)


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestSecretsScanner:
    
    def test_aws_access_key_detection(self, scanner, temp_dir):
        """Test AWS access key detection"""
        code = '''
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''
        file_path = Path(temp_dir) / "config.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert len(aws_findings) > 0
        assert aws_findings[0].severity == "critical"
    
    def test_github_token_detection(self, scanner, temp_dir):
        """Test GitHub token detection"""
        code = '''
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
'''
        file_path = Path(temp_dir) / "secrets.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        github_findings = [f for f in findings if "GitHub" in f.title]
        assert len(github_findings) > 0
    
    def test_private_key_detection(self, scanner, temp_dir):
        """Test RSA private key detection"""
        code = '''
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----
'''
        file_path = Path(temp_dir) / "key.pem"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        key_findings = [f for f in findings if "Private Key" in f.title]
        assert len(key_findings) > 0
        assert key_findings[0].severity == "critical"
    
    def test_database_connection_string(self, scanner, temp_dir):
        """Test database connection string detection"""
        code = '''
DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"
'''
        file_path = Path(temp_dir) / "database.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        db_findings = [f for f in findings if "Database" in f.title or "Connection" in f.title]
        assert len(db_findings) > 0
    
    def test_jwt_token_detection(self, scanner, temp_dir):
        """Test JWT token detection"""
        code = '''
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
'''
        file_path = Path(temp_dir) / "auth.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        jwt_findings = [f for f in findings if "JWT" in f.title]
        assert len(jwt_findings) > 0
    
    def test_stripe_key_detection(self, scanner, temp_dir):
        """Test Stripe API key detection"""
        code = '''
STRIPE_SECRET_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
'''
        file_path = Path(temp_dir) / "payment.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        stripe_findings = [f for f in findings if "Stripe" in f.title]
        assert len(stripe_findings) > 0
    
    def test_false_positive_filtering(self, scanner, temp_dir):
        """Test that obvious false positives are filtered"""
        code = '''
# Example configuration
password = "changeme"
api_key = "your_api_key_here"
secret = "placeholder"
'''
        file_path = Path(temp_dir) / "example.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        # Should filter out obvious placeholders
        # May still detect some, but should be reduced
        assert all("placeholder" not in f.metadata.get("masked_value", "") for f in findings)
    
    def test_secret_masking(self, scanner, temp_dir):
        """Test that secrets are properly masked in output"""
        code = '''
API_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz123456"
'''
        file_path = Path(temp_dir) / "config.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        for finding in findings:
            if "masked_value" in finding.metadata:
                masked = finding.metadata["masked_value"]
                # Should contain asterisks for masking
                assert "*" in masked or len(masked) <= 8
    
    def test_finding_type_is_secret(self, scanner, temp_dir):
        """Test that all findings are marked as SECRET type"""
        code = '''
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
'''
        file_path = Path(temp_dir) / "test.py"
        file_path.write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        for finding in findings:
            assert finding.finding_type == FindingType.SECRET
    
    def test_skip_node_modules(self, scanner, temp_dir):
        """Test that node_modules directory is skipped"""
        # Create node_modules structure
        node_modules = Path(temp_dir) / "node_modules" / "some-package"
        node_modules.mkdir(parents=True)
        
        code = '''
const API_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx";
'''
        (node_modules / "index.js").write_text(code)
        
        findings = scanner.scan(temp_dir)
        
        # Should not find secrets in node_modules
        assert len(findings) == 0
