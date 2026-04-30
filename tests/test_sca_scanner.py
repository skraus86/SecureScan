"""
Tests for SCA Scanner
"""

import pytest
import tempfile
import json
from pathlib import Path

from securescan.config import ScanConfig
from securescan.scanners.sca_scanner import SCAScanner
from securescan.models import FindingType


@pytest.fixture
def scanner():
    config = ScanConfig()
    return SCAScanner(config)


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestSCAScanner:
    
    def test_vulnerable_npm_package(self, scanner, temp_dir):
        """Test detection of vulnerable npm package"""
        package_json = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15"  # Vulnerable version
            }
        }
        
        file_path = Path(temp_dir) / "package.json"
        file_path.write_text(json.dumps(package_json))
        
        findings = scanner.scan(temp_dir)
        
        lodash_findings = [f for f in findings if "lodash" in f.title.lower()]
        assert len(lodash_findings) > 0
        assert lodash_findings[0].severity in ["critical", "high"]
    
    def test_vulnerable_python_package(self, scanner, temp_dir):
        """Test detection of vulnerable Python package"""
        requirements = '''
django==2.2.20
flask==2.0.0
requests==2.25.0
'''
        file_path = Path(temp_dir) / "requirements.txt"
        file_path.write_text(requirements)
        
        findings = scanner.scan(temp_dir)
        
        # Should detect vulnerable versions
        django_findings = [f for f in findings if "django" in f.title.lower()]
        assert len(django_findings) > 0
    
    def test_safe_package_no_findings(self, scanner, temp_dir):
        """Test that safe packages don't produce findings"""
        package_json = {
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.21"  # Safe version
            }
        }
        
        file_path = Path(temp_dir) / "package.json"
        file_path.write_text(json.dumps(package_json))
        
        findings = scanner.scan(temp_dir)
        
        lodash_findings = [f for f in findings if "lodash" in f.title.lower()]
        assert len(lodash_findings) == 0
    
    def test_log4j_detection(self, scanner, temp_dir):
        """Test Log4Shell (CVE-2021-44228) detection"""
        pom_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>
'''
        file_path = Path(temp_dir) / "pom.xml"
        file_path.write_text(pom_xml)
        
        findings = scanner.scan(temp_dir)
        
        log4j_findings = [f for f in findings if "log4j" in f.title.lower()]
        assert len(log4j_findings) > 0
        assert any("CVE-2021-44228" in f.rule_id for f in log4j_findings)
    
    def test_finding_includes_fixed_version(self, scanner, temp_dir):
        """Test that findings include fixed version info"""
        requirements = '''
django==2.2.20
'''
        file_path = Path(temp_dir) / "requirements.txt"
        file_path.write_text(requirements)
        
        findings = scanner.scan(temp_dir)
        
        for finding in findings:
            if "django" in finding.title.lower():
                assert "fixed_version" in finding.metadata
                assert finding.metadata["fixed_version"]
    
    def test_finding_type_is_sca(self, scanner, temp_dir):
        """Test that all findings are marked as SCA type"""
        requirements = '''
django==2.2.20
'''
        file_path = Path(temp_dir) / "requirements.txt"
        file_path.write_text(requirements)
        
        findings = scanner.scan(temp_dir)
        
        for finding in findings:
            assert finding.finding_type == FindingType.SCA
    
    def test_package_lock_scanning(self, scanner, temp_dir):
        """Test scanning of package-lock.json"""
        package_lock = {
            "name": "test-app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "node_modules/minimist": {
                    "version": "1.2.5"  # Vulnerable
                }
            }
        }
        
        file_path = Path(temp_dir) / "package-lock.json"
        file_path.write_text(json.dumps(package_lock))
        
        findings = scanner.scan(temp_dir)
        
        minimist_findings = [f for f in findings if "minimist" in f.title.lower()]
        assert len(minimist_findings) > 0
    
    def test_csproj_scanning(self, scanner, temp_dir):
        """Test scanning of .csproj files"""
        csproj = '''<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.0" />
  </ItemGroup>
</Project>
'''
        file_path = Path(temp_dir) / "MyApp.csproj"
        file_path.write_text(csproj)
        
        findings = scanner.scan(temp_dir)
        
        newtonsoft_findings = [f for f in findings if "Newtonsoft" in f.title]
        assert len(newtonsoft_findings) > 0
    
    def test_remediation_guidance(self, scanner, temp_dir):
        """Test that findings include remediation guidance"""
        requirements = '''
django==2.2.20
'''
        file_path = Path(temp_dir) / "requirements.txt"
        file_path.write_text(requirements)
        
        findings = scanner.scan(temp_dir)
        
        for finding in findings:
            assert finding.remediation is not None
            assert "upgrade" in finding.remediation.description.lower() or "update" in finding.remediation.description.lower()
