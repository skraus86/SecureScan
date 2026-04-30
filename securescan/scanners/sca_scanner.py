"""
SCA (Software Composition Analysis) Scanner
Detects vulnerabilities in third-party dependencies
"""

import re
import json
import uuid
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

from .base import BaseScanner
from ..models import Finding, FindingType, Location, Remediation, Dependency, Vulnerability, SCAFinding
from ..config import ScanConfig, DEPENDENCY_FILES


# Known vulnerable packages database (simplified - in production, use NVD/OSV/GitHub Advisory)
VULNERABILITY_DATABASE = {
    "npm": {
        "lodash": [
            {"version_range": "<4.17.21", "cve": "CVE-2021-23337", "severity": "high", "cvss": 7.2,
             "description": "Command Injection in lodash", "fixed_version": "4.17.21"},
            {"version_range": "<4.17.19", "cve": "CVE-2020-8203", "severity": "high", "cvss": 7.4,
             "description": "Prototype Pollution in lodash", "fixed_version": "4.17.19"},
        ],
        "axios": [
            {"version_range": "<0.21.1", "cve": "CVE-2020-28168", "severity": "medium", "cvss": 5.9,
             "description": "Server-Side Request Forgery in axios", "fixed_version": "0.21.1"},
        ],
        "express": [
            {"version_range": "<4.17.3", "cve": "CVE-2022-24999", "severity": "high", "cvss": 7.5,
             "description": "Open Redirect in express", "fixed_version": "4.17.3"},
        ],
        "minimist": [
            {"version_range": "<1.2.6", "cve": "CVE-2021-44906", "severity": "critical", "cvss": 9.8,
             "description": "Prototype Pollution in minimist", "fixed_version": "1.2.6"},
        ],
        "node-fetch": [
            {"version_range": "<2.6.7", "cve": "CVE-2022-0235", "severity": "high", "cvss": 8.8,
             "description": "Exposure of Sensitive Information in node-fetch", "fixed_version": "2.6.7"},
        ],
        "jsonwebtoken": [
            {"version_range": "<9.0.0", "cve": "CVE-2022-23529", "severity": "critical", "cvss": 9.8,
             "description": "Improper Restriction of Security Token Assignment", "fixed_version": "9.0.0"},
        ],
        "moment": [
            {"version_range": "<2.29.4", "cve": "CVE-2022-31129", "severity": "high", "cvss": 7.5,
             "description": "Path Traversal in moment", "fixed_version": "2.29.4"},
        ],
    },
    "pypi": {
        "django": [
            {"version_range": "<3.2.14", "cve": "CVE-2022-34265", "severity": "critical", "cvss": 9.8,
             "description": "SQL Injection in Django", "fixed_version": "3.2.14"},
            {"version_range": "<2.2.28", "cve": "CVE-2022-28346", "severity": "critical", "cvss": 9.8,
             "description": "SQL Injection in QuerySet.annotate()", "fixed_version": "2.2.28"},
        ],
        "flask": [
            {"version_range": "<2.2.5", "cve": "CVE-2023-30861", "severity": "high", "cvss": 7.5,
             "description": "Cookie Injection in Flask", "fixed_version": "2.2.5"},
        ],
        "requests": [
            {"version_range": "<2.31.0", "cve": "CVE-2023-32681", "severity": "medium", "cvss": 6.1,
             "description": "Unintended leak of Proxy-Authorization header", "fixed_version": "2.31.0"},
        ],
        "pyyaml": [
            {"version_range": "<5.4", "cve": "CVE-2020-14343", "severity": "critical", "cvss": 9.8,
             "description": "Arbitrary Code Execution in PyYAML", "fixed_version": "5.4"},
        ],
        "pillow": [
            {"version_range": "<9.3.0", "cve": "CVE-2022-45198", "severity": "high", "cvss": 7.5,
             "description": "DoS via crafted image in Pillow", "fixed_version": "9.3.0"},
        ],
        "cryptography": [
            {"version_range": "<39.0.1", "cve": "CVE-2023-23931", "severity": "medium", "cvss": 6.5,
             "description": "Memory corruption in cryptography", "fixed_version": "39.0.1"},
        ],
        "urllib3": [
            {"version_range": "<1.26.5", "cve": "CVE-2021-33503", "severity": "high", "cvss": 7.5,
             "description": "ReDoS in urllib3", "fixed_version": "1.26.5"},
        ],
    },
    "maven": {
        "org.apache.logging.log4j:log4j-core": [
            {"version_range": "<2.17.0", "cve": "CVE-2021-44228", "severity": "critical", "cvss": 10.0,
             "description": "Log4Shell - Remote Code Execution", "fixed_version": "2.17.0"},
        ],
        "org.springframework:spring-core": [
            {"version_range": "<5.3.18", "cve": "CVE-2022-22965", "severity": "critical", "cvss": 9.8,
             "description": "Spring4Shell - Remote Code Execution", "fixed_version": "5.3.18"},
        ],
        "com.fasterxml.jackson.core:jackson-databind": [
            {"version_range": "<2.13.2.1", "cve": "CVE-2020-36518", "severity": "high", "cvss": 7.5,
             "description": "Denial of Service in jackson-databind", "fixed_version": "2.13.2.1"},
        ],
    },
    "nuget": {
        "Newtonsoft.Json": [
            {"version_range": "<13.0.1", "cve": "CVE-2024-21907", "severity": "high", "cvss": 7.5,
             "description": "Denial of Service in Newtonsoft.Json", "fixed_version": "13.0.1"},
        ],
        "System.Text.Json": [
            {"version_range": "<6.0.0", "cve": "CVE-2021-26701", "severity": "critical", "cvss": 9.8,
             "description": "Remote Code Execution in System.Text.Json", "fixed_version": "6.0.0"},
        ],
    },
}

# License risk classifications
LICENSE_RISKS = {
    "high_risk": ["GPL-3.0", "AGPL-3.0", "GPL-2.0", "LGPL-3.0", "LGPL-2.1"],
    "medium_risk": ["MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0"],
    "low_risk": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unlicense"],
}


class SCAScanner(BaseScanner):
    """Software Composition Analysis Scanner"""
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.vuln_db = VULNERABILITY_DATABASE
    
    def get_scanner_name(self) -> str:
        return "SCA Scanner"
    
    def scan(self, target_path: str) -> List[Finding]:
        """Scan target path for vulnerable dependencies"""
        findings = []
        
        # Scan for different package managers
        findings.extend(self.scan_npm(target_path))
        findings.extend(self.scan_python(target_path))
        findings.extend(self.scan_maven(target_path))
        findings.extend(self.scan_nuget(target_path))
        
        return findings
    
    def parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Parse version string into tuple for comparison"""
        # Remove common prefixes
        version_str = re.sub(r'^[v^~>=<]', '', version_str)
        # Extract numeric parts
        parts = re.findall(r'\d+', version_str)
        return tuple(int(p) for p in parts) if parts else (0,)
    
    def is_vulnerable(self, version: str, version_range: str) -> bool:
        """Check if version falls within vulnerable range"""
        try:
            current = self.parse_version(version)
            
            # Handle different range formats
            if version_range.startswith('<'):
                max_version = self.parse_version(version_range[1:])
                return current < max_version
            elif version_range.startswith('<='):
                max_version = self.parse_version(version_range[2:])
                return current <= max_version
            elif version_range.startswith('>='):
                min_version = self.parse_version(version_range[2:])
                return current >= min_version
            elif version_range.startswith('>'):
                min_version = self.parse_version(version_range[1:])
                return current > min_version
            elif '-' in version_range:
                parts = version_range.split('-')
                min_ver = self.parse_version(parts[0])
                max_ver = self.parse_version(parts[1])
                return min_ver <= current <= max_ver
            else:
                return version == version_range
        except Exception:
            return False
    
    def scan_npm(self, target_path: str) -> List[Finding]:
        """Scan npm/yarn dependencies"""
        findings = []
        
        for file_path in self.get_files(target_path):
            if file_path.name == "package.json":
                findings.extend(self.parse_package_json(file_path))
            elif file_path.name == "package-lock.json":
                findings.extend(self.parse_package_lock(file_path))
        
        return findings
    
    def parse_package_json(self, file_path: Path) -> List[Finding]:
        """Parse package.json for dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        try:
            data = json.loads(content)
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))
            
            for pkg_name, version in all_deps.items():
                # Clean version string
                clean_version = re.sub(r'^[\^~>=<]', '', version)
                
                # Check for vulnerabilities
                if pkg_name in self.vuln_db.get("npm", {}):
                    for vuln in self.vuln_db["npm"][pkg_name]:
                        if self.is_vulnerable(clean_version, vuln["version_range"]):
                            finding = self.create_sca_finding(
                                pkg_name, clean_version, "npm", file_path, vuln
                            )
                            findings.append(finding)
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def parse_package_lock(self, file_path: Path) -> List[Finding]:
        """Parse package-lock.json for transitive dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        try:
            data = json.loads(content)
            packages = data.get("packages", data.get("dependencies", {}))
            
            for pkg_path, pkg_info in packages.items():
                if isinstance(pkg_info, dict):
                    pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules" in pkg_path else pkg_path
                    version = pkg_info.get("version", "")
                    
                    if pkg_name and pkg_name in self.vuln_db.get("npm", {}):
                        for vuln in self.vuln_db["npm"][pkg_name]:
                            if self.is_vulnerable(version, vuln["version_range"]):
                                finding = self.create_sca_finding(
                                    pkg_name, version, "npm", file_path, vuln
                                )
                                findings.append(finding)
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def scan_python(self, target_path: str) -> List[Finding]:
        """Scan Python dependencies"""
        findings = []
        
        for file_path in self.get_files(target_path):
            if file_path.name == "requirements.txt":
                findings.extend(self.parse_requirements_txt(file_path))
            elif file_path.name == "Pipfile.lock":
                findings.extend(self.parse_pipfile_lock(file_path))
            elif file_path.name == "pyproject.toml":
                findings.extend(self.parse_pyproject_toml(file_path))
        
        return findings
    
    def parse_requirements_txt(self, file_path: Path) -> List[Finding]:
        """Parse requirements.txt for dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        for line_num, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Parse package==version or package>=version format
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([0-9.]+)', line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(3)
                
                if pkg_name in self.vuln_db.get("pypi", {}):
                    for vuln in self.vuln_db["pypi"][pkg_name]:
                        if self.is_vulnerable(version, vuln["version_range"]):
                            finding = self.create_sca_finding(
                                pkg_name, version, "pypi", file_path, vuln, line_num
                            )
                            findings.append(finding)
        
        return findings
    
    def parse_pipfile_lock(self, file_path: Path) -> List[Finding]:
        """Parse Pipfile.lock for dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        try:
            data = json.loads(content)
            for section in ["default", "develop"]:
                packages = data.get(section, {})
                for pkg_name, pkg_info in packages.items():
                    version = pkg_info.get("version", "").lstrip("=")
                    pkg_name_lower = pkg_name.lower()
                    
                    if pkg_name_lower in self.vuln_db.get("pypi", {}):
                        for vuln in self.vuln_db["pypi"][pkg_name_lower]:
                            if self.is_vulnerable(version, vuln["version_range"]):
                                finding = self.create_sca_finding(
                                    pkg_name, version, "pypi", file_path, vuln
                                )
                                findings.append(finding)
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def parse_pyproject_toml(self, file_path: Path) -> List[Finding]:
        """Parse pyproject.toml for dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        # Simple TOML parsing for dependencies
        in_deps = False
        for line_num, line in enumerate(content.split('\n'), 1):
            if '[project.dependencies]' in line or '[tool.poetry.dependencies]' in line:
                in_deps = True
                continue
            if in_deps and line.startswith('['):
                in_deps = False
                continue
            
            if in_deps:
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*["\']?([^"\']+)["\']?', line)
                if match:
                    pkg_name = match.group(1).lower()
                    version_spec = match.group(2)
                    version = re.sub(r'^[\^~>=<]', '', version_spec)
                    
                    if pkg_name in self.vuln_db.get("pypi", {}):
                        for vuln in self.vuln_db["pypi"][pkg_name]:
                            if self.is_vulnerable(version, vuln["version_range"]):
                                finding = self.create_sca_finding(
                                    pkg_name, version, "pypi", file_path, vuln, line_num
                                )
                                findings.append(finding)
        
        return findings
    
    def scan_maven(self, target_path: str) -> List[Finding]:
        """Scan Maven dependencies"""
        findings = []
        
        for file_path in self.get_files(target_path):
            if file_path.name == "pom.xml":
                findings.extend(self.parse_pom_xml(file_path))
        
        return findings
    
    def parse_pom_xml(self, file_path: Path) -> List[Finding]:
        """Parse pom.xml for dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        # Simple XML parsing for dependencies
        dep_pattern = re.compile(
            r'<dependency>\s*'
            r'<groupId>([^<]+)</groupId>\s*'
            r'<artifactId>([^<]+)</artifactId>\s*'
            r'<version>([^<]+)</version>',
            re.DOTALL
        )
        
        for match in dep_pattern.finditer(content):
            group_id = match.group(1)
            artifact_id = match.group(2)
            version = match.group(3)
            
            # Skip property references
            if '${' in version:
                continue
            
            full_name = f"{group_id}:{artifact_id}"
            
            if full_name in self.vuln_db.get("maven", {}):
                for vuln in self.vuln_db["maven"][full_name]:
                    if self.is_vulnerable(version, vuln["version_range"]):
                        line_num = content[:match.start()].count('\n') + 1
                        finding = self.create_sca_finding(
                            full_name, version, "maven", file_path, vuln, line_num
                        )
                        findings.append(finding)
        
        return findings
    
    def scan_nuget(self, target_path: str) -> List[Finding]:
        """Scan NuGet dependencies"""
        findings = []
        
        for file_path in self.get_files(target_path):
            if file_path.suffix == ".csproj":
                findings.extend(self.parse_csproj(file_path))
        
        return findings
    
    def parse_csproj(self, file_path: Path) -> List[Finding]:
        """Parse .csproj for NuGet dependencies"""
        findings = []
        content = self.read_file_content(file_path)
        
        # Parse PackageReference elements
        pkg_pattern = re.compile(
            r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"',
            re.IGNORECASE
        )
        
        for match in pkg_pattern.finditer(content):
            pkg_name = match.group(1)
            version = match.group(2)
            
            if pkg_name in self.vuln_db.get("nuget", {}):
                for vuln in self.vuln_db["nuget"][pkg_name]:
                    if self.is_vulnerable(version, vuln["version_range"]):
                        line_num = content[:match.start()].count('\n') + 1
                        finding = self.create_sca_finding(
                            pkg_name, version, "nuget", file_path, vuln, line_num
                        )
                        findings.append(finding)
        
        return findings
    
    def create_sca_finding(self, pkg_name: str, version: str, ecosystem: str,
                          file_path: Path, vuln: Dict, line_num: int = 1) -> Finding:
        """Create an SCA finding from vulnerability data"""
        return Finding(
            id=str(uuid.uuid4()),
            title=f"Vulnerable dependency: {pkg_name}@{version}",
            description=vuln["description"],
            severity=vuln["severity"],
            finding_type=FindingType.SCA,
            location=Location(
                file_path=str(file_path),
                start_line=line_num,
                end_line=line_num,
            ),
            rule_id=f"SCA-{vuln['cve']}",
            cwe_id="CWE-1035",  # Using Components with Known Vulnerabilities
            cvss_score=vuln.get("cvss"),
            remediation=Remediation(
                description=f"Upgrade {pkg_name} to version {vuln['fixed_version']} or later.",
                references=[
                    f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}",
                    f"https://github.com/advisories?query={vuln['cve']}"
                ]
            ),
            metadata={
                "package_name": pkg_name,
                "installed_version": version,
                "fixed_version": vuln["fixed_version"],
                "ecosystem": ecosystem,
                "cve": vuln["cve"],
            }
        )
