"""
Secrets Scanner
Detects hardcoded secrets, API keys, and credentials in source code
"""

import re
import math
import uuid
from typing import List, Dict, Any, Tuple
from pathlib import Path
from dataclasses import dataclass

from .base import BaseScanner
from ..models import Finding, FindingType, Location, Remediation, SecretFinding
from ..config import ScanConfig


@dataclass
class SecretPattern:
    """Represents a secret detection pattern"""
    pattern_id: str
    name: str
    pattern: re.Pattern
    severity: str
    description: str
    false_positive_patterns: List[str] = None
    
    def __post_init__(self):
        if self.false_positive_patterns is None:
            self.false_positive_patterns = []


# Secret detection patterns
SECRET_PATTERNS = [
    # AWS
    SecretPattern(
        pattern_id="SEC001",
        name="AWS Access Key ID",
        pattern=re.compile(r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        severity="critical",
        description="AWS Access Key ID detected. This could allow unauthorized access to AWS resources."
    ),
    SecretPattern(
        pattern_id="SEC002",
        name="AWS Secret Access Key",
        pattern=re.compile(r'(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        severity="critical",
        description="AWS Secret Access Key detected. This could allow unauthorized access to AWS resources."
    ),
    
    # Azure
    SecretPattern(
        pattern_id="SEC003",
        name="Azure Storage Account Key",
        pattern=re.compile(r'(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{88}'),
        severity="critical",
        description="Azure Storage Account Key detected."
    ),
    SecretPattern(
        pattern_id="SEC004",
        name="Azure Service Principal Secret",
        pattern=re.compile(r'(?i)(?:client[_\-]?secret|azure[_\-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9~._-]{34,}["\']?'),
        severity="critical",
        description="Azure Service Principal Secret detected."
    ),
    
    # Google Cloud
    SecretPattern(
        pattern_id="SEC005",
        name="Google Cloud API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        severity="high",
        description="Google Cloud API Key detected."
    ),
    SecretPattern(
        pattern_id="SEC006",
        name="Google Cloud Service Account",
        pattern=re.compile(r'(?i)"type"\s*:\s*"service_account"'),
        severity="high",
        description="Google Cloud Service Account JSON detected."
    ),
    
    # GitHub
    SecretPattern(
        pattern_id="SEC007",
        name="GitHub Personal Access Token",
        pattern=re.compile(r'ghp_[A-Za-z0-9]{36}'),
        severity="critical",
        description="GitHub Personal Access Token detected."
    ),
    SecretPattern(
        pattern_id="SEC008",
        name="GitHub OAuth Access Token",
        pattern=re.compile(r'gho_[A-Za-z0-9]{36}'),
        severity="critical",
        description="GitHub OAuth Access Token detected."
    ),
    SecretPattern(
        pattern_id="SEC009",
        name="GitHub App Token",
        pattern=re.compile(r'(?:ghu|ghs)_[A-Za-z0-9]{36}'),
        severity="critical",
        description="GitHub App Token detected."
    ),
    
    # Generic API Keys
    SecretPattern(
        pattern_id="SEC010",
        name="Generic API Key",
        pattern=re.compile(r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
        severity="high",
        description="Generic API Key detected."
    ),
    SecretPattern(
        pattern_id="SEC011",
        name="Generic Secret Key",
        pattern=re.compile(r'(?i)(?:secret[_\-]?key|secretkey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'),
        severity="high",
        description="Generic Secret Key detected."
    ),
    
    # Database Credentials
    SecretPattern(
        pattern_id="SEC012",
        name="Database Connection String",
        pattern=re.compile(r'(?i)(?:mongodb|postgres|mysql|mssql|redis|amqp)://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+'),
        severity="critical",
        description="Database connection string with credentials detected."
    ),
    SecretPattern(
        pattern_id="SEC013",
        name="Database Password",
        pattern=re.compile(r'(?i)(?:db[_\-]?password|database[_\-]?password|mysql[_\-]?password|postgres[_\-]?password)\s*[=:]\s*["\']?([^\s"\']{8,})["\']?'),
        severity="critical",
        description="Database password detected."
    ),
    
    # Private Keys
    SecretPattern(
        pattern_id="SEC014",
        name="RSA Private Key",
        pattern=re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        severity="critical",
        description="RSA Private Key detected."
    ),
    SecretPattern(
        pattern_id="SEC015",
        name="SSH Private Key",
        pattern=re.compile(r'-----BEGIN (?:OPENSSH|DSA|EC|PGP) PRIVATE KEY-----'),
        severity="critical",
        description="SSH/DSA/EC Private Key detected."
    ),
    SecretPattern(
        pattern_id="SEC016",
        name="PGP Private Key",
        pattern=re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        severity="critical",
        description="PGP Private Key detected."
    ),
    
    # JWT
    SecretPattern(
        pattern_id="SEC017",
        name="JWT Token",
        pattern=re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        severity="medium",
        description="JWT Token detected. May contain sensitive claims."
    ),
    SecretPattern(
        pattern_id="SEC018",
        name="JWT Secret",
        pattern=re.compile(r'(?i)(?:jwt[_\-]?secret|jwt[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'),
        severity="critical",
        description="JWT Secret Key detected."
    ),
    
    # Slack
    SecretPattern(
        pattern_id="SEC019",
        name="Slack Token",
        pattern=re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'),
        severity="high",
        description="Slack Token detected."
    ),
    SecretPattern(
        pattern_id="SEC020",
        name="Slack Webhook URL",
        pattern=re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        severity="medium",
        description="Slack Webhook URL detected."
    ),
    
    # Stripe
    SecretPattern(
        pattern_id="SEC021",
        name="Stripe API Key",
        pattern=re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'),
        severity="critical",
        description="Stripe API Key detected."
    ),
    
    # Twilio
    SecretPattern(
        pattern_id="SEC022",
        name="Twilio API Key",
        pattern=re.compile(r'SK[a-f0-9]{32}'),
        severity="high",
        description="Twilio API Key detected."
    ),
    
    # SendGrid
    SecretPattern(
        pattern_id="SEC023",
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
        severity="high",
        description="SendGrid API Key detected."
    ),
    
    # Mailchimp
    SecretPattern(
        pattern_id="SEC024",
        name="Mailchimp API Key",
        pattern=re.compile(r'[a-f0-9]{32}-us[0-9]{1,2}'),
        severity="high",
        description="Mailchimp API Key detected."
    ),
    
    # Generic Password
    SecretPattern(
        pattern_id="SEC025",
        name="Hardcoded Password",
        pattern=re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'),
        severity="high",
        description="Hardcoded password detected.",
        false_positive_patterns=["password123", "changeme", "placeholder", "example", "your_password"]
    ),
    
    # Bearer Token
    SecretPattern(
        pattern_id="SEC026",
        name="Bearer Token",
        pattern=re.compile(r'(?i)bearer\s+[A-Za-z0-9_\-\.=]+'),
        severity="high",
        description="Bearer token detected in code."
    ),
    
    # NPM Token
    SecretPattern(
        pattern_id="SEC027",
        name="NPM Access Token",
        pattern=re.compile(r'npm_[A-Za-z0-9]{36}'),
        severity="high",
        description="NPM Access Token detected."
    ),
    
    # Heroku
    SecretPattern(
        pattern_id="SEC028",
        name="Heroku API Key",
        pattern=re.compile(r'(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9\-]{36})["\']?'),
        severity="high",
        description="Heroku API Key detected."
    ),
    
    # Firebase
    SecretPattern(
        pattern_id="SEC029",
        name="Firebase Database URL",
        pattern=re.compile(r'https://[a-z0-9-]+\.firebaseio\.com'),
        severity="medium",
        description="Firebase Database URL detected."
    ),
    
    # Generic Token
    SecretPattern(
        pattern_id="SEC030",
        name="Generic Auth Token",
        pattern=re.compile(r'(?i)(?:auth[_\-]?token|access[_\-]?token|refresh[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?'),
        severity="high",
        description="Authentication token detected."
    ),
]

# Files to skip during secrets scanning
SKIP_FILES = [
    ".min.js", ".min.css", ".map", ".lock",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
]

# Directories to skip
SKIP_DIRS = [
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", ".idea", ".vscode",
]


class SecretsScanner(BaseScanner):
    """Scanner for detecting hardcoded secrets and credentials"""
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.patterns = SECRET_PATTERNS
        self.entropy_threshold = config.secrets_entropy_threshold
    
    def get_scanner_name(self) -> str:
        return "Secrets Scanner"
    
    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for char in set(data):
            p = data.count(char) / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    def is_false_positive(self, value: str, pattern: SecretPattern) -> bool:
        """Check if the detected secret is likely a false positive"""
        value_lower = value.lower()
        
        # Check pattern-specific false positives
        for fp in pattern.false_positive_patterns:
            if fp.lower() in value_lower:
                return True
        
        # Common false positive patterns
        common_fps = [
            "example", "sample", "test", "demo", "placeholder",
            "your_", "xxx", "abc", "123", "fake", "dummy",
            "changeme", "password", "secret", "key", "token",
        ]
        
        for fp in common_fps:
            if value_lower == fp or value_lower.startswith(fp + "_"):
                return True
        
        # Check if it's all the same character
        if len(set(value)) <= 2:
            return True
        
        # Check entropy - very low entropy might be a false positive
        if self.calculate_entropy(value) < 2.0:
            return True
        
        return False
    
    def should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        file_name = file_path.name.lower()
        file_str = str(file_path).lower()
        
        # Skip binary and minified files
        for skip in SKIP_FILES:
            if file_name.endswith(skip):
                return True
        
        # Skip certain directories
        for skip_dir in SKIP_DIRS:
            if f"/{skip_dir}/" in file_str or f"\\{skip_dir}\\" in file_str:
                return True
        
        return False
    
    def scan(self, target_path: str) -> List[Finding]:
        """Scan target path for secrets"""
        findings = []
        
        for file_path in self.get_files(target_path):
            if self.should_skip_file(file_path):
                continue
            
            file_findings = self.scan_file(file_path)
            findings.extend(file_findings)
        
        return findings
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for secrets"""
        findings = []
        content = self.read_file_content(file_path)
        
        if not content:
            return findings
        
        lines = content.split('\n')
        
        for pattern in self.patterns:
            for match in pattern.pattern.finditer(content):
                matched_text = match.group(0)
                
                # Extract the actual secret value if there's a capture group
                secret_value = match.group(1) if match.lastindex else matched_text
                
                # Check for false positives
                if self.is_false_positive(secret_value, pattern):
                    continue
                
                # Calculate line number
                line_number = content[:match.start()].count('\n') + 1
                
                # Get code snippet
                snippet = self.get_line_content(file_path, line_number, context_lines=1)
                
                # Mask the secret in the snippet for security
                masked_secret = self.mask_secret(secret_value)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"{pattern.name} Detected",
                    description=pattern.description,
                    severity=pattern.severity,
                    finding_type=FindingType.SECRET,
                    location=Location(
                        file_path=str(file_path),
                        start_line=line_number,
                        end_line=line_number,
                        snippet=snippet
                    ),
                    rule_id=pattern.pattern_id,
                    cwe_id="CWE-798",
                    remediation=Remediation(
                        description="Remove the hardcoded secret and use environment variables or a secrets manager instead.",
                        fix_example="secret = os.environ.get('SECRET_KEY')",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
                        ]
                    ),
                    metadata={
                        "secret_type": pattern.name,
                        "masked_value": masked_secret,
                        "entropy": self.calculate_entropy(secret_value),
                        "pattern_id": pattern.pattern_id,
                    }
                )
                findings.append(finding)
        
        # Also check for high-entropy strings that might be secrets
        findings.extend(self.scan_high_entropy(file_path, content))
        
        return findings
    
    def scan_high_entropy(self, file_path: Path, content: str) -> List[Finding]:
        """Scan for high-entropy strings that might be secrets"""
        findings = []
        
        # Pattern to find potential secrets (quoted strings, assignments)
        potential_secrets = re.finditer(
            r'(?:=|:)\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
            content
        )
        
        for match in potential_secrets:
            value = match.group(1)
            entropy = self.calculate_entropy(value)
            
            # High entropy threshold for potential secrets
            if entropy >= self.entropy_threshold:
                # Skip if it looks like a hash or encoded data that's not a secret
                if self.is_likely_hash_or_encoded(value):
                    continue
                
                line_number = content[:match.start()].count('\n') + 1
                snippet = self.get_line_content(file_path, line_number, context_lines=1)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title="High-Entropy String Detected",
                    description=f"A high-entropy string (entropy: {entropy:.2f}) was detected, which may be a hardcoded secret.",
                    severity="medium",
                    finding_type=FindingType.SECRET,
                    location=Location(
                        file_path=str(file_path),
                        start_line=line_number,
                        end_line=line_number,
                        snippet=snippet
                    ),
                    rule_id="SEC-ENTROPY",
                    cwe_id="CWE-798",
                    remediation=Remediation(
                        description="Review this high-entropy string. If it's a secret, move it to environment variables or a secrets manager.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]
                    ),
                    metadata={
                        "secret_type": "high_entropy",
                        "masked_value": self.mask_secret(value),
                        "entropy": entropy,
                    }
                )
                findings.append(finding)
        
        return findings
    
    def is_likely_hash_or_encoded(self, value: str) -> bool:
        """Check if value is likely a hash or encoded data (not a secret)"""
        # Common hash lengths
        hash_lengths = [32, 40, 64, 128]  # MD5, SHA1, SHA256, SHA512
        
        if len(value) in hash_lengths and all(c in '0123456789abcdefABCDEF' for c in value):
            return True
        
        # Base64 encoded data that's likely not a secret
        if value.endswith('==') and len(value) > 100:
            return True
        
        return False
    
    def mask_secret(self, secret: str) -> str:
        """Mask a secret for safe display"""
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
