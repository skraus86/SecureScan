"""
Configuration settings for SecureScan
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuration for scanning operations"""
    target_path: str = "."
    output_dir: str = "./reports"
    output_formats: List[str] = field(default_factory=lambda: ["json", "html", "sarif"])
    
    # SAST settings
    sast_enabled: bool = True
    sast_languages: List[str] = field(default_factory=lambda: ["python", "javascript", "java", "csharp", "go"])
    sast_severity_threshold: str = "low"  # low, medium, high, critical
    
    # SCA settings
    sca_enabled: bool = True
    sca_check_licenses: bool = True
    sca_fail_on_vulnerable: bool = True
    
    # Secrets settings
    secrets_enabled: bool = True
    secrets_entropy_threshold: float = 4.5
    secrets_scan_history: bool = False  # Scan git history
    
    # Reporting
    generate_executive_summary: bool = True
    include_remediation: bool = True
    
    # CI/CD settings
    fail_on_critical: bool = True
    fail_on_high: bool = False
    max_issues_threshold: int = 0  # 0 = no limit
    
    @classmethod
    def from_env(cls) -> "ScanConfig":
        """Load configuration from environment variables"""
        return cls(
            target_path=os.getenv("SECURESCAN_TARGET", "."),
            output_dir=os.getenv("SECURESCAN_OUTPUT_DIR", "./reports"),
            sast_enabled=os.getenv("SECURESCAN_SAST_ENABLED", "true").lower() == "true",
            sca_enabled=os.getenv("SECURESCAN_SCA_ENABLED", "true").lower() == "true",
            secrets_enabled=os.getenv("SECURESCAN_SECRETS_ENABLED", "true").lower() == "true",
            fail_on_critical=os.getenv("SECURESCAN_FAIL_ON_CRITICAL", "true").lower() == "true",
            fail_on_high=os.getenv("SECURESCAN_FAIL_ON_HIGH", "false").lower() == "true",
        )


# Severity levels
class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    LEVELS = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
    
    @staticmethod
    def get_score(severity: str) -> int:
        scores = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2,
            "info": 0
        }
        return scores.get(severity.lower(), 0)


# File extensions by language
LANGUAGE_EXTENSIONS = {
    "python": [".py", ".pyw"],
    "javascript": [".js", ".jsx", ".mjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "csharp": [".cs"],
    "go": [".go"],
    "ruby": [".rb"],
    "php": [".php"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".h"],
    "c": [".c", ".h"],
}

# Dependency files
DEPENDENCY_FILES = {
    "python": ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "setup.py"],
    "javascript": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "csharp": ["*.csproj", "packages.config", "*.nuspec"],
    "go": ["go.mod", "go.sum"],
    "ruby": ["Gemfile", "Gemfile.lock"],
    "php": ["composer.json", "composer.lock"],
}

# Directories to exclude from scanning
EXCLUDED_DIRS = [
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
    "dist",
    "build",
    "target",
    "bin",
    "obj",
    ".idea",
    ".vscode",
    "vendor",
]
