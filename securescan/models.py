"""
Data models for SecureScan findings and reports
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class FindingType(Enum):
    SAST = "sast"
    SCA = "sca"
    SECRET = "secret"


class FindingStatus(Enum):
    OPEN = "open"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Location:
    """Location of a finding in source code"""
    file_path: str
    start_line: int
    end_line: int
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None


@dataclass
class Remediation:
    """Remediation guidance for a finding"""
    description: str
    fix_example: Optional[str] = None
    references: List[str] = field(default_factory=list)
    effort: str = "medium"  # low, medium, high


@dataclass
class Finding:
    """Base class for all security findings"""
    id: str
    title: str
    description: str
    severity: str
    finding_type: FindingType
    location: Location
    rule_id: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[Remediation] = None
    status: FindingStatus = FindingStatus.OPEN
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "finding_type": self.finding_type.value,
            "location": {
                "file_path": self.location.file_path,
                "start_line": self.location.start_line,
                "end_line": self.location.end_line,
                "start_column": self.location.start_column,
                "end_column": self.location.end_column,
                "snippet": self.location.snippet,
            },
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "remediation": {
                "description": self.remediation.description,
                "fix_example": self.remediation.fix_example,
                "references": self.remediation.references,
                "effort": self.remediation.effort,
            } if self.remediation else None,
            "status": self.status.value,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class Dependency:
    """Represents a software dependency"""
    name: str
    version: str
    ecosystem: str  # npm, pypi, maven, nuget, etc.
    file_path: str
    license: Optional[str] = None
    is_direct: bool = True


@dataclass
class Vulnerability:
    """Vulnerability information for SCA findings"""
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    severity: str = "unknown"
    cvss_score: Optional[float] = None
    description: str = ""
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class SCAFinding(Finding):
    """SCA-specific finding with dependency information"""
    dependency: Optional[Dependency] = None
    vulnerability: Optional[Vulnerability] = None


@dataclass
class SecretFinding(Finding):
    """Secret-specific finding"""
    secret_type: str = "generic"
    entropy: Optional[float] = None
    verified: bool = False


@dataclass
class ScanSummary:
    """Summary statistics for a scan"""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    sast_findings: int = 0
    sca_findings: int = 0
    secret_findings: int = 0
    files_scanned: int = 0
    dependencies_scanned: int = 0
    scan_duration_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "by_type": {
                "sast": self.sast_findings,
                "sca": self.sca_findings,
                "secrets": self.secret_findings,
            },
            "files_scanned": self.files_scanned,
            "dependencies_scanned": self.dependencies_scanned,
            "scan_duration_seconds": self.scan_duration_seconds,
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target_path: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[Finding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.summary.total_findings += 1
        
        # Update severity counts
        if finding.severity == "critical":
            self.summary.critical_count += 1
        elif finding.severity == "high":
            self.summary.high_count += 1
        elif finding.severity == "medium":
            self.summary.medium_count += 1
        elif finding.severity == "low":
            self.summary.low_count += 1
        else:
            self.summary.info_count += 1
        
        # Update type counts
        if finding.finding_type == FindingType.SAST:
            self.summary.sast_findings += 1
        elif finding.finding_type == FindingType.SCA:
            self.summary.sca_findings += 1
        elif finding.finding_type == FindingType.SECRET:
            self.summary.secret_findings += 1
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_path": self.target_path,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "metadata": self.metadata,
        }
