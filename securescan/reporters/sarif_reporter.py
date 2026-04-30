"""
SARIF Report Generator
Static Analysis Results Interchange Format - compatible with GitHub Code Scanning
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime

from .base import BaseReporter
from ..models import ScanResult, Finding, FindingType


class SARIFReporter(BaseReporter):
    """Generates SARIF format reports for GitHub/Azure DevOps integration"""
    
    def get_format_name(self) -> str:
        return "SARIF"
    
    def severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return mapping.get(severity.lower(), "note")
    
    def severity_to_security_severity(self, severity: str) -> str:
        """Convert severity to security-severity for GitHub"""
        mapping = {
            "critical": "9.0",
            "high": "7.0",
            "medium": "4.0",
            "low": "1.0",
            "info": "0.0"
        }
        return mapping.get(severity.lower(), "0.0")
    
    def generate(self, result: ScanResult, filename: Optional[str] = None) -> str:
        """Generate SARIF report"""
        if filename is None:
            filename = f"securescan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        output_path = self.get_output_path(filename, "sarif")
        
        # Build rules from findings
        rules = self.build_rules(result.findings)
        
        # Build results
        results = self.build_results(result.findings)
        
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecureScan",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-org/securescan",
                            "rules": rules
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                        }
                    ]
                }
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)
        
        return str(output_path)
    
    def build_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build SARIF rules from findings"""
        rules_map = {}
        
        for finding in findings:
            if finding.rule_id not in rules_map:
                rule = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": self.severity_to_sarif_level(finding.severity)
                    },
                    "properties": {
                        "security-severity": self.severity_to_security_severity(finding.severity),
                        "tags": [finding.finding_type.value, "security"]
                    }
                }
                
                if finding.cwe_id:
                    rule["properties"]["tags"].append(finding.cwe_id)
                
                if finding.remediation:
                    rule["help"] = {
                        "text": finding.remediation.description,
                        "markdown": f"## Remediation\n\n{finding.remediation.description}"
                    }
                    if finding.remediation.fix_example:
                        rule["help"]["markdown"] += f"\n\n### Example Fix\n\n```\n{finding.remediation.fix_example}\n```"
                
                rules_map[finding.rule_id] = rule
        
        return list(rules_map.values())
    
    def build_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build SARIF results from findings"""
        results = []
        
        for finding in findings:
            result = {
                "ruleId": finding.rule_id,
                "level": self.severity_to_sarif_level(finding.severity),
                "message": {
                    "text": finding.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.location.file_path.replace("\\", "/")
                            },
                            "region": {
                                "startLine": finding.location.start_line,
                                "endLine": finding.location.end_line
                            }
                        }
                    }
                ],
                "fingerprints": {
                    "primaryLocationLineHash": finding.id
                },
                "properties": {
                    "security-severity": self.severity_to_security_severity(finding.severity)
                }
            }
            
            if finding.location.snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": finding.location.snippet
                }
            
            if finding.cwe_id:
                result["taxa"] = [
                    {
                        "id": finding.cwe_id,
                        "toolComponent": {
                            "name": "CWE"
                        }
                    }
                ]
            
            results.append(result)
        
        return results
