"""
Command-line interface for SecureScan

Standalone CLI for security scanning without web UI dependencies.
Supports JSON and SARIF output formats for CI/CD integration.
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

from .config import ScanConfig
from .core import SecureScan


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        prog="securescan",
        description="SecureScan - Application Security Scanner (SAST, SCA, Secrets)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  securescan .                          # Scan current directory
  securescan /path/to/project           # Scan specific path
  securescan . --format json,sarif      # Generate specific report formats
  securescan . --json                   # Output JSON to stdout
  securescan . --sarif                  # Output SARIF to stdout
  securescan . --no-sast                # Skip SAST scanning
  securescan . --fail-on-high           # Fail build on high severity issues

Output Modes:
  By default, reports are written to files in the output directory.
  Use --json or --sarif to output directly to stdout (useful for piping).
  Use --output-file to write to a specific file.
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target path to scan (default: current directory)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    
    parser.add_argument(
        "-f", "--format",
        default="json,sarif",
        help="Report formats: json,html,sarif (default: json,sarif)"
    )
    
    # Direct output options
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON results to stdout (no files written)"
    )
    
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Output SARIF results to stdout (no files written)"
    )
    
    parser.add_argument(
        "--output-file",
        help="Write output to specific file instead of stdout"
    )
    
    # Scanner toggles
    parser.add_argument(
        "--no-sast",
        action="store_true",
        help="Disable SAST scanning"
    )
    
    parser.add_argument(
        "--no-sca",
        action="store_true",
        help="Disable SCA scanning"
    )
    
    parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Disable secrets scanning"
    )
    
    # Severity thresholds
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        default=True,
        help="Fail if critical issues found (default: true)"
    )
    
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Fail if high severity issues found"
    )
    
    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Never fail the build regardless of findings"
    )
    
    # Report options
    parser.add_argument(
        "--no-executive",
        action="store_true",
        help="Skip executive summary report"
    )
    
    parser.add_argument(
        "--severity",
        default="low",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report (default: low)"
    )
    
    # Output options
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output except for errors"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="SecureScan 1.0.0"
    )
    
    return parser.parse_args()


def generate_sarif_output(result) -> dict:
    """Generate SARIF format output from scan result"""
    
    def severity_to_level(severity: str) -> str:
        mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        return mapping.get(severity.lower(), "note")
    
    def severity_to_score(severity: str) -> str:
        mapping = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
        return mapping.get(severity.lower(), "0.0")
    
    # Build rules
    rules_map = {}
    for finding in result.findings:
        if finding.rule_id not in rules_map:
            rule = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {"level": severity_to_level(finding.severity)},
                "properties": {
                    "security-severity": str(finding.cvss_score) if finding.cvss_score else severity_to_score(finding.severity),
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
            rules_map[finding.rule_id] = rule
    
    # Build results
    results = []
    for finding in result.findings:
        sarif_result = {
            "ruleId": finding.rule_id,
            "level": severity_to_level(finding.severity),
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file_path.replace("\\", "/")},
                    "region": {
                        "startLine": finding.location.start_line,
                        "endLine": finding.location.end_line
                    }
                }
            }],
            "fingerprints": {"primaryLocationLineHash": finding.id},
            "properties": {
                "security-severity": str(finding.cvss_score) if finding.cvss_score else severity_to_score(finding.severity)
            }
        }
        if finding.location.snippet:
            sarif_result["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": finding.location.snippet}
        results.append(sarif_result)
    
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecureScan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/securescan",
                    "rules": list(rules_map.values())
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }


def main():
    """Main entry point for CLI"""
    args = parse_args()
    
    # Check for direct output mode (stdout)
    direct_output = args.json or args.sarif
    
    # Build configuration from arguments
    config = ScanConfig(
        target_path=args.target,
        output_dir=args.output if not direct_output else "/tmp/securescan-temp",
        output_formats=[] if direct_output else [f.strip() for f in args.format.split(",")],
        sast_enabled=not args.no_sast,
        sca_enabled=not args.no_sca,
        secrets_enabled=not args.no_secrets,
        sast_severity_threshold=args.severity,
        generate_executive_summary=False if direct_output else not args.no_executive,
        fail_on_critical=args.fail_on_critical and not args.no_fail,
        fail_on_high=args.fail_on_high and not args.no_fail,
    )
    
    # Validate target path
    target_path = Path(args.target).resolve()
    if not target_path.exists():
        print(f"Error: Target path does not exist: {args.target}", file=sys.stderr)
        sys.exit(1)
    
    # Run scan
    try:
        scanner = SecureScan(config)
        
        # Direct output mode - just scan, no file reports
        if direct_output:
            if not args.quiet:
                print("Running security scan...", file=sys.stderr)
            
            result = scanner.scan(str(target_path))
            
            # Generate output
            if args.json:
                output_data = result.to_dict()
                output_data["report_metadata"] = {
                    "tool": "SecureScan",
                    "version": "1.0.0",
                    "generated_at": datetime.utcnow().isoformat(),
                    "format": "json"
                }
            else:  # SARIF
                output_data = generate_sarif_output(result)
            
            output_str = json.dumps(output_data, indent=2, default=str)
            
            # Write to file or stdout
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    f.write(output_str)
                if not args.quiet:
                    print(f"Output written to: {args.output_file}", file=sys.stderr)
            else:
                print(output_str)
            
            # Print summary to stderr if not quiet
            if not args.quiet:
                print(f"\n--- Scan Summary ---", file=sys.stderr)
                print(f"Total findings: {result.summary.total_findings}", file=sys.stderr)
                print(f"  Critical: {result.summary.critical_count}", file=sys.stderr)
                print(f"  High: {result.summary.high_count}", file=sys.stderr)
                print(f"  Medium: {result.summary.medium_count}", file=sys.stderr)
                print(f"  Low: {result.summary.low_count}", file=sys.stderr)
        
        else:
            # Standard mode - generate file reports
            result, report_paths = scanner.run(str(target_path))
            
            if not args.quiet:
                print("\nReports generated:")
                for path in report_paths:
                    print(f"  - {path}")
        
        # Determine exit code
        exit_code = scanner.get_exit_code(result)
        
        if exit_code != 0 and not args.quiet:
            print("\n⚠️  Build failed due to security findings!", file=sys.stderr)
            if result.summary.critical_count > 0:
                print(f"   Found {result.summary.critical_count} critical issues", file=sys.stderr)
            if args.fail_on_high and result.summary.high_count > 0:
                print(f"   Found {result.summary.high_count} high severity issues", file=sys.stderr)
        
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
