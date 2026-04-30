
# 🛡️ SecureScan
Developed with Claude 4.5
**Application Security Scanner for SAST, SCA, and Secrets Detection**

SecureScan is a comprehensive security scanning tool designed for CI/CD integration with GitHub Actions and Azure DevOps. It provides static application security testing (SAST), software composition analysis (SCA), and secrets detection capabilities with beautiful reports for both engineers and leadership.

[![Security Scan](https://img.shields.io/badge/Security-Scan-green.svg)](https://github.com/your-org/securescan)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 🔍 SAST (Static Application Security Testing)
- **20+ Security Rules** covering OWASP Top 10 vulnerabilities
- SQL Injection, XSS, Command Injection, Path Traversal
- Insecure Deserialization, Weak Cryptography
- Multi-language support: Python, JavaScript, TypeScript, Java, C#, Go

### 📦 SCA (Software Composition Analysis)
- Vulnerability scanning for dependencies
- Support for npm, PyPI, Maven, NuGet ecosystems
- Known CVE detection with CVSS scores
- License compliance checking

### 🔑 Secrets Detection
- 30+ secret patterns (AWS, Azure, GCP, GitHub, Slack, etc.)
- High-entropy string detection
- Private key detection (RSA, SSH, PGP)
- API keys, tokens, and credentials

### 📊 Reporting
- **Engineer Report**: Detailed HTML with code snippets, remediation guidance
- **Executive Summary**: High-level risk overview for leadership
- **SARIF Output**: GitHub Code Scanning & Azure DevOps integration
- **JSON Export**: Machine-readable for automation

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/securescan.git
cd securescan

# Install the package (CLI only)
pip install -e .

# Install with Web UI
pip install -e ".[web]"
```

### Command Line Usage

```bash
# Scan current directory
securescan .

# Scan specific path
securescan /path/to/project

# Generate specific report formats
securescan . --format json,sarif

# Scan with specific options
securescan . --no-sast --fail-on-high
```

### Web UI

SecureScan includes a beautiful web interface for executing scans and reviewing findings:

```bash
# Start the web server
securescan-web --port 5000

# Or with debug mode
securescan-web --debug
```

Then open http://localhost:5000 in your browser.

**Web UI Features:**
- 📊 Interactive dashboard with scan history
- 🔍 Execute scans with real-time progress
- 📋 Filter and search findings
- 📈 CVE severity rankings (CVSS v3.0)
- 📥 Export reports to JSON

### Python API

```python
from securescan import SecureScan, ScanConfig

# Create configuration
config = ScanConfig(
    target_path="./my-project",
    output_dir="./reports",
    sast_enabled=True,
    sca_enabled=True,
    secrets_enabled=True,
)

# Run scan
scanner = SecureScan(config)
result, reports = scanner.run()

# Check results
print(f"Total findings: {result.summary.total_findings}")
print(f"Critical: {result.summary.critical_count}")
```

## 🔧 Configuration

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--output, -o` | Output directory for reports | `./reports` |
| `--format, -f` | Report formats (json,html,sarif) | `json,html,sarif` |
| `--no-sast` | Disable SAST scanning | `false` |
| `--no-sca` | Disable SCA scanning | `false` |
| `--no-secrets` | Disable secrets scanning | `false` |
| `--fail-on-critical` | Fail build on critical issues | `true` |
| `--fail-on-high` | Fail build on high severity | `false` |
| `--no-fail` | Never fail the build | `false` |
| `--severity` | Minimum severity to report | `low` |

### Environment Variables

```bash
export SECURESCAN_TARGET="."
export SECURESCAN_OUTPUT_DIR="./reports"
export SECURESCAN_SAST_ENABLED="true"
export SECURESCAN_SCA_ENABLED="true"
export SECURESCAN_SECRETS_ENABLED="true"
export SECURESCAN_FAIL_ON_CRITICAL="true"
```

## 🔄 CI/CD Integration

### GitHub Actions

Add to your repository's `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install SecureScan
        run: pip install securescan
      
      - name: Run Security Scan
        run: securescan . --output ./reports --format sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports/*.sarif
```

### Azure DevOps

Add to your `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: pip install securescan
    displayName: 'Install SecureScan'

  - script: |
      securescan $(Build.SourcesDirectory) \
        --output $(Build.ArtifactStagingDirectory)/reports \
        --format json,html,sarif
    displayName: 'Run Security Scan'

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: '$(Build.ArtifactStagingDirectory)/reports'
      artifactName: 'SecurityReports'
```

## 📋 Report Examples

### Engineer Report (HTML)
![Engineer Report](docs/images/engineer-report.png)

The engineer report includes:
- Severity-based filtering
- Code snippets with line numbers
- Remediation guidance with fix examples
- Interactive charts and search

### Executive Summary
![Executive Summary](docs/images/executive-report.png)

The executive summary provides:
- Overall risk score (0-100)
- Prioritized recommendations
- Top issues overview
- Scan coverage metrics

## 🔒 Security Rules

### SAST Rules

| Rule ID | Title | Severity | CWE |
|---------|-------|----------|-----|
| SAST001 | SQL Injection | Critical | CWE-89 |
| SAST003 | Command Injection | Critical | CWE-78 |
| SAST004 | Cross-Site Scripting (XSS) | High | CWE-79 |
| SAST005 | Path Traversal | High | CWE-22 |
| SAST007 | Insecure Deserialization | Critical | CWE-502 |
| SAST008 | Weak Cryptography | Medium | CWE-327 |
| SAST016 | Dangerous eval() | High | CWE-95 |

### Secrets Patterns

| Pattern ID | Type | Severity |
|------------|------|----------|
| SEC001 | AWS Access Key ID | Critical |
| SEC007 | GitHub Personal Access Token | Critical |
| SEC012 | Database Connection String | Critical |
| SEC014 | RSA Private Key | Critical |
| SEC021 | Stripe API Key | Critical |
| SEC025 | Hardcoded Password | High |

## 🏗️ Architecture

```
securescan/
├── __init__.py          # Package initialization
├── cli.py               # Command-line interface
├── core.py              # Main orchestrator
├── config.py            # Configuration management
├── models.py            # Data models
├── scanners/
│   ├── base.py          # Base scanner class
│   ├── sast_scanner.py  # SAST implementation
│   ├── sca_scanner.py   # SCA implementation
│   └── secrets_scanner.py # Secrets detection
└── reporters/
    ├── base.py          # Base reporter class
    ├── json_reporter.py # JSON output
    ├── html_reporter.py # HTML report
    ├── sarif_reporter.py # SARIF format
    └── executive_reporter.py # Executive summary
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security guidelines and vulnerability classifications
- CWE for weakness enumeration
- The security community for pattern contributions

---

**Made with ❤️ by the SecureScan Team**
