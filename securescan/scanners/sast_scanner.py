"""
SAST (Static Application Security Testing) Scanner
Detects code-level security vulnerabilities
"""

import re
import uuid
from typing import List, Dict, Any
from pathlib import Path

from .base import BaseScanner
from ..models import Finding, FindingType, Location, Remediation
from ..config import ScanConfig, LANGUAGE_EXTENSIONS


class SASTRule:
    """Represents a SAST detection rule"""
    def __init__(self, rule_id: str, title: str, description: str, pattern: str,
                 severity: str, cwe_id: str, languages: List[str],
                 remediation: str, fix_example: str = None, references: List[str] = None):
        self.rule_id = rule_id
        self.title = title
        self.description = description
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.severity = severity
        self.cwe_id = cwe_id
        self.languages = languages
        self.remediation = remediation
        self.fix_example = fix_example
        self.references = references or []


# SAST Rules Database
SAST_RULES = [
    # SQL Injection
    SASTRule(
        rule_id="SAST001",
        title="Potential SQL Injection",
        description="User input is directly concatenated into SQL query, which may lead to SQL injection attacks.",
        pattern=r'(execute|cursor\.execute|query|raw_query|rawQuery)\s*\(\s*["\'].*(%s|%d|\+\s*\w+|\{\}|f["\']|\.format).*["\']',
        severity="critical",
        cwe_id="CWE-89",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Use parameterized queries or prepared statements instead of string concatenation.",
        fix_example="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"]
    ),
    SASTRule(
        rule_id="SAST002",
        title="SQL Injection via String Concatenation",
        description="SQL query built using string concatenation with variables.",
        pattern=r'(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*[\+\.].*(\+|\.concat|\.format|\$\{)',
        severity="critical",
        cwe_id="CWE-89",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Use parameterized queries or an ORM to prevent SQL injection.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]
    ),
    
    # Command Injection
    SASTRule(
        rule_id="SAST003",
        title="Potential Command Injection",
        description="User input may be passed to system command execution functions.",
        pattern=r'(os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen|exec|eval|child_process\.exec|Runtime\.getRuntime\(\)\.exec)\s*\([^)]*\+',
        severity="critical",
        cwe_id="CWE-78",
        languages=["python", "javascript", "java"],
        remediation="Avoid using shell commands with user input. Use subprocess with shell=False and pass arguments as a list.",
        fix_example="subprocess.run(['ls', '-la', directory], shell=False)",
        references=["https://owasp.org/www-community/attacks/Command_Injection"]
    ),
    
    # XSS
    SASTRule(
        rule_id="SAST004",
        title="Potential Cross-Site Scripting (XSS)",
        description="User input may be rendered without proper sanitization, leading to XSS.",
        pattern=r'(innerHTML|outerHTML|document\.write|\.html\(|dangerouslySetInnerHTML|v-html)',
        severity="high",
        cwe_id="CWE-79",
        languages=["javascript", "typescript"],
        remediation="Use textContent instead of innerHTML, or properly sanitize HTML using a library like DOMPurify.",
        fix_example="element.textContent = userInput;",
        references=["https://owasp.org/www-community/attacks/xss/"]
    ),
    
    # Path Traversal
    SASTRule(
        rule_id="SAST005",
        title="Potential Path Traversal",
        description="File path is constructed using user input without proper validation.",
        pattern=r'(open|read|write|readFile|writeFile|createReadStream|createWriteStream|Path\.Combine)\s*\([^)]*(\+|\.join|\.resolve|\$\{)',
        severity="high",
        cwe_id="CWE-22",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Validate and sanitize file paths. Use os.path.realpath() and verify the path is within expected directory.",
        references=["https://owasp.org/www-community/attacks/Path_Traversal"]
    ),
    
    # Hardcoded Credentials
    SASTRule(
        rule_id="SAST006",
        title="Hardcoded Password",
        description="Password appears to be hardcoded in source code.",
        pattern=r'(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["\'][^"\']{4,}["\']',
        severity="high",
        cwe_id="CWE-798",
        languages=["python", "javascript", "java", "csharp", "go"],
        remediation="Store credentials in environment variables or a secure secrets manager.",
        fix_example="password = os.environ.get('DB_PASSWORD')",
        references=["https://cwe.mitre.org/data/definitions/798.html"]
    ),
    
    # Insecure Deserialization
    SASTRule(
        rule_id="SAST007",
        title="Insecure Deserialization",
        description="Deserializing untrusted data can lead to remote code execution.",
        pattern=r'(pickle\.loads?|yaml\.load\s*\([^)]*\)|yaml\.unsafe_load|unserialize|ObjectInputStream|BinaryFormatter\.Deserialize)',
        severity="critical",
        cwe_id="CWE-502",
        languages=["python", "java", "csharp", "php"],
        remediation="Use safe deserialization methods. For YAML, use yaml.safe_load(). Avoid deserializing untrusted data.",
        fix_example="data = yaml.safe_load(yaml_string)",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests"]
    ),
    
    # Weak Cryptography
    SASTRule(
        rule_id="SAST008",
        title="Weak Cryptographic Algorithm",
        description="Use of weak or deprecated cryptographic algorithms (MD5, SHA1, DES).",
        pattern=r'(md5|sha1|DES|RC4|RC2|Blowfish)\s*\(|hashlib\.(md5|sha1)|MessageDigest\.getInstance\s*\(\s*["\']?(MD5|SHA-?1)["\']?\)',
        severity="medium",
        cwe_id="CWE-327",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Use strong cryptographic algorithms like SHA-256, SHA-3, or bcrypt for passwords.",
        fix_example="hashlib.sha256(data.encode()).hexdigest()",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"]
    ),
    
    # Insecure Random
    SASTRule(
        rule_id="SAST009",
        title="Insecure Random Number Generator",
        description="Using non-cryptographic random number generator for security-sensitive operations.",
        pattern=r'(random\.random|random\.randint|Math\.random|Random\(\)\.Next)',
        severity="medium",
        cwe_id="CWE-330",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Use cryptographically secure random number generators for security-sensitive operations.",
        fix_example="import secrets; token = secrets.token_hex(32)",
        references=["https://cwe.mitre.org/data/definitions/330.html"]
    ),
    
    # SSRF
    SASTRule(
        rule_id="SAST010",
        title="Potential Server-Side Request Forgery (SSRF)",
        description="URL is constructed using user input, which may lead to SSRF attacks.",
        pattern=r'(requests\.get|requests\.post|urllib\.request\.urlopen|fetch|axios\.(get|post)|HttpClient)\s*\([^)]*(\+|\$\{|\.format)',
        severity="high",
        cwe_id="CWE-918",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Validate and whitelist allowed URLs. Use URL parsing to verify the host.",
        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"]
    ),
    
    # XXE
    SASTRule(
        rule_id="SAST011",
        title="Potential XML External Entity (XXE) Injection",
        description="XML parser may be vulnerable to XXE attacks if external entities are not disabled.",
        pattern=r'(etree\.parse|xml\.dom\.minidom\.parse|DocumentBuilder|XMLReader|SAXParser|XmlDocument\.Load)',
        severity="high",
        cwe_id="CWE-611",
        languages=["python", "java", "csharp"],
        remediation="Disable external entity processing in XML parsers.",
        fix_example="parser = etree.XMLParser(resolve_entities=False)",
        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"]
    ),
    
    # Open Redirect
    SASTRule(
        rule_id="SAST012",
        title="Potential Open Redirect",
        description="Redirect URL is constructed using user input without validation.",
        pattern=r'(redirect|Response\.Redirect|res\.redirect|window\.location|location\.href)\s*[=(]\s*[^)]*(\+|req\.|request\.|params|query)',
        severity="medium",
        cwe_id="CWE-601",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Validate redirect URLs against a whitelist of allowed destinations.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]
    ),
    
    # LDAP Injection
    SASTRule(
        rule_id="SAST013",
        title="Potential LDAP Injection",
        description="LDAP query is constructed using user input without proper escaping.",
        pattern=r'(ldap\.search|ldap_search|DirectorySearcher|SearchRequest)\s*\([^)]*(\+|\.format|\$\{)',
        severity="high",
        cwe_id="CWE-90",
        languages=["python", "java", "csharp"],
        remediation="Use parameterized LDAP queries and escape special characters.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"]
    ),
    
    # Insecure Cookie
    SASTRule(
        rule_id="SAST014",
        title="Insecure Cookie Configuration",
        description="Cookie is set without secure flags (HttpOnly, Secure, SameSite).",
        pattern=r'(set_cookie|Set-Cookie|cookie\s*=|res\.cookie)\s*\([^)]*(?!.*(?:httponly|secure|samesite))',
        severity="medium",
        cwe_id="CWE-614",
        languages=["python", "javascript", "java"],
        remediation="Set HttpOnly, Secure, and SameSite flags on sensitive cookies.",
        fix_example="response.set_cookie('session', value, httponly=True, secure=True, samesite='Strict')",
        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"]
    ),
    
    # Debug Mode
    SASTRule(
        rule_id="SAST015",
        title="Debug Mode Enabled",
        description="Application appears to have debug mode enabled, which may expose sensitive information.",
        pattern=r'(DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug:\s*true|NODE_ENV.*development)',
        severity="low",
        cwe_id="CWE-489",
        languages=["python", "javascript"],
        remediation="Ensure debug mode is disabled in production environments.",
        references=["https://cwe.mitre.org/data/definitions/489.html"]
    ),
    
    # Eval Usage
    SASTRule(
        rule_id="SAST016",
        title="Dangerous Use of eval()",
        description="Use of eval() can lead to code injection if user input is passed.",
        pattern=r'\beval\s*\(',
        severity="high",
        cwe_id="CWE-95",
        languages=["python", "javascript"],
        remediation="Avoid using eval(). Use safer alternatives like ast.literal_eval() for Python or JSON.parse() for JavaScript.",
        references=["https://owasp.org/www-community/attacks/Code_Injection"]
    ),
    
    # Hardcoded IP
    SASTRule(
        rule_id="SAST017",
        title="Hardcoded IP Address",
        description="IP address is hardcoded in source code, which may cause issues in different environments.",
        pattern=r'["\'](\d{1,3}\.){3}\d{1,3}["\']',
        severity="low",
        cwe_id="CWE-547",
        languages=["python", "javascript", "java", "csharp", "go"],
        remediation="Use configuration files or environment variables for IP addresses.",
        references=["https://cwe.mitre.org/data/definitions/547.html"]
    ),
    
    # Missing Authentication
    SASTRule(
        rule_id="SAST018",
        title="Potential Missing Authentication",
        description="Endpoint or route may be missing authentication checks.",
        pattern=r'(@app\.route|@router\.(get|post|put|delete)|app\.(get|post|put|delete))\s*\([^)]*\)\s*\n\s*(def|async|function)',
        severity="medium",
        cwe_id="CWE-306",
        languages=["python", "javascript"],
        remediation="Ensure all sensitive endpoints have proper authentication and authorization checks.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/"]
    ),
    
    # JWT Without Verification
    SASTRule(
        rule_id="SAST019",
        title="JWT Without Signature Verification",
        description="JWT token may be decoded without verifying the signature.",
        pattern=r'(jwt\.decode|jsonwebtoken\.decode)\s*\([^)]*verify\s*[=:]\s*False',
        severity="high",
        cwe_id="CWE-347",
        languages=["python", "javascript"],
        remediation="Always verify JWT signatures using the appropriate secret or public key.",
        fix_example="jwt.decode(token, secret_key, algorithms=['HS256'])",
        references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"]
    ),
    
    # Sensitive Data Exposure
    SASTRule(
        rule_id="SAST020",
        title="Potential Sensitive Data Logging",
        description="Sensitive data may be logged, which could expose it in log files.",
        pattern=r'(log|logger|console\.log|print|System\.out\.print)\s*\([^)]*(?:password|secret|token|key|credential|ssn|credit)',
        severity="medium",
        cwe_id="CWE-532",
        languages=["python", "javascript", "java", "csharp"],
        remediation="Avoid logging sensitive data. Mask or redact sensitive information before logging.",
        references=["https://cwe.mitre.org/data/definitions/532.html"]
    ),
]


class SASTScanner(BaseScanner):
    """Static Application Security Testing Scanner"""
    
    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self.rules = SAST_RULES
    
    def get_scanner_name(self) -> str:
        return "SAST Scanner"
    
    def get_language_for_file(self, file_path: Path) -> str:
        """Determine the programming language based on file extension"""
        suffix = file_path.suffix.lower()
        for lang, extensions in LANGUAGE_EXTENSIONS.items():
            if suffix in extensions:
                return lang
        return "unknown"
    
    def scan(self, target_path: str) -> List[Finding]:
        """Scan target path for SAST vulnerabilities"""
        findings = []
        
        # Get all supported extensions
        all_extensions = []
        for lang in self.config.sast_languages:
            all_extensions.extend(LANGUAGE_EXTENSIONS.get(lang, []))
        
        for file_path in self.get_files(target_path, all_extensions):
            file_findings = self.scan_file(file_path)
            findings.extend(file_findings)
        
        return findings
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file for SAST vulnerabilities"""
        findings = []
        content = self.read_file_content(file_path)
        
        if not content:
            return findings
        
        language = self.get_language_for_file(file_path)
        lines = content.split('\n')
        
        for rule in self.rules:
            # Skip rules not applicable to this language
            if language not in rule.languages:
                continue
            
            # Find all matches
            for match in rule.pattern.finditer(content):
                # Calculate line number
                line_number = content[:match.start()].count('\n') + 1
                
                # Get code snippet
                snippet = self.get_line_content(file_path, line_number, context_lines=2)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    finding_type=FindingType.SAST,
                    location=Location(
                        file_path=str(file_path),
                        start_line=line_number,
                        end_line=line_number,
                        snippet=snippet
                    ),
                    rule_id=rule.rule_id,
                    cwe_id=rule.cwe_id,
                    remediation=Remediation(
                        description=rule.remediation,
                        fix_example=rule.fix_example,
                        references=rule.references
                    ),
                    metadata={
                        "language": language,
                        "matched_text": match.group(0)[:100]  # Truncate long matches
                    }
                )
                findings.append(finding)
        
        return findings
