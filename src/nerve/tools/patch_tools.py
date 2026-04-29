
# Create fixed patch_tools.py - the trickiest one due to f-string escaping in diffs
# Strategy: Use regular strings with .format() or concatenation for diff blocks
# instead of f-strings with {{ escaping

#!/usr/bin/env python3


import json
from typing import Type, Dict, Any, List

from crewai.tools import BaseTool
from pydantic import BaseModel, Field


# ============================================================================
# SCHEMAS
# ============================================================================

class PatchInput(BaseModel):
    finding: Dict[str, Any] = Field(description="Vulnerability finding with severity to generate patch for")


# ============================================================================
# PATCH GENERATOR
# ============================================================================

class PatchGeneratorTool(BaseTool):
    name: str = "patch_generator"
    description: str = """
    Generate production-ready patches and remediation guidance for 
    vulnerabilities. Produces unified diffs, secure code examples, 
    configuration hardening, WAF rules, and testing steps. Covers 
    XSS, SQLi, command injection, CVEs, and misconfigurations with 
    framework-specific fixes.
    """
    args_schema: Type[BaseModel] = PatchInput

    def _run(self, finding: Dict[str, Any]) -> str:
        vuln_type = finding.get("type", "").lower()
        subtype = finding.get("subtype", "").lower()
        parameter = finding.get("parameter", "input")
        severity = finding.get("severity_rating", "Medium")
        
        patches: List[Dict[str, Any]] = []
        
        if "xss" in vuln_type:
            patches.extend(self._xss_patches(parameter, subtype, finding))
        elif "sql" in vuln_type:
            patches.extend(self._sqli_patches(parameter, finding))
        elif any(x in vuln_type for x in ["rce", "command", "code"]):
            patches.extend(self._command_injection_patches(parameter))
        elif "ssrf" in vuln_type:
            patches.extend(self._ssrf_patches())
        elif "lfi" in vuln_type or "path" in vuln_type:
            patches.extend(self._lfi_patches(parameter))
        elif "cve" in vuln_type or "misconfig" in vuln_type:
            patches.extend(self._cve_patches(finding))
        
        # Add WAF rules for all web vulnerabilities
        if any(x in vuln_type for x in ["xss", "sql", "rce", "command", "lfi", "ssrf"]):
            patches.append(self._waf_rules(vuln_type))
        
        patches.append(self._defense_in_depth(vuln_type))
        
        return json.dumps({
            "tool": "patch_generator",
            "vuln_id": finding.get("id", "unknown"),
            "vuln_type": vuln_type,
            "patches": patches,
            "patch_count": len(patches),
            "priority": severity,
            "estimated_total_effort": self._sum_effort(patches),
            "implementation_order": self._implementation_order(patches, severity)
        }, indent=2)
    
    def _xss_patches(self, parameter: str, subtype: str, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate XSS-specific patches."""
        patches = []
        
        # Patch 1: Output Encoding
        diff1 = """```python\n"""
        diff1 += "# BEFORE (VULNERABLE)\n"
        diff1 += "from flask import Flask, request\n\n"
        diff1 += "app = Flask(__name__)\n\n"
        diff1 += "@app.route('/search')\n"
        diff1 += "def search():\n"
        diff1 += "    user_input = request.args.get('" + parameter + "')\n"
        diff1 += "    return f\"<div>Results for: {user_input}</div>\"\n\n"
        diff1 += "# AFTER (PATCHED)\n"
        diff1 += "from markupsafe import escape\n"
        diff1 += "from flask import Flask, request\n\n"
        diff1 += "app = Flask(__name__)\n\n"
        diff1 += "@app.route('/search')\n"
        diff1 += "def search():\n"
        diff1 += "    user_input = request.args.get('" + parameter + "')\n"
        diff1 += "    safe_html = escape(user_input)\n"
        diff1 += "    return f\"<div>Results for: {safe_html}</div>\"\n"
        diff1 += "```"
        
        patches.append({
            "patch_type": "code_fix",
            "language": "python",
            "framework": "Flask/Django/Jinja2",
            "title": "Context-Aware Output Encoding",
            "severity_impact": "HIGH",
            "diff": diff1,
            "explanation": "Use framework escaping. Never concatenate user input into HTML without encoding.",
            "effort": "15 minutes",
            "testing": [
                "Submit XSS payload: <script>alert(1)</script>",
                "Verify output is rendered as text, not executed"
            ],
            "references": ["OWASP XSS Prevention Cheat Sheet", "CWE-79"]
        })
        
        # Patch 2: CSP Header
        diff2 = """```python\n"""
        diff2 += "# Flask\n"
        diff2 += "@app.after_request\n"
        diff2 += "def set_csp(response):\n"
        diff2 += "    response.headers['Content-Security-Policy'] = (\n"
        diff2 += "        \"default-src 'self'; \"\n"
        diff2 += "        \"script-src 'self'; \"\n"
        diff2 += "        \"style-src 'self' 'unsafe-inline'; \"\n"
        diff2 += "        \"img-src 'self' data: https:; \"\n"
        diff2 += "        \"frame-ancestors 'none'; \"\n"
        diff2 += "        \"base-uri 'self'; \"\n"
        diff2 += "        \"form-action 'self';\"\n"
        diff2 += "    )\n"
        diff2 += "    return response\n"
        diff2 += "```"
        
        patches.append({
            "patch_type": "config_change",
            "title": "Content Security Policy Header",
            "severity_impact": "MEDIUM",
            "diff": diff2,
            "explanation": "CSP acts as second line of defense. Blocks script execution even if XSS exists.",
            "effort": "30 minutes",
            "testing": [
                "Check response headers: curl -I https://target.com",
                "Verify inline scripts blocked in dev tools"
            ],
            "references": ["OWASP CSP Cheat Sheet", "CWE-693"]
        })
        
        # Patch 3: DOM XSS Fix
        if "dom" in subtype:
            diff3 = """```javascript\n"""
            diff3 += "// BEFORE (VULNERABLE)\n"
            diff3 += "const userInput = new URLSearchParams(window.location.search).get('" + parameter + "');\n"
            diff3 += "element.innerHTML = userInput;\n\n"
            diff3 += "// AFTER (PATCHED)\n"
            diff3 += "const userInput = new URLSearchParams(window.location.search).get('" + parameter + "');\n"
            diff3 += "element.textContent = userInput;\n\n"
            diff3 += "// If HTML needed, sanitize first\n"
            diff3 += "import DOMPurify from 'dompurify';\n"
            diff3 += "const clean = DOMPurify.sanitize(userInput);\n"
            diff3 += "element.innerHTML = clean;\n\n"
            diff3 += "// React: use auto-escaping\n"
            diff3 += "// <div>{userInput}</div>  // Safe - auto-escaped\n"
            diff3 += "// Vue: use mustache syntax\n"
            diff3 += "// <div>{{ userInput }}</div>  // Safe - auto-escaped\n"
            diff3 += "```"
            
            patches.append({
                "patch_type": "code_fix",
                "language": "javascript",
                "framework": "Vanilla JS / React / Vue",
                "title": "DOM-Based XSS Fix",
                "severity_impact": "HIGH",
                "diff": diff3,
                "explanation": "Use textContent instead of innerHTML. Sanitize with DOMPurify if HTML needed.",
                "effort": "20 minutes",
                "testing": [
                    "Test DOM XSS payloads in URL hash",
                    "Verify DOMPurify removes dangerous tags"
                ],
                "references": ["OWASP DOM XSS Prevention", "CWE-79"]
            })
        
        # Patch 4: Stored XSS Fix
        if "stored" in subtype or "persistent" in subtype:
            diff4 = """```python\n"""
            diff4 += "# BEFORE (VULNERABLE)\n"
            diff4 += "# In template: {{ comment.text|safe }}  # NEVER use 'safe' on user input\n\n"
            diff4 += "# AFTER (PATCHED)\n"
            diff4 += "# In template: {{ comment.text }}  # Auto-escaped by Django\n\n"
            diff4 += "# If rich text needed:\n"
            diff4 += "import bleach\n\n"
            diff4 += "ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u']\n"
            diff4 += "ALLOWED_ATTRS = {}\n\n"
            diff4 += "def save_comment(request):\n"
            diff4 += "    raw_text = request.POST.get('" + parameter + "', '')\n"
            diff4 += "    clean_text = bleach.clean(raw_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)\n"
            diff4 += "    Comment.objects.create(text=clean_text)\n"
            diff4 += "```"
            
            patches.append({
                "patch_type": "code_fix",
                "language": "python",
                "framework": "Django",
                "title": "Stored XSS - Output Encoding",
                "severity_impact": "CRITICAL",
                "diff": diff4,
                "explanation": "Encode on output, not just input. Stored XSS affects all users.",
                "effort": "30 minutes",
                "testing": [
                    "Post XSS payload in comment",
                    "View from different account",
                    "Verify payload rendered as text"
                ],
                "references": ["OWASP Stored XSS Prevention", "CWE-79"]
            })
        
        # Patch 5: HttpOnly Cookies
        if finding.get("cookies_accessible") or finding.get("stealable_count", 0) > 0:
            diff5 = """```python\n"""
            diff5 += "# Flask\n"
            diff5 += "app.config.update(\n"
            diff5 += "    SESSION_COOKIE_HTTPONLY=True,\n"
            diff5 += "    SESSION_COOKIE_SECURE=True,\n"
            diff5 += "    SESSION_COOKIE_SAMESITE='Strict',\n"
            diff5 += "    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)\n"
            diff5 += ")\n\n"
            diff5 += "# Django\n"
            diff5 += "SESSION_COOKIE_HTTPONLY = True\n"
            diff5 += "SESSION_COOKIE_SECURE = True\n"
            diff5 += "SESSION_COOKIE_SAMESITE = 'Strict'\n\n"
            diff5 += "# Express.js\n"
            diff5 += "app.use(session({\n"
            diff5 += "    secret: 'your-secret',\n"
            diff5 += "    cookie: {\n"
            diff5 += "        httpOnly: true,\n"
            diff5 += "        secure: true,\n"
            diff5 += "        sameSite: 'strict'\n"
            diff5 += "    }\n"
            diff5 += "}))\n"
            diff5 += "```"
            
            patches.append({
                "patch_type": "config_change",
                "title": "Secure Cookie Flags",
                "severity_impact": "HIGH",
                "diff": diff5,
                "explanation": "HttpOnly prevents JS from reading session cookies, blocking session hijacking.",
                "effort": "15 minutes",
                "testing": [
                    "Check Set-Cookie headers",
                    "Verify document.cookie empty for HttpOnly"
                ],
                "references": ["OWASP Session Management", "CWE-1004"]
            })
        
        return patches
    
    def _sqli_patches(self, parameter: str, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate SQL injection patches."""
        patches = []
        
        # Patch 1: Parameterized Queries
        diff1 = """```python\n"""
        diff1 += "# BEFORE (VULNERABLE)\n"
        diff1 += "import sqlite3\n\n"
        diff1 += "def get_user(user_id):\n"
        diff1 += "    conn = sqlite3.connect('app.db')\n"
        diff1 += "    cursor = conn.cursor()\n"
        diff1 += "    query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n"
        diff1 += "    cursor.execute(query)\n"
        diff1 += "    return cursor.fetchone()\n\n"
        diff1 += "# AFTER (PATCHED)\n"
        diff1 += "def get_user(user_id):\n"
        diff1 += "    conn = sqlite3.connect('app.db')\n"
        diff1 += "    cursor = conn.cursor()\n"
        diff1 += "    cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
        diff1 += "    return cursor.fetchone()\n\n"
        diff1 += "# SQLAlchemy ORM\n"
        diff1 += "from sqlalchemy import text\n"
        diff1 += "result = db.execute(\n"
        diff1 += "    text(\"SELECT * FROM users WHERE name = :name\"),\n"
        diff1 += "    {\"name\": name}\n"
        diff1 += ")\n\n"
        diff1 += "# Django ORM (already safe)\n"
        diff1 += "User.objects.filter(username=name)  # Auto-parameterized\n"
        diff1 += "```"
        
        patches.append({
            "patch_type": "code_fix",
            "language": "python",
            "framework": "SQLAlchemy / psycopg2 / sqlite3",
            "title": "Parameterized Queries",
            "severity_impact": "CRITICAL",
            "diff": diff1,
            "explanation": "Parameterized queries separate code from data. DB treats params as data only.",
            "effort": "30 minutes",
            "testing": [
                "Submit SQL injection: ' OR '1'='1",
                "Verify no unauthorized data access"
            ],
            "references": ["OWASP SQL Injection Prevention", "CWE-89"]
        })
        
        # Patch 2: Prepared Statements (PHP)
        diff2 = """```php\n"""
        diff2 += "// BEFORE (VULNERABLE)\n"
        diff2 += "<?php\n"
        diff2 += "$user_id = $_GET['" + parameter + "'];\n"
        diff2 += "$query = \"SELECT * FROM users WHERE id = '$user_id'\";\n"
        diff2 += "$result = mysqli_query($conn, $query);\n\n"
        diff2 += "// AFTER (PATCHED) - PDO\n"
        diff2 += "<?php\n"
        diff2 += "$user_id = $_GET['" + parameter + "'];\n"
        diff2 += "$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = :id\");\n"
        diff2 += "$stmt->execute(['id' => $user_id]);\n"
        diff2 += "$result = $stmt->fetchAll();\n\n"
        diff2 += "// AFTER (PATCHED) - MySQLi\n"
        diff2 += "<?php\n"
        diff2 += "$user_id = $_GET['" + parameter + "'];\n"
        diff2 += "$stmt = $conn->prepare(\"SELECT * FROM users WHERE id = ?\");\n"
        diff2 += "$stmt->bind_param(\"i\", $user_id);\n"
        diff2 += "$stmt->execute();\n"
        diff2 += "$result = $stmt->get_result();\n"
        diff2 += "```"
        
        patches.append({
            "patch_type": "code_fix",
            "language": "php",
            "framework": "PDO / MySQLi",
            "title": "Prepared Statements in PHP",
            "severity_impact": "CRITICAL",
            "diff": diff2,
            "explanation": "Prepared statements compile SQL structure before data binding.",
            "effort": "45 minutes",
            "testing": [
                "Use sqlmap against patched endpoint",
                "Verify error injection no longer works"
            ],
            "references": ["OWASP SQL Injection Prevention", "CWE-89"]
        })
        
        # Patch 3: Input Validation
        diff3 = """```python\n"""
        diff3 += "import re\n"
        diff3 += "from pydantic import BaseModel, validator\n\n"
        diff3 += "def validate_id(user_id):\n"
        diff3 += "    if not re.match(r'^[0-9]+$', user_id):\n"
        diff3 += "        raise ValueError(\"ID must be numeric\")\n"
        diff3 += "    return int(user_id)\n\n"
        diff3 += "class UserQuery(BaseModel):\n"
        diff3 += "    user_id: int\n"
        diff3 += "    sort_by: str = \"name\"\n"
        diff3 += "    \n"
        diff3 += "    @validator('sort_by')\n"
        diff3 += "    def validate_sort(cls, v):\n"
        diff3 += "        allowed = ['name', 'date', 'email']\n"
        diff3 += "        if v not in allowed:\n"
        diff3 += "            raise ValueError('Invalid sort column')\n"
        diff3 += "        return v\n"
        diff3 += "```"
        
        patches.append({
            "patch_type": "code_fix",
            "language": "python",
            "title": "Input Validation & Whitelisting",
            "severity_impact": "MEDIUM",
            "diff": diff3,
            "explanation": "Whitelisting is stronger than blacklisting. Define allowed, reject rest.",
            "effort": "20 minutes",
            "testing": [
                "Submit invalid input types",
                "Verify clear error rejection"
            ],
            "references": ["OWASP Input Validation", "CWE-20"]
        })
        
        return patches
    
    def _command_injection_patches(self, parameter: str) -> List[Dict[str, Any]]:
        diff = """```python\n"""
        diff += "import subprocess\n\n"
        diff += "# BEFORE (VULNERABLE)\n"
        diff += "def ping_host(hostname):\n"
        diff += "    result = subprocess.run(f\"ping -c 1 {hostname}\", shell=True, capture_output=True)\n"
        diff += "    return result.stdout\n\n"
        diff += "# AFTER (PATCHED)\n"
        diff += "def ping_host(hostname):\n"
        diff += "    result = subprocess.run(\n"
        diff += "        [\"ping\", \"-c\", \"1\", hostname],\n"
        diff += "        shell=False,\n"
        diff += "        capture_output=True,\n"
        diff += "        timeout=10\n"
        diff += "    )\n"
        diff += "    return result.stdout\n\n"
        diff += "# Even safer: validate input\n"
        diff += "import re\n"
        diff += "def validate_hostname(hostname):\n"
        diff += "    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):\n"
        diff += "        raise ValueError(\"Invalid hostname\")\n"
        diff += "    return hostname\n\n"
        diff += "# Alternative: use dedicated libraries\n"
        diff += "import socket\n"
        diff += "def check_host(hostname):\n"
        diff += "    try:\n"
        diff += "        socket.gethostbyname(hostname)\n"
        diff += "        return \"Host reachable\"\n"
        diff += "    except socket.gaierror:\n"
        diff += "        return \"Host not found\"\n"
        diff += "```"
        
        return [{
            "patch_type": "code_fix",
            "language": "python",
            "title": "Avoid Shell Execution",
            "severity_impact": "CRITICAL",
            "diff": diff,
            "explanation": "Never pass user input to shell=True. Use list args with shell=False.",
            "effort": "30 minutes",
            "testing": [
                "Submit payload: ; cat /etc/passwd",
                "Verify command not executed"
            ],
            "references": ["OWASP Command Injection", "CWE-78"]
        }]
    
    def _ssrf_patches(self) -> List[Dict[str, Any]]:
        diff = """```python\n"""
        diff += "import urllib.parse\n"
        diff += "import socket\n"
        diff += "import ipaddress\n\n"
        diff += "# BEFORE (VULNERABLE)\n"
        diff += "def fetch_url(url):\n"
        diff += "    response = requests.get(url)\n"
        diff += "    return response.text\n\n"
        diff += "# AFTER (PATCHED)\n"
        diff += "def fetch_url(user_url):\n"
        diff += "    parsed = urllib.parse.urlparse(user_url)\n"
        diff += "    \n"
        diff += "    # 1. Validate scheme\n"
        diff += "    if parsed.scheme not in ['http', 'https']:\n"
        diff += "        raise ValueError(\"Only HTTP/HTTPS allowed\")\n"
        diff += "    \n"
        diff += "    # 2. Resolve and validate IP\n"
        diff += "    hostname = parsed.hostname\n"
        diff += "    try:\n"
        diff += "        ip = socket.getaddrinfo(hostname, None)[0][4][0]\n"
        diff += "        ip_obj = ipaddress.ip_address(ip)\n"
        diff += "        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:\n"
        diff += "            raise ValueError(\"Internal addresses not allowed\")\n"
        diff += "    except socket.gaierror:\n"
        diff += "        raise ValueError(\"Cannot resolve hostname\")\n"
        diff += "    \n"
        diff += "    # 3. Use timeout and limit redirects\n"
        diff += "    response = requests.get(\n"
        diff += "        user_url,\n"
        diff += "        timeout=10,\n"
        diff += "        allow_redirects=False\n"
        diff += "    )\n"
        diff += "    return response.text\n"
        diff += "```"
        
        return [{
            "patch_type": "code_fix",
            "language": "python",
            "title": "SSRF Prevention - URL Validation",
            "severity_impact": "HIGH",
            "diff": diff,
            "explanation": "Validate URLs against IP allowlists. Block private/reserved IPs.",
            "effort": "45 minutes",
            "testing": [
                "Test with http://localhost/admin",
                "Test with http://169.254.169.254/latest/meta-data"
            ],
            "references": ["OWASP SSRF Prevention", "CWE-918"]
        }]
    
    def _lfi_patches(self, parameter: str) -> List[Dict[str, Any]]:
        diff = """```python\n"""
        diff += "import os\n"
        diff += "from pathlib import Path\n\n"
        diff += "# BEFORE (VULNERABLE)\n"
        diff += "def read_file(filename):\n"
        diff += "    path = f\"/var/www/files/{filename}\"\n"
        diff += "    with open(path, 'r') as f:\n"
        diff += "        return f.read()\n\n"
        diff += "# AFTER (PATCHED)\n"
        diff += "def read_file(filename):\n"
        diff += "    base_dir = Path(\"/var/www/files\").resolve()\n"
        diff += "    safe_name = os.path.basename(filename)\n"
        diff += "    target_path = (base_dir / safe_name).resolve()\n"
        diff += "    \n"
        diff += "    if not str(target_path).startswith(str(base_dir)):\n"
        diff += "        raise ValueError(\"Invalid file path\")\n"
        diff += "    if not target_path.exists() or not target_path.is_file():\n"
        diff += "        raise FileNotFoundError(\"File not found\")\n"
        diff += "    \n"
        diff += "    with open(target_path, 'r') as f:\n"
        diff += "        return f.read()\n\n"
        diff += "# Alternative: use allowlist\n"
        diff += "ALLOWED_FILES = {\n"
        diff += "    'report': '/var/www/files/report.pdf',\n"
        diff += "    'summary': '/var/www/files/summary.txt'\n"
        diff += "}\n\n"
        diff += "def read_allowed_file(file_key):\n"
        diff += "    if file_key not in ALLOWED_FILES:\n"
        diff += "        raise ValueError(\"File not in allowlist\")\n"
        diff += "    with open(ALLOWED_FILES[file_key], 'r') as f:\n"
        diff += "        return f.read()\n"
        diff += "```"
        
        return [{
            "patch_type": "code_fix",
            "language": "python",
            "title": "Path Traversal Prevention",
            "severity_impact": "HIGH",
            "diff": diff,
            "explanation": "Never use user input directly in file paths. Use basename() and verify.",
            "effort": "30 minutes",
            "testing": [
                "Test with ../../../etc/passwd",
                "Verify valid files still accessible"
            ],
            "references": ["OWASP Path Traversal", "CWE-22"]
        }]
    
    def _cve_patches(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        cve_id = finding.get("cve_id", [])
        if isinstance(cve_id, list) and cve_id:
            cve_id = cve_id[0]
        else:
            cve_id = str(cve_id) if cve_id else "Unknown"
        
        diff = """```bash\n"""
        diff += "# 1. Identify vulnerable component version\n"
        diff += "npm list <package>      # Node.js\n"
        diff += "pip show <package>      # Python\n\n"
        diff += "# 2. Update to patched version\n"
        diff += "npm audit fix\n"
        diff += "# OR\n"
        diff += "pip install --upgrade <package>\n"
        diff += "# OR\n"
        diff += "apt update && apt upgrade\n\n"
        diff += "# 3. Verify fix\n"
        diff += "<tool> --version\n"
        diff += "nuclei -u target -t cves/" + cve_id.lower() + ".yaml\n\n"
        diff += "# 4. Remove unused components\n"
        diff += "npm prune\n"
        diff += "```"
        
        return [{
            "patch_type": "config_change",
            "title": f"CVE Remediation: {cve_id}",
            "severity_impact": "HIGH",
            "diff": diff,
            "explanation": f"Apply vendor patch for {cve_id}. Implement compensating controls if no patch.",
            "effort": "1-2 hours",
            "testing": [
                f"Re-run nuclei scan for {cve_id}",
                "Verify component version patched"
            ],
            "references": [f"NVD: {cve_id}", "Vendor Security Advisory"]
        }]
    
    def _waf_rules(self, vuln_type: str) -> Dict[str, Any]:
        rules = {
            "xss": 'SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/* "@rx <script|javascript:|on\\w+\\s*=|<iframe|<object|<embed" "id:941100,phase:2,deny,status:403,msg:\'XSS Attack Detected\'"',
            "sql": 'SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/* "@rx (union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|drop\\s+table)" "id:942100,phase:2,deny,status:403,msg:\'SQL Injection Detected\'"',
            "rce": 'SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/* "@rx [;&|`]\\s*(cat|ls|pwd|whoami|nc\\s+-|wget\\s+|curl\\s+)" "id:932100,phase:2,deny,status:403,msg:\'Command Injection Detected\'"',
            "lfi": 'SecRule REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/* "@rx \\.\\./|\\.\\.\\\\" "id:930100,phase:2,deny,status:403,msg:\'Path Traversal Detected\'"'
        }
        
        selected = []
        for key in rules:
            if key in vuln_type:
                selected.append(rules[key])
        
        diff = "```apache\n"
        diff += "# Add to modsecurity.conf\n"
        diff += "\\n".join(selected) if selected else rules["xss"]
        diff += "\n\n# Rate limiting\n"
        diff += 'SecAction "id:900700,phase:1,nolog,pass,setvar:ip.scan_counter=+1"\n'
        diff += 'SecRule IP:SCAN_COUNTER "@gt 100" "id:900701,phase:1,deny,status:429,msg:\'Rate limit exceeded\'"\n'
        diff += "```"
        
        return {
            "patch_type": "waf_rule",
            "title": "ModSecurity WAF Rules",
            "severity_impact": "MEDIUM",
            "diff": diff,
            "explanation": "WAF rules provide defense-in-depth but should not replace secure coding.",
            "effort": "1 hour",
            "testing": [
                "Submit attack payload, verify 403 response",
                "Test legitimate traffic not blocked"
            ],
            "references": ["OWASP ModSecurity CRS", "CWE-693"]
        }
    
    def _defense_in_depth(self, vuln_type: str) -> Dict[str, Any]:
        recommendations = []
        
        if "xss" in vuln_type:
            recommendations.extend([
                "Implement Subresource Integrity (SRI) for external scripts",
                "Use X-Frame-Options: DENY to prevent clickjacking",
                "Use Trusted Types API for DOM manipulation"
            ])
        
        if "sql" in vuln_type:
            recommendations.extend([
                "Enable database query logging and anomaly detection",
                "Regular automated SQLi scanning in CI/CD"
            ])
        
        recommendations.extend([
            "Implement centralized logging and SIEM alerting",
            "Regular penetration testing and vulnerability scanning",
            "Bug bounty program for continuous testing"
        ])
        
        diff = """```yaml\n"""
        diff += "# Security Headers (add to all responses)\n"
        diff += "X-Content-Type-Options: nosniff\n"
        diff += "X-Frame-Options: DENY\n"
        diff += "Referrer-Policy: strict-origin-when-cross-origin\n"
        diff += "Permissions-Policy: geolocation=(), microphone=(), camera=()\n\n"
        diff += "# Logging Configuration\n"
        diff += "security_events:\n"
        diff += "  - sql_injection_attempts\n"
        diff += "  - xss_payloads_detected\n"
        diff += "  - authentication_failures\n"
        diff += "\n"
        diff += "alert_channels:\n"
        diff += "  - email: security@example.com\n"
        diff += "  - slack: #security-alerts\n"
        diff += "```"
        
        return {
            "patch_type": "architecture_change",
            "title": "Defense-in-Depth Recommendations",
            "severity_impact": "MEDIUM",
            "diff": diff,
            "explanation": "Defense-in-depth uses multiple security layers for redundancy.",
            "effort": "2 hours",
            "testing": [
                "Verify all security headers present",
                "Test alerting with simulated attack"
            ],
            "references": ["OWASP Defense in Depth", "NIST Cybersecurity Framework"]
        }
    
    def _sum_effort(self, patches: List[Dict[str, Any]]) -> str:
        total_minutes = 0
        for p in patches:
            effort = p.get("effort", "30 minutes")
            if "15" in effort:
                total_minutes += 15
            elif "20" in effort:
                total_minutes += 20
            elif "30" in effort:
                total_minutes += 30
            elif "45" in effort:
                total_minutes += 45
            elif "1 hour" in effort:
                total_minutes += 60
            elif "1-2" in effort:
                total_minutes += 90
            elif "2" in effort:
                total_minutes += 120
            else:
                total_minutes += 30
        
        hours = total_minutes // 60
        minutes = total_minutes % 60
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes} minutes"
    
    def _implementation_order(self, patches: List[Dict[str, Any]], severity: str) -> List[str]:
        order = []
        
        immediate = [p for p in patches if p.get("severity_impact") in ["CRITICAL", "HIGH"]]
        for p in immediate:
            order.append(f"IMMEDIATE: {p['title']} ({p.get('effort', 'unknown')})")
        
        config = [p for p in patches if p.get("patch_type") == "config_change"]
        for p in config:
            if p["title"] not in [x.split(":")[1].strip() for x in order]:
                order.append(f"SHORT-TERM: {p['title']} ({p.get('effort', 'unknown')})")
        
        waf = [p for p in patches if p.get("patch_type") == "waf_rule"]
        for p in waf:
            order.append(f"SHORT-TERM: {p['title']} ({p.get('effort', 'unknown')})")
        
        arch = [p for p in patches if p.get("patch_type") == "architecture_change"]
        for p in arch:
            order.append(f"LONG-TERM: {p['title']} ({p.get('effort', 'unknown')})")
        
        return order
