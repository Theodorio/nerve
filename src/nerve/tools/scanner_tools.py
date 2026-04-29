# !/usr/bin/env python3


import json
import subprocess
from pathlib import Path
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..config import Config


# ============================================================================
# SCHEMAS
# ============================================================================

class DalfoxInput(BaseModel):
    target_file: str = Field(description="Path to file with URLs/parameters to test for XSS")

class NucleiInput(BaseModel):
    target_file: str = Field(description="Path to file with targets to scan")

class SqlmapInput(BaseModel):
    target_file: str = Field(description="Path to file with forms/URLs for SQL injection testing")


# ============================================================================
# DALFOX (XSS Scanner)
# ============================================================================

class DalfoxTool(BaseTool):
    name: str = "dalfox_xss"
    description: str = """
    Run dalfox XSS scanner against targets. Context-aware detection 
    for reflected, DOM, and stored XSS. Outputs structured JSON with 
    confirmed vulnerabilities, payloads, parameters, and proof-of-concept URLs.
    """
    args_schema: Type[BaseModel] = DalfoxInput

    def _run(self, target_file: str) -> str:
        if not Config.validate_tool("dalfox", Config.DALFOX):
            return json.dumps({
                "tool": "dalfox",
                "error": "dalfox not found in PATH. Install: go install github.com/hahwul/dalfox/v2@latest",
                "findings": [],
                "finding_count": 0
            }, indent=2)
        
        output_file = Config.OUTPUT_DIR / f"dalfox_{Config.get_timestamp()}.json"
        
        cmd = [
            Config.DALFOX,
            "file", target_file,
            "-o", str(output_file),
            "--format", "json",
            "--only-poc", "g",  # Only verified findings
            "--worker", "10",
            "--timeout", "10"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_SCAN
            )
            
            findings = []
            
            if output_file.exists():
                try:
                    content = output_file.read_text().strip()
                    if content:
                        # Dalfox JSON output can be single object or array or newline-delimited
                        data = json.loads(content)
                        if isinstance(data, list):
                            findings = data
                        elif isinstance(data, dict):
                            findings = [data]
                except json.JSONDecodeError:
                    # Fallback: try parsing as newline-delimited JSON
                    for line in result.stdout.split("\\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            findings.append(entry)
                        except json.JSONDecodeError:
                            if "Vulnerable" in line or "POC" in line:
                                findings.append({"raw": line.strip()})
            
            # Normalize findings
            normalized = []
            for f in findings:
                if isinstance(f, dict):
                    normalized.append({
                        "type": "xss",
                        "subtype": f.get("type", "reflected"),
                        "target_url": f.get("target", f.get("url", "")),
                        "parameter": f.get("param", f.get("parameter", "unknown")),
                        "payload": f.get("poc", f.get("payload", "")),
                        "evidence": f.get("poc", ""),
                        "confidence": "high" if f.get("type") else "medium",
                        "raw": f
                    })
            
            return json.dumps({
                "tool": "dalfox",
                "findings": normalized,
                "finding_count": len(normalized),
                "output_file": str(output_file),
                "stderr": result.stderr[-500:] if result.stderr else "",
                "stdout_tail": result.stdout[-1000:] if len(result.stdout) > 1000 else result.stdout
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "dalfox",
                "error": f"Timeout after {Config.TIMEOUT_SCAN}s",
                "findings": [],
                "finding_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "dalfox",
                "error": str(e),
                "findings": [],
                "finding_count": 0
            }, indent=2)


# ============================================================================
# NUCLEI
# ============================================================================

class NucleiTool(BaseTool):
    name: str = "nuclei_scan"
    description: str = """
    Run nuclei vulnerability scanner for known CVEs and misconfigurations.
    Targets critical, high, and medium severity findings. Outputs structured 
    JSON with CVE IDs, severity, matched templates, and remediation references.
    """
    args_schema: Type[BaseModel] = NucleiInput

    def _run(self, target_file: str) -> str:
        if not Config.validate_tool("nuclei", Config.NUCLEI):
            return json.dumps({
                "tool": "nuclei",
                "error": "nuclei not found in PATH. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "findings": [],
                "finding_count": 0
            }, indent=2)
        
        output_file = Config.OUTPUT_DIR / f"nuclei_{Config.get_timestamp()}.json"
        
        cmd = [
            Config.NUCLEI,
            "-l", target_file,
            "-severity", "critical,high,medium",
            "-json",
            "-o", str(output_file),
            "-rate-limit", "150",
            "-timeout", "10"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_SCAN
            )
            
            findings = []
            
            if output_file.exists():
                for line in output_file.read_text().strip().split("\\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        findings.append({
                            "type": "cve" if "cve-id" in str(entry).lower() else "misconfiguration",
                            "template": entry.get("template-id", ""),
                            "target_url": entry.get("host", ""),
                            "severity": entry.get("info", {}).get("severity", "unknown"),
                            "cve_id": entry.get("info", {}).get("classification", {}).get("cve-id", []),
                            "cwe_id": entry.get("info", {}).get("classification", {}).get("cwe-id", []),
                            "description": entry.get("info", {}).get("description", ""),
                            "remediation": entry.get("info", {}).get("remediation", ""),
                            "reference": entry.get("info", {}).get("reference", []),
                            "matcher_name": entry.get("matcher-name", ""),
                            "extracted_results": entry.get("extracted-results", []),
                            "confidence": "high",
                            "raw": entry
                        })
                    except json.JSONDecodeError:
                        continue
            
            return json.dumps({
                "tool": "nuclei",
                "findings": findings,
                "finding_count": len(findings),
                "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
                "high_count": sum(1 for f in findings if f.get("severity") == "high"),
                "medium_count": sum(1 for f in findings if f.get("severity") == "medium"),
                "output_file": str(output_file),
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "nuclei",
                "error": f"Timeout after {Config.TIMEOUT_SCAN}s",
                "findings": [],
                "finding_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "nuclei",
                "error": str(e),
                "findings": [],
                "finding_count": 0
            }, indent=2)


# ============================================================================
# SQLMAP
# ============================================================================

class SqlmapTool(BaseTool):
    name: str = "sqlmap_scan"
    description: str = """
    Run sqlmap for automated SQL injection detection and exploitation.
    Uses batch mode with level 2 / risk 1 for safe automated scanning.
    Returns confirmed injection points with DBMS type and payload details.
    """
    args_schema: Type[BaseModel] = SqlmapInput

    def _run(self, target_file: str) -> str:
        if not Config.validate_tool("sqlmap", Config.SQLMAP):
            return json.dumps({
                "tool": "sqlmap",
                "error": "sqlmap not found in PATH. Install: pip install sqlmap",
                "findings": [],
                "finding_count": 0
            }, indent=2)
        
        output_dir = Config.OUTPUT_DIR / f"sqlmap_{Config.get_timestamp()}"
        output_dir.mkdir(exist_ok=True)
        
        cmd = [
            Config.SQLMAP,
            "-m", target_file,
            "--batch",
            "--level=2",
            "--risk=1",
            "--output-dir", str(output_dir),
            "--timeout=10",
            "--retries=2",
            "--threads=4"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_SCAN
            )
            
            # Parse sqlmap output for findings
            findings = []
            stdout = result.stdout
            
            # Look for injection confirmations
            if "is vulnerable" in stdout.lower() or "parameter" in stdout.lower():
                lines = stdout.split("\\n")
                current_injection = {}
                
                for line in lines:
                    line = line.strip()
                    if "Parameter:" in line:
                        current_injection = {"parameter": line.split("Parameter:")[-1].strip()}
                    elif "Type:" in line and current_injection:
                        current_injection["injection_type"] = line.split("Type:")[-1].strip()
                    elif "Title:" in line and current_injection:
                        current_injection["title"] = line.split("Title:")[-1].strip()
                    elif "Payload:" in line and current_injection:
                        current_injection["payload"] = line.split("Payload:")[-1].strip()
                        findings.append({
                            "type": "sqli",
                            "parameter": current_injection.get("parameter", "unknown"),
                            "injection_type": current_injection.get("injection_type", "unknown"),
                            "title": current_injection.get("title", ""),
                            "payload": current_injection.get("payload", ""),
                            "dbms": self._extract_dbms(stdout),
                            "confidence": "high",
                            "evidence": current_injection.get("payload", "")
                        })
                        current_injection = {}
            
            # Check for log files
            log_files = list(output_dir.rglob("log"))
            
            return json.dumps({
                "tool": "sqlmap",
                "findings": findings,
                "finding_count": len(findings),
                "output_dir": str(output_dir),
                "log_files": [str(l) for l in log_files],
                "stdout_summary": stdout[-3000:] if len(stdout) > 3000 else stdout,
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "sqlmap",
                "error": f"Timeout after {Config.TIMEOUT_SCAN}s",
                "findings": [],
                "finding_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "sqlmap",
                "error": str(e),
                "findings": [],
                "finding_count": 0
            }, indent=2)
    
    def _extract_dbms(self, stdout: str) -> str:
        """Extract DBMS type from sqlmap output."""
        dbms_indicators = {
            "MySQL": "mysql",
            "PostgreSQL": "postgresql",
            "Microsoft SQL Server": "mssql",
            "Oracle": "oracle",
            "SQLite": "sqlite"
        }
        for name in dbms_indicators:
            if name.lower() in stdout.lower():
                return name
        return "unknown"
