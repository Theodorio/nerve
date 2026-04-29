#!/usr/bin/env python3

import json
import os
import subprocess
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from ..config import Config


# ============================================================================
# SCHEMAS
# ============================================================================

class SubfinderInput(BaseModel):
    domain: str = Field(description="Target domain to enumerate subdomains")

class HttpxInput(BaseModel):
    subdomain_file: str = Field(description="Path to file containing subdomains")

class NmapInput(BaseModel):
    target_file: str = Field(description="Path to file containing targets")

class GowitnessInput(BaseModel):
    httpx_results: str = Field(description="Path to httpx results file")


# ============================================================================
# SUBFINDER
# ============================================================================

class SubfinderTool(BaseTool):
    name: str = "subfinder_enum"
    description: str = """
    Enumerate subdomains using subfinder. Discovers all subdomains 
    for a given domain using passive sources. Outputs to file and 
    returns structured JSON with subdomain list and count.
    """
    args_schema: Type[BaseModel] = SubfinderInput

    def _run(self, domain: str) -> str:
        if not Config.validate_tool("subfinder", Config.SUBFINDER):
            return json.dumps({
                "tool": "subfinder",
                "error": f"subfinder not found in PATH. Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "subdomains": [],
                "count": 0
            }, indent=2)
        
        output_file = Config.OUTPUT_DIR / f"subdomains_{Config.get_timestamp()}.txt"
        
        cmd = [
            Config.SUBFINDER,
            "-d", domain,
            "-all",
            "-o", str(output_file)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_RECON
            )
            
            if output_file.exists():
                content = output_file.read_text().strip()
                subdomains = [s.strip() for s in content.splitlines() if s.strip()]
                
                return json.dumps({
                    "tool": "subfinder",
                    "domain": domain,
                    "subdomains": subdomains,
                    "count": len(subdomains),
                    "output_file": str(output_file),
                    "stderr": result.stderr[-500:] if result.stderr else ""
                }, indent=2)
            
            return json.dumps({
                "tool": "subfinder",
                "error": "No output file generated",
                "stderr": result.stderr[-1000:] if result.stderr else "",
                "subdomains": [],
                "count": 0
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "subfinder",
                "error": f"Timeout after {Config.TIMEOUT_RECON}s",
                "subdomains": [],
                "count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "subfinder",
                "error": str(e),
                "subdomains": [],
                "count": 0
            }, indent=2)


# ============================================================================
# HTTPX
# ============================================================================

class HttpxTool(BaseTool):
    name: str = "httpx_probe"
    description: str = """
    Probe subdomains with httpx for live services, tech detection, 
    status codes, and page titles. Filters to only live hosts (status 200-599).
    Returns structured JSON with live hosts, tech stack, and metadata.
    """
    args_schema: Type[BaseModel] = HttpxInput

    def _load_hosts(self, subdomain_file: str) -> list[str]:
        path = Path(subdomain_file)
        if not path.exists():
            return []
        content = path.read_text(encoding="utf-8", errors="ignore")
        return [line.strip() for line in content.splitlines() if line.strip()]

    def _is_projectdiscovery_httpx(self, binary: str) -> bool:
        try:
            help_result = subprocess.run(
                [binary, "-h"],
                capture_output=True,
                text=True,
                timeout=15
            )
            help_text = f"{help_result.stdout}\n{help_result.stderr}".lower()
            return "--list" in help_text or "-l" in help_text
        except Exception:
            return False

    def _resolve_httpx_binary(self) -> str | None:
        candidates = []
        for candidate in [Config.HTTPX, os.getenv("HTTPX_BIN", ""), "httpx", "httpx.exe"]:
            candidate = candidate.strip()
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        for candidate in candidates:
            resolved = shutil.which(candidate) if not Path(candidate).exists() else candidate
            if resolved and self._is_projectdiscovery_httpx(resolved):
                return resolved
        return None

    def _fallback_probe(self, subdomain_file: str) -> tuple[list[dict], list[str], str]:
        live_hosts = []
        tech_stack = set()
        errors = []

        hosts = self._load_hosts(subdomain_file)
        for host in hosts:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                request = urllib.request.Request(url, method="HEAD")
                try:
                    with urllib.request.urlopen(request, timeout=8) as response:
                        status_code = getattr(response, "status", 200)
                        headers = dict(response.headers.items())
                        live_hosts.append({
                            "url": url,
                            "status_code": status_code,
                            "title": "",
                            "tech": [],
                            "webserver": headers.get("server", ""),
                            "content_type": headers.get("content-type", ""),
                            "content_length": int(headers.get("content-length", "0") or 0),
                            "response_time": "",
                        })
                        break
                except urllib.error.HTTPError as response_error:
                    live_hosts.append({
                        "url": url,
                        "status_code": response_error.code,
                        "title": "",
                        "tech": [],
                        "webserver": response_error.headers.get("server", "") if response_error.headers else "",
                        "content_type": response_error.headers.get("content-type", "") if response_error.headers else "",
                        "content_length": 0,
                        "response_time": "",
                    })
                    break
                except Exception as probe_error:
                    errors.append(f"{url}: {probe_error}")
                    continue

        return live_hosts, sorted(tech_stack), " | ".join(errors[-5:])

    def _run(self, subdomain_file: str) -> str:
        if not Config.validate_tool("httpx", Config.HTTPX):
            binary = self._resolve_httpx_binary()
        else:
            binary = self._resolve_httpx_binary()

        if not binary:
            live_hosts, tech_stack, fallback_error = self._fallback_probe(subdomain_file)
            return json.dumps({
                "tool": "httpx",
                "probe_mode": "fallback",
                "degraded": True,
                "error": "ProjectDiscovery httpx not available or not usable; used Python fallback probe",
                "fallback_error": fallback_error,
                "live_hosts": live_hosts,
                "host_count": len(live_hosts),
                "tech_stack": tech_stack,
            }, indent=2)

        if binary != Config.HTTPX:
            Config.HTTPX = binary
        
        output_file = Config.OUTPUT_DIR / f"httpx_{Config.get_timestamp()}.json"
        
        cmd = [
            binary,
            "-l", subdomain_file,
            "-tech-detect",
            "-status-code",
            "-title",
            "-json",
            "-o", str(output_file),
            "-timeout", "10"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_RECON
            )

            if result.returncode != 0:
                stderr = (result.stderr or "").strip()
                hint = ""
                if "No such option: -l" in stderr:
                    hint = (
                        "Likely wrong 'httpx' executable in PATH (Python HTTPX CLI). "
                        "Install ProjectDiscovery httpx and set HTTPX env var to that binary."
                    )
                live_hosts, tech_stack, fallback_error = self._fallback_probe(subdomain_file)
                return json.dumps({
                    "tool": "httpx",
                    "probe_mode": "fallback",
                    "degraded": True,
                    "error": "httpx probe failed; used Python fallback probe",
                    "hint": hint,
                    "stderr": stderr[-1000:],
                    "fallback_error": fallback_error,
                    "live_hosts": live_hosts,
                    "host_count": len(live_hosts),
                    "tech_stack": tech_stack,
                }, indent=2)
            
            live_hosts = []
            tech_stack = set()
            
            if output_file.exists():
                content = output_file.read_text().strip()
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        status = entry.get("status_code", 0)
                        # Include all responding hosts
                        if 100 <= status <= 599:
                            live_hosts.append({
                                "url": entry.get("url", ""),
                                "status_code": status,
                                "title": entry.get("title", ""),
                                "tech": entry.get("tech", []),
                                "webserver": entry.get("webserver", ""),
                                "content_type": entry.get("content_type", ""),
                                "content_length": entry.get("content_length", 0),
                                "response_time": entry.get("time", "")
                            })
                            tech_stack.update(entry.get("tech", []))
                    except json.JSONDecodeError:
                        continue
            
            if not live_hosts:
                fallback_live_hosts, fallback_tech_stack, fallback_error = self._fallback_probe(subdomain_file)
                return json.dumps({
                    "tool": "httpx",
                    "probe_mode": "fallback",
                    "degraded": True,
                    "error": "ProjectDiscovery httpx returned no parsed hosts; used Python fallback probe",
                    "fallback_error": fallback_error,
                    "live_hosts": fallback_live_hosts,
                    "host_count": len(fallback_live_hosts),
                    "tech_stack": fallback_tech_stack,
                    "output_file": str(output_file),
                    "stderr": result.stderr[-500:] if result.stderr else ""
                }, indent=2)

            return json.dumps({
                "tool": "httpx",
                "probe_mode": "projectdiscovery",
                "degraded": False,
                "live_hosts": live_hosts,
                "host_count": len(live_hosts),
                "tech_stack": sorted(list(tech_stack)),
                "output_file": str(output_file),
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "httpx",
                "error": f"Timeout after {Config.TIMEOUT_RECON}s",
                "live_hosts": [],
                "host_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "httpx",
                "error": str(e),
                "live_hosts": [],
                "host_count": 0
            }, indent=2)


# ============================================================================
# NMAP
# ============================================================================

class NmapTool(BaseTool):
    name: str = "nmap_scan"
    description: str = """
    Run nmap service scan (-sV -sC) against targets from file.
    Produces XML, nmap, and gnmap output files. Returns scan summary 
    with open ports, services, and versions.
    """
    args_schema: Type[BaseModel] = NmapInput

    def _run(self, target_file: str) -> str:
        if not Config.validate_tool("nmap", Config.NMAP):
            return json.dumps({
                "tool": "nmap",
                "error": "nmap not found in PATH. Install: sudo apt-get install nmap",
                "services_found": [],
                "service_count": 0
            }, indent=2)
        
        timestamp = Config.get_timestamp()
        output_prefix = str(Config.OUTPUT_DIR / f"nmap_scan_{timestamp}")
        
        cmd = [
            Config.NMAP,
            "-sV",
            "-sC",
            "-iL", target_file,
            "-oA", output_prefix,
            "--open"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_SCAN
            )
            
            # Parse nmap output for summary
            services = []
            xml_file = Path(f"{output_prefix}.xml")
            nmap_file = Path(f"{output_prefix}.nmap")
            
            if nmap_file.exists():
                content = nmap_file.read_text()
                current_host = None
                for line in content.splitlines():
                    if "Nmap scan report for" in line:
                        current_host = line.split("for")[-1].strip()
                    elif "/tcp" in line and "open" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            state = parts[1]
                            service = parts[2]
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""
                            
                            services.append({
                                "host": current_host,
                                "port_proto": port_proto,
                                "state": state,
                                "service": service,
                                "version": version
                            })
            
            return json.dumps({
                "tool": "nmap",
                "services_found": services,
                "service_count": len(services),
                "output_files": {
                    "xml": f"{output_prefix}.xml",
                    "nmap": f"{output_prefix}.nmap",
                    "gnmap": f"{output_prefix}.gnmap"
                },
                "stdout_summary": result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout,
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "nmap",
                "error": f"Timeout after {Config.TIMEOUT_SCAN}s",
                "services_found": [],
                "service_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "nmap",
                "error": str(e),
                "services_found": [],
                "service_count": 0
            }, indent=2)


# ============================================================================
# GOWITNESS
# ============================================================================

class GowitnessTool(BaseTool):
    name: str = "gowitness_screenshots"
    description: str = """
    Take screenshots of discovered services using gowitness.
    Creates a screenshot directory and captures visual evidence 
    of each web service for the final report.
    """
    args_schema: Type[BaseModel] = GowitnessInput

    def _run(self, httpx_results: str) -> str:
        if not Config.validate_tool("gowitness", Config.GOWITNESS):
            return json.dumps({
                "tool": "gowitness",
                "error": "gowitness not found in PATH. Install: go install github.com/sensepost/gowitness@latest",
                "screenshot_count": 0,
                "screenshots": []
            }, indent=2)
        
        screenshot_dir = Config.OUTPUT_DIR / f"screenshots_{Config.get_timestamp()}"
        screenshot_dir.mkdir(exist_ok=True)
        
        db_file = Config.OUTPUT_DIR / f"gowitness_{Config.get_timestamp()}.db"
        
        cmd = [
            Config.GOWITNESS,
            "file",
            "-f", httpx_results,
            "-P", str(screenshot_dir),
            "-D", str(db_file)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_RECON
            )
            
            screenshots = []
            for ext in ["*.png", "*.jpg", "*.jpeg"]:
                screenshots.extend([str(p.name) for p in screenshot_dir.glob(ext)])
            
            return json.dumps({
                "tool": "gowitness",
                "screenshot_count": len(screenshots),
                "screenshot_dir": str(screenshot_dir),
                "screenshots": screenshots[:50],  # Limit output
                "database": str(db_file),
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "gowitness",
                "error": f"Timeout after {Config.TIMEOUT_RECON}s",
                "screenshot_count": 0,
                "screenshots": []
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "gowitness",
                "error": str(e),
                "screenshot_count": 0,
                "screenshots": []
            }, indent=2)
