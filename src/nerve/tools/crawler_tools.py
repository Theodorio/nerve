#!/usr/bin/env python3


import json
import subprocess
from pathlib import Path
from typing import Type, List, Dict, Any

from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from playwright.sync_api import sync_playwright

from ..config import Config


# ============================================================================
# SCHEMAS
# ============================================================================

class KatanaInput(BaseModel):
    url: str = Field(description="Target URL to crawl")

class ArjunInput(BaseModel):
    url: str = Field(description="Target URL to discover parameters")

class PlaywrightCrawlInput(BaseModel):
    url: str = Field(description="Target URL to crawl with Playwright")


# ============================================================================
# KATANA
# ============================================================================

class KatanaTool(BaseTool):
    name: str = "katana_crawl"
    description: str = """
    Crawl web application with katana (ProjectDiscovery). Discovers 
    endpoints, API routes, forms, and JavaScript files up to depth 3.
    Excludes static assets to focus on functional endpoints.
    """
    args_schema: Type[BaseModel] = KatanaInput

    def _run(self, url: str) -> str:
        if not Config.validate_tool("katana", Config.KATANA):
            return json.dumps({
                "tool": "katana",
                "target": url,
                "error": "katana not found in PATH. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
                "endpoints": [],
                "endpoint_count": 0
            }, indent=2)
        
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:100]
        output_file = Config.OUTPUT_DIR / f"katana_{safe_name}_{Config.get_timestamp()}.txt"
        
        cmd = [
            Config.KATANA,
            "-u", url,
            "-d", "3",
            "-jc",  # JS crawling
            "-ef", "js,css,png,jpg,svg,woff,woff2,ttf,eot,ico,gif",  # Exclude static
            "-o", str(output_file),
            "-timeout", "15"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_RECON
            )
            
            endpoints = []
            js_files = []
            api_endpoints = []
            
            if output_file.exists():
                content = output_file.read_text().strip()
                for line in content.split("\\n"):
                    line = line.strip()
                    if not line:
                        continue
                    
                    endpoints.append(line)
                    
                    if line.endswith(".js") or "/js/" in line:
                        js_files.append(line)
                    
                    # Detect API patterns
                    api_indicators = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/swagger", "/openapi"]
                    if any(ind in line.lower() for ind in api_indicators):
                        api_endpoints.append(line)
            
            return json.dumps({
                "tool": "katana",
                "target": url,
                "endpoints": endpoints[:200],  # Limit
                "endpoint_count": len(endpoints),
                "js_files": js_files[:50],
                "api_endpoints": api_endpoints[:50],
                "output_file": str(output_file),
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "katana",
                "target": url,
                "error": f"Timeout after {Config.TIMEOUT_RECON}s",
                "endpoints": [],
                "endpoint_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "katana",
                "target": url,
                "error": str(e),
                "endpoints": [],
                "endpoint_count": 0
            }, indent=2)


# ============================================================================
# ARJUN
# ============================================================================

class ArjunTool(BaseTool):
    name: str = "arjun_params"
    description: str = """
    Discover hidden HTTP parameters with arjun. Tests common parameter 
    names against GET/POST endpoints to find injection points that 
    standard crawlers miss.
    """
    args_schema: Type[BaseModel] = ArjunInput

    def _run(self, url: str) -> str:
        if not Config.validate_tool("arjun", Config.ARJUN):
            return json.dumps({
                "tool": "arjun",
                "target": url,
                "error": "arjun not found in PATH. Install: pip install arjun",
                "parameters": [],
                "parameter_count": 0
            }, indent=2)
        
        safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:100]
        output_file = Config.OUTPUT_DIR / f"arjun_{safe_name}_{Config.get_timestamp()}.json"
        
        cmd = [
            Config.ARJUN,
            "-u", url,
            "-oJ", str(output_file),
            "-t", "10",
            "--stable"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.TIMEOUT_RECON
            )
            
            params = []
            methods_tested = []
            
            if output_file.exists():
                try:
                    data = json.loads(output_file.read_text())
                    if isinstance(data, dict):
                        params = data.get("params", [])
                        methods_tested = data.get("methods", ["GET"])
                    elif isinstance(data, list):
                        params = data
                except json.JSONDecodeError:
                    pass
            
            return json.dumps({
                "tool": "arjun",
                "target": url,
                "parameters": params,
                "parameter_count": len(params),
                "methods_tested": methods_tested,
                "output_file": str(output_file),
                "stderr": result.stderr[-500:] if result.stderr else ""
            }, indent=2)
            
        except subprocess.TimeoutExpired:
            return json.dumps({
                "tool": "arjun",
                "target": url,
                "error": f"Timeout after {Config.TIMEOUT_RECON}s",
                "parameters": [],
                "parameter_count": 0
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "tool": "arjun",
                "target": url,
                "error": str(e),
                "parameters": [],
                "parameter_count": 0
            }, indent=2)


# ============================================================================
# PLAYWRIGHT CRAWLER - FIXED VERSION
# ============================================================================

class PlaywrightCrawlTool(BaseTool):
    name: str = "playwright_crawl"
    description: str = """
    Use Playwright to crawl a page in a real browser. Extracts all 
    links, forms with input fields, standalone inputs, JavaScript files, 
    and authentication endpoints. Captures a screenshot for visual 
    confirmation. Handles SPAs and JavaScript-rendered content.
    FIXED: Uses modern Playwright APIs, proper cleanup, stealth mode.
    """
    args_schema: Type[BaseModel] = PlaywrightCrawlInput

    def _run(self, url: str) -> str:
        browser = None
        try:
            with sync_playwright() as p:
                # Launch with stealth args
                launch_args = [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                ]
                
                browser = p.chromium.launch(
                    headless=Config.HEADLESS,
                    args=launch_args
                )
                
                context = browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    locale="en-US",
                    timezone_id="America/New_York",
                    # Additional stealth
                    java_script_enabled=True,
                    bypass_csp=True,
                )
                
                # Add stealth script to hide automation
                if Config.PLAYWRIGHT_STEALTH:
                    try:
                        context.add_init_script("""
                            Object.defineProperty(navigator, 'webdriver', {
                                get: () => undefined
                            });
                            Object.defineProperty(navigator, 'plugins', {
                                get: () => [1, 2, 3, 4, 5]
                            });
                            window.chrome = { runtime: {} };
                        """)
                    except Exception:
                        # Stealth is best-effort; continue if the script is rejected.
                        pass
                
                page = context.new_page()
                page_source = ""
                
                try:
                    # Navigate and wait for full load
                    response = page.goto(
                        url,
                        wait_until="networkidle",
                        timeout=30000
                    )
                    
                    # Extra wait for lazy-loaded content
                    page.wait_for_timeout(3000)
                    
                    # FIXED: Use page.evaluate with querySelectorAll instead of eval_on_selector_all
                    links = page.evaluate("""
                        () => Array.from(document.querySelectorAll('a[href]')).map(e => ({
                            href: e.href,
                            text: e.textContent.trim().substring(0, 100),
                            is_external: !e.href.includes(window.location.hostname)
                        }))
                    """)
                    
                    forms = page.evaluate("""
                        () => Array.from(document.querySelectorAll('form')).map(e => ({
                            action: e.action || window.location.href,
                            method: (e.method || 'GET').toUpperCase(),
                            id: e.id,
                            name: e.name,
                            enctype: e.enctype,
                            inputs: Array.from(e.querySelectorAll('input, textarea, select')).map(i => ({
                                tag: i.tagName.toLowerCase(),
                                name: i.name,
                                type: i.type || 'text',
                                id: i.id,
                                required: i.required,
                                placeholder: i.placeholder || '',
                                value: i.value || ''
                            }))
                        }))
                    """)
                    
                    all_inputs = page.evaluate("""
                        () => Array.from(document.querySelectorAll('input, textarea, select')).map(e => ({
                            tag: e.tagName.toLowerCase(),
                            name: e.name,
                            type: e.type || 'text',
                            id: e.id,
                            required: e.required,
                            placeholder: e.placeholder || '',
                            form: e.form ? e.form.id || e.form.action : null
                        }))
                    """)
                    
                    scripts = page.evaluate("""
                        () => Array.from(document.querySelectorAll('script[src]')).map(e => e.src)
                    """)
                    
                    inline_scripts = page.evaluate("""
                        () => Array.from(document.querySelectorAll('script:not([src])')).map(e => e.textContent.substring(0, 500))
                    """)
                    
                    # Detect authentication endpoints
                    auth_keywords = [
                        "login", "signin", "auth", "register", "signup",
                        "password", "reset", "forgot", "admin", "dashboard",
                        "account", "profile", "logout", "signout"
                    ]
                    auth_endpoints = [
                        link for link in links
                        if any(kw in link.get("href", "").lower() for kw in auth_keywords)
                    ]
                    
                    # Extract cookies
                    cookies = context.cookies()
                    cookie_summary = [
                        {
                            "name": c.get("name", ""),
                            "domain": c.get("domain", ""),
                            "httpOnly": c.get("httpOnly", False),
                            "secure": c.get("secure", False),
                            "sameSite": c.get("sameSite", "")
                        }
                        for c in cookies
                    ]
                    
                    # Capture screenshot
                    safe_name = url.replace("://", "_").replace("/", "_")[:80]
                    screenshot_path = Config.OUTPUT_DIR / f"crawl_{safe_name}_{Config.get_timestamp()}.png"
                    page.screenshot(path=str(screenshot_path), full_page=True)

                    # Capture the page source before closing the page.
                    page_source = page.content()
                    
                    # Page metadata
                    title = page.title()
                    meta_description = ""
                    try:
                        meta_desc = page.query_selector("meta[name='description']")
                        if meta_desc:
                            meta_description = meta_desc.get_attribute("content") or ""
                    except Exception:
                        pass
                    
                    page.close()
                    context.close()
                    browser.close()
                    browser = None
                    
                    return json.dumps({
                        "tool": "playwright_crawl",
                        "url": url,
                        "title": title,
                        "meta_description": meta_description[:200],
                        "status_code": response.status if response else 0,
                        "links": links[:100],
                        "link_count": len(links),
                        "forms": forms,
                        "form_count": len(forms),
                        "all_inputs": all_inputs[:50],
                        "input_count": len(all_inputs),
                        "scripts": scripts[:30],
                        "script_count": len(scripts),
                        "inline_script_snippets": [s[:200] for s in inline_scripts[:10]],
                        "auth_endpoints": auth_endpoints[:20],
                        "auth_endpoint_count": len(auth_endpoints),
                        "cookies": cookie_summary,
                        "screenshot": str(screenshot_path),
                        "content_length": len(page_source)
                    }, indent=2)
                    
                except Exception as e:
                    screenshot_path = None
                    try:
                        safe_name = url.replace("://", "_").replace("/", "_")[:80]
                        screenshot_path = Config.OUTPUT_DIR / f"crawl_{safe_name}_{Config.get_timestamp()}_error.png"
                        if page:
                            page.screenshot(path=str(screenshot_path), full_page=True)
                    except Exception:
                        screenshot_path = None
                    page.close()
                    context.close()
                    if browser:
                        browser.close()
                        browser = None
                    return json.dumps({
                        "tool": "playwright_crawl",
                        "url": url,
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "screenshot": str(screenshot_path) if screenshot_path else "",
                        "links": [],
                        "forms": [],
                        "auth_endpoints": []
                    }, indent=2)
                    
        except Exception as e:
            if browser:
                try:
                    browser.close()
                except:
                    pass
            return json.dumps({
                "tool": "playwright_crawl",
                "url": url,
                "error": f"Browser launch failed: {str(e)}",
                "links": [],
                "forms": [],
                "auth_endpoints": []
            }, indent=2)
