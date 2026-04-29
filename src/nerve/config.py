import os
import shutil
from pathlib import Path
from datetime import datetime


class Config:
    TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "example.com")
    CALLBACK_SERVER = os.getenv("CALLBACK_SERVER", "127.0.0.1:8080")
    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./pentest_output"))
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    MAX_WORKERS = int(os.getenv("MAX_WORKERS", "3"))
    HEADLESS = os.getenv("HEADLESS", "true").lower() == "true"
    TIMEOUT_RECON = int(os.getenv("TIMEOUT_RECON", "300"))
    TIMEOUT_SCAN = int(os.getenv("TIMEOUT_SCAN", "600"))
    TIMEOUT_EXPLOIT = int(os.getenv("TIMEOUT_EXPLOIT", "30"))
    SUBFINDER = os.getenv("SUBFINDER_BIN", "subfinder")
    HTTPX = os.getenv("HTTPX_BIN", "httpx")
    NMAP = os.getenv("NMAP_BIN", "nmap")
    GOWITNESS = os.getenv("GOWITNESS_BIN", "gowitness")
    KATANA = os.getenv("KATANA_BIN", "katana")
    ARJUN = os.getenv("ARJUN_BIN", "arjun")
    DALFOX = os.getenv("DALFOX_BIN", "dalfox")
    NUCLEI = os.getenv("NUCLEI_BIN", "nuclei")
    SQLMAP = os.getenv("SQLMAP_BIN", "sqlmap")
    FFUF = os.getenv("FFUF_BIN", "ffuf")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    PLAYWRIGHT_STEALTH = os.getenv("PLAYWRIGHT_STEALTH", "true").lower() == "true"
    
    # Runtime context
    ACTIVE_TARGET_DOMAIN = None
    ACTIVE_REPORT_FILE = None
    ACTIVE_RUN_ID = None
    _notify_callback = None

    @classmethod
    def get_timestamp(cls) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    @classmethod
    def validate_tool(cls, tool_name: str, tool_path: str) -> bool:
        return shutil.which(tool_path) is not None

    @classmethod
    def set_notifier(cls, fn):
        cls._notify_callback = fn

    @classmethod
    def notify_progress(cls, message: str):
        if cls._notify_callback:
            cls._notify_callback(message)

    @classmethod
    def set_runtime_context(cls, target_domain: str, report_file, run_id: str, notify):
        cls.ACTIVE_TARGET_DOMAIN = target_domain
        cls.ACTIVE_REPORT_FILE = report_file
        cls.ACTIVE_RUN_ID = run_id
        cls.set_notifier(notify)