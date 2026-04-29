"""Runtime configuration shared across Nerve tools."""

from __future__ import annotations

import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Callable, Any


def _to_bool(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Centralized configuration values used by tool wrappers."""

    OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./pentest_output")).resolve()
    TARGET_DOMAIN = os.getenv("TARGET_DOMAIN", "example.com")
    ACTIVE_TARGET_DOMAIN = TARGET_DOMAIN
    ACTIVE_REPORT_FILE = OUTPUT_DIR / "report.md"
    ACTIVE_RUN_ID = ""
    ACTIVE_NOTIFY: Callable[[str], None] | None = None

    SUBFINDER = os.getenv("SUBFINDER", "subfinder")
    HTTPX = os.getenv("HTTPX", "httpx")
    NMAP = os.getenv("NMAP", "nmap")
    GOWITNESS = os.getenv("GOWITNESS", "gowitness")
    KATANA = os.getenv("KATANA", "katana")
    ARJUN = os.getenv("ARJUN", "arjun")
    DALFOX = os.getenv("DALFOX", "dalfox")
    NUCLEI = os.getenv("NUCLEI", "nuclei")
    SQLMAP = os.getenv("SQLMAP", "sqlmap")

    TIMEOUT_RECON = int(os.getenv("TIMEOUT_RECON", "180"))
    TIMEOUT_SCAN = int(os.getenv("TIMEOUT_SCAN", "600"))

    HEADLESS = _to_bool(os.getenv("HEADLESS"), default=True)
    CALLBACK_SERVER = os.getenv("CALLBACK_SERVER", "127.0.0.1:8000")
    PLAYWRIGHT_STEALTH = _to_bool(os.getenv("PLAYWRIGHT_STEALTH"), default=True)

    EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")

    @staticmethod
    def get_timestamp() -> str:
        return datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    @staticmethod
    def validate_tool(tool_name: str, tool_path: str) -> bool:
        del tool_name
        return shutil.which(tool_path) is not None

    @classmethod
    def set_runtime_context(
        cls,
        *,
        target_domain: str | None = None,
        report_file: Path | None = None,
        run_id: str | None = None,
        notify: Callable[[str], None] | None = None,
    ) -> None:
        if target_domain:
            cls.ACTIVE_TARGET_DOMAIN = target_domain
        if report_file is not None:
            cls.ACTIVE_REPORT_FILE = report_file
        if run_id is not None:
            cls.ACTIVE_RUN_ID = run_id
        if notify is not None:
            cls.ACTIVE_NOTIFY = notify

    @classmethod
    def notify_progress(cls, message: str) -> None:
        callback = cls.ACTIVE_NOTIFY
        if callback is None:
            return
        try:
            callback(message)
        except Exception:
            pass


Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
