from __future__ import annotations

import asyncio
import os
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import uuid

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from .crew import Nerve
from .config import Config
from .tool_notifier import reset_tool_tracker, send_tool_summary_to_whatsapp

app = FastAPI(title="Nerve WhatsApp Bot")

_state_lock = threading.Lock()
_state: dict[str, Any] = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "last_error": None,
    "last_report": None,
    "last_report_excerpt": None,
    "active_target": None,
    "active_report_file": None,
    "active_run_id": None,
}

# Store active WebSocket connections and their event loops so background threads can notify WhatsApp.
_connections: dict[str, dict[str, Any]] = {}


def _load_dotenv() -> None:
    dotenv_path = Path(".env")
    if not dotenv_path.exists():
        return

    for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[key] = value


_load_dotenv()


def _normalize_sender_value(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.endswith("@c.us") or normalized.endswith("@s.whatsapp.net"):
        normalized = normalized.split("@", 1)[0]
    digits_only = "".join(character for character in normalized if character.isdigit())
    if len(digits_only) == 11 and digits_only.startswith("0"):
        digits_only = "234" + digits_only[1:]
    return digits_only or normalized


def _normalize_target_domain(value: str | None) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return Config.TARGET_DOMAIN

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    host = parsed.hostname or parsed.path.split("/")[0]
    host = host.strip().lower().rstrip(".")
    return host or Config.TARGET_DOMAIN


def _safe_report_name(target_domain: str) -> str:
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target_domain).strip("._-") or "target"
    return f"{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"


def _report_path_for_target(target_domain: str) -> Path:
    reports_dir = Config.OUTPUT_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir / _safe_report_name(target_domain)


def _queue_notification(sender: str, message: str) -> None:
    connection = _connections.get(sender)
    if not connection:
        return

    websocket = connection.get("websocket")
    loop = connection.get("loop")
    if websocket is None or loop is None or loop.is_closed():
        return

    payload = {
        "status": "progress",
        "event": "progress",
        "sender": sender,
        "response": message,
    }

    try:
        asyncio.run_coroutine_threadsafe(websocket.send_json(payload), loop)
    except Exception:
        pass


def _report_chunks(path: Path, limit: int = 2800) -> list[str]:
    if not path.exists():
        return []

    content = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not content:
        return []

    return [content[index:index + limit] for index in range(0, len(content), limit)]


def _allowed_sender(sender: str) -> bool:
    allowed = os.getenv("WHATSAPP_ALLOWED_SENDERS", "").strip()
    if not allowed:
        return True
    normalized = {_normalize_sender_value(item) for item in allowed.split(",") if item.strip()}
    return _normalize_sender_value(sender) in normalized


async def _handle_message(sender: str, message: str) -> dict[str, Any]:
    """Process a WhatsApp message and return response."""
    if sender and not _allowed_sender(sender):
        return {"status": "error", "response": "This number is not authorized for the bot."}

    normalized_message = message.strip()
    command, _, remainder = normalized_message.partition(" ")
    command = command.lower()
    target_domain = _normalize_target_domain(remainder) if command == "run" and remainder else Config.TARGET_DOMAIN

    if command in {"help", "hi", "hello", "menu"}:
        return {
            "status": "ok",
            "response": "Commands: help, status, run [target], report. Example: run oraimo.ng"
        }

    if command == "status":
        return {"status": "ok", "response": _status_message()}

    if command == "report":
        report_file = _active_report_file()
        if not report_file.exists():
            return {"status": "error", "response": "No report has been generated yet. Send 'run' first."}

        chunks = _report_chunks(report_file)
        if len(chunks) <= 1:
            return {"status": "ok", "response": chunks[0] if chunks else "Report exists but is empty."}

        return {
            "status": "ok",
            "response": f"Report ready at {report_file.name}. Sending {len(chunks)} parts.",
            "response_parts": chunks,
        }

    if command == "run":
        with _state_lock:
            already_running = bool(_state["running"])
        if already_running:
            return {
                "status": "error",
                "response": "A run is already in progress. Send 'status' to check progress."
            }
        run_id = uuid.uuid4().hex[:12]
        report_file = _report_path_for_target(target_domain)
        Config.set_runtime_context(
            target_domain=target_domain,
            report_file=report_file,
            run_id=run_id,
            notify=lambda text: _queue_notification(sender, text),
        )
        worker = threading.Thread(target=_run_crew_in_background, daemon=True)
        worker.start()
        return {
            "status": "ok",
            "response": f"Started a new readiness run for {target_domain}. I’ll send progress updates here and save the report to {report_file.name}."
        }

    return {
        "status": "error",
        "response": "Unknown command. Send 'help' for options, or 'run' to start the configured assessment."
    }


def _active_report_file() -> Path:
    report_file = getattr(Config, "ACTIVE_REPORT_FILE", None)
    if isinstance(report_file, Path):
        return report_file
    return Path("report.md")


def _send_report_to_whatsapp(sender: str, report_path: Path) -> None:
    """Send the final report to WhatsApp in chunks."""
    chunks = _report_chunks(report_path)
    if not chunks:
        _queue_notification(sender, "Report generated but is empty.")
        return

    _queue_notification(sender, f"📋 **PENTEST REPORT** 📋\nSending {len(chunks)} part(s)...\n")
    
    for idx, chunk in enumerate(chunks, 1):
        header = f"\n---\n**PART {idx}/{len(chunks)}**\n---\n" if idx > 1 else ""
        message = header + chunk
        _queue_notification(sender, message)


def _run_crew_in_background() -> None:
    sender = None
    with _state_lock:
        if _state["running"]:
            return
        _state["running"] = True
        _state["started_at"] = datetime.utcnow().isoformat()
        _state["finished_at"] = None
        _state["last_error"] = None
        _state["active_target"] = Config.ACTIVE_TARGET_DOMAIN
        _state["active_report_file"] = str(_active_report_file())
        _state["active_run_id"] = Config.ACTIVE_RUN_ID

    # Extract sender from callback context if available
    for s, conn in _connections.items():
        if conn.get("websocket"):
            sender = s
            break

    # Reset tool execution tracker for new run
    reset_tool_tracker()

    print(f"[NERVE] Starting background crew execution for {Config.ACTIVE_TARGET_DOMAIN}")
    Config.notify_progress(f"🚀 **Starting pentest** for {Config.ACTIVE_TARGET_DOMAIN}...\n")

    try:
        print(f"[NERVE] Initializing Nerve crew...")
        inputs = {
            "target_domain": Config.ACTIVE_TARGET_DOMAIN,
            "callback_server": Config.CALLBACK_SERVER,
            "current_year": str(datetime.now().year),
        }
        print(f"[NERVE] Crew inputs: {inputs}")
        crew_instance = Nerve()
        print(f"[NERVE] Nerve instance created: {crew_instance}")
        crew = crew_instance.crew()
        print(f"[NERVE] Crew initialized: {crew}")
        result = crew.kickoff(inputs=inputs)
        print(f"[NERVE] Crew execution completed. Result: {result}")
        
        # Send tool execution summary
        send_tool_summary_to_whatsapp()
        
        report_path = _active_report_file()
        excerpt_parts = _report_chunks(report_path)
        excerpt = excerpt_parts[0] if excerpt_parts else ""
        with _state_lock:
            _state["last_report"] = str(report_path.resolve()) if report_path.exists() else None
            _state["last_report_excerpt"] = excerpt
            _state["finished_at"] = datetime.utcnow().isoformat()
        
        Config.notify_progress(f"✅ **Run complete** for {Config.ACTIVE_TARGET_DOMAIN}.\nReport saved to {report_path.name}.\n")
        
        # Send the report to WhatsApp if sender is available
        if sender:
            _send_report_to_whatsapp(sender, report_path)
    except Exception as exc:
        print(f"[NERVE] ERROR: {exc}")
        import traceback
        traceback.print_exc()
        with _state_lock:
            _state["last_error"] = str(exc)
            _state["finished_at"] = datetime.utcnow().isoformat()
        Config.notify_progress(f"❌ **Run failed** for {Config.ACTIVE_TARGET_DOMAIN}:\n{exc}")
    finally:
        with _state_lock:
            _state["running"] = False
        print(f"[NERVE] Background execution finished")


def _status_message() -> str:
    with _state_lock:
        if _state["running"]:
            return f"Run in progress for {_state.get('active_target') or Config.ACTIVE_TARGET_DOMAIN}. Report file: {_state.get('active_report_file') or 'pending'}."
        if _state["last_error"]:
            return f"Last run failed: {_state['last_error']}"
        if _state["last_report"]:
            return f"Last report ready at {_state['last_report']}. Send 'report' for a summary."
    return f"Idle. Send 'run' to start a readiness assessment for {Config.ACTIVE_TARGET_DOMAIN}, or 'run oraimo.ng' to scan a different target."


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok", "service": "nerve-whatsapp-bot"}


@app.websocket("/ws/whatsapp/{sender}")
async def websocket_endpoint(websocket: WebSocket, sender: str):
    """WebSocket endpoint for Venom JS integration."""
    await websocket.accept()
    _connections[sender] = {"websocket": websocket, "loop": asyncio.get_running_loop()}
    
    try:
        while True:
            data = await websocket.receive_json()
            message = str(data.get("message", "")).strip()
            request_id = data.get("request_id")
            
            if not message:
                await websocket.send_json({"status": "error", "response": "Empty message"})
                continue
            
            result = await _handle_message(sender, message)
            if request_id:
                result["request_id"] = request_id
            await websocket.send_json(result)
            
    except WebSocketDisconnect:
        _connections.pop(sender, None)
    except Exception as e:
        try:
            await websocket.send_json({"status": "error", "response": str(e)})
        except:
            pass
        _connections.pop(sender, None)


@app.post("/whatsapp")
async def whatsapp_webhook(request: Request):
    """HTTP webhook for WhatsApp providers that POST inbound messages."""
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        payload = dict(request.query_params)

    sender = str(payload.get("sender") or payload.get("from") or payload.get("phone") or payload.get("wa_id") or "").strip()
    message = str(payload.get("message") or payload.get("body") or payload.get("text") or payload.get("content") or "").strip()

    if not sender:
        return JSONResponse({"status": "error", "response": "Missing sender"}, status_code=400)

    if not message:
        return JSONResponse({"status": "error", "response": "Missing message"}, status_code=400)

    result = await _handle_message(sender, message)
    return JSONResponse(result)

@app.post("/message")
async def send_message(request: Request):
    payload = {}

    # ✅ Try JSON first
    try:
        payload = await request.json()
    except:
        pass

    # ✅ Try FORM (this is what your bot uses)
    if not payload:
        try:
            form = await request.form()
            payload = dict(form)
        except:
            pass

    # ✅ Fallback to query params
    if not payload:
        payload = dict(request.query_params)

    sender = str(
        payload.get("sender")
        or payload.get("from")
        or payload.get("phone")
        or payload.get("wa_id")
        or ""
    ).strip()

    message = str(
        payload.get("message")
        or payload.get("body")
        or payload.get("text")
        or payload.get("content")
        or ""
    ).strip()

    print(f"[WHATSAPP-WEBHOOK] Received message from {sender}: {message}")
    print(f"[WHATSAPP-WEBHOOK] DEBUG PAYLOAD: {payload}")

    if not sender:
        print("[WHATSAPP-WEBHOOK] ERROR: Missing sender")
        return JSONResponse({"status": "error", "response": "Missing sender"}, status_code=400)

    if not message:
        print("[WHATSAPP-WEBHOOK] ERROR: Missing message")
        return JSONResponse({"status": "error", "response": "Missing message"}, status_code=400)

    print(f"[WHATSAPP-WEBHOOK] Calling _handle_message({sender}, {message})")
    result = await _handle_message(sender, message)
    print(f"[WHATSAPP-WEBHOOK] Result: {result}")
    return JSONResponse(result)