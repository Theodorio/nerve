#!/usr/bin/env python3
"""
Enhanced tool notification and tracking system.
Sends WhatsApp notifications for tool execution, captures results, and formats reports.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional
from crewai.tools import BaseTool

from .config import Config


@dataclass
class ToolExecution:
    """Tracks a single tool execution."""
    tool_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "pending"  # pending, success, error, timeout
    error_message: Optional[str] = None
    result_summary: Optional[str] = None
    result_data: Optional[dict] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name,
            "status": self.status,
            "duration": f"{self.duration_seconds:.1f}s",
            "summary": self.result_summary,
            "error": self.error_message,
        }


class ToolExecutionTracker:
    """Tracks all tool executions for a crew run."""
    
    def __init__(self):
        self.executions: list[ToolExecution] = []
    
    def add_execution(self, execution: ToolExecution):
        self.executions.append(execution)
    
    def get_summary(self) -> dict:
        """Generate summary statistics."""
        total = len(self.executions)
        successful = sum(1 for e in self.executions if e.status == "success")
        failed = sum(1 for e in self.executions if e.status == "error")
        total_time = sum(e.duration_seconds for e in self.executions)
        
        return {
            "total_tools": total,
            "successful": successful,
            "failed": failed,
            "total_time": f"{total_time:.1f}s",
            "executions": [e.to_dict() for e in self.executions]
        }
    
    def format_for_whatsapp(self) -> str:
        """Format summary for WhatsApp."""
        summary = self.get_summary()
        
        if summary["total_tools"] == 0:
            return "No tools executed."
        
        message = f"""📊 **TOOL EXECUTION SUMMARY**
━━━━━━━━━━━━━━━━━━━
✅ Successful: {summary['successful']}/{summary['total_tools']}
❌ Failed: {summary['failed']}/{summary['total_tools']}
⏱️ Total Time: {summary['total_time']}
━━━━━━━━━━━━━━━━━━━
"""
        
        for exe in self.executions:
            status_emoji = "✅" if exe.status == "success" else "❌" if exe.status == "error" else "⏳"
            message += f"\n{status_emoji} **{exe.tool_name}** ({exe.duration_seconds:.1f}s)"
            if exe.result_summary:
                summary_text = exe.result_summary[:80]
                message += f"\n   📝 {summary_text}"
            if exe.error_message:
                error_text = exe.error_message[:60]
                message += f"\n   ⚠️ {error_text}"
        
        return message


# Global tracker instance
_tool_tracker = ToolExecutionTracker()


def get_tool_tracker() -> ToolExecutionTracker:
    """Get the global tool tracker."""
    return _tool_tracker


def reset_tool_tracker():
    """Reset tracker for new run."""
    global _tool_tracker
    _tool_tracker = ToolExecutionTracker()


def extract_tool_summary(result_str: str) -> tuple[Optional[str], Optional[dict]]:
    """
    Extract a summary and structured data from tool result.
    
    Returns:
        Tuple of (summary_text, result_dict)
    """
    if not isinstance(result_str, str):
        return None, None
    
    try:
        result_dict = json.loads(result_str)
        
        # Build summary from various possible fields
        summary_parts = []
        
        # Check for error first
        if "error" in result_dict:
            return f"Error: {result_dict['error']}", result_dict
        
        # Extract counts
        count_fields = ['count', 'found', 'vulnerabilities', 'results', 'total']
        for field in count_fields:
            if field in result_dict:
                value = result_dict[field]
                summary_parts.append(f"{field}: {value}")
                break
        
        # Extract status
        if "status" in result_dict:
            summary_parts.append(f"Status: {result_dict['status']}")
        
        # Extract tool name
        if "tool" in result_dict:
            summary_parts.append(f"Tool: {result_dict['tool']}")
        
        summary = " | ".join(summary_parts) if summary_parts else "Completed"
        return summary, result_dict
        
    except (json.JSONDecodeError, TypeError):
        # Not JSON, try to extract info from text
        lines = result_str.split('\n')
        if lines:
            first_line = lines[0].strip()
            return first_line[:100], {"raw": result_str[:200]}
        return None, None


def _get_error_recovery_tip(tool_name: str, error: str) -> str:
    """
    Provide recovery tips for common tool errors.
    """
    tool_lower = tool_name.lower()
    error_lower = error.lower()
    
    recovery_tips = {
        "gowitness": {
            "not found": "Install: go install github.com/sensepost/gowitness@latest",
            "timeout": "Try increasing TIMEOUT_RECON in config or checking target availability",
            "connection": "Check target is reachable and has web services running",
        },
        "playwright": {
            "timeout": "Increase timeout or check page load performance",
            "connection": "Check target URL is valid and reachable",
            "stealth": "Try disabling PLAYWRIGHT_STEALTH in config",
            "executable": "Install: pip install playwright && playwright install chromium",
        },
        "sqlmap": {
            "not found": "Install: pip install sqlmap",
            "timeout": "Reduce sqlmap verbosity or set custom timeout",
            "no injectable": "Target may not have SQL injection vulnerabilities",
        },
        "katana": {
            "not found": "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "timeout": "Check target crawlability or reduce crawl depth",
        },
    }
    
    # Find matching recovery tip
    if tool_lower in recovery_tips:
        tips = recovery_tips[tool_lower]
        for error_key, tip in tips.items():
            if error_key in error_lower:
                return tip
        # Generic tip for tool
        return f"Check tool configuration and target availability"
    
    return "Check tool availability and network connectivity"


def wrap_tool_with_whatsapp_notifications(tool: BaseTool) -> BaseTool:
    """
    Wraps a tool to send WhatsApp notifications for execution events.
    Tracks execution, captures errors, and formats results.
    
    Usage:
        wrapped = wrap_tool_with_whatsapp_notifications(MyTool())
        agent = Agent(tools=[wrapped])
    """
    original_run = tool._run
    tracker = get_tool_tracker()
    
    def wrapped_run(*args, **kwargs) -> str:
        tool_name = tool.name
        start_time = datetime.now()
        execution = ToolExecution(tool_name=tool_name, start_time=start_time)
        
        # Send start notification
        Config.notify_progress(f"🔧 **{tool_name}** started...")
        
        try:
            result = original_run(*args, **kwargs)
            
            # Parse result
            summary, result_dict = extract_tool_summary(result)
            
            # Update execution tracking
            execution.status = "success"
            execution.result_summary = summary
            execution.result_data = result_dict
            execution.end_time = datetime.now()
            execution.duration_seconds = (execution.end_time - start_time).total_seconds()
            
            # Send completion notification
            if summary:
                Config.notify_progress(f"✅ **{tool_name}** completed ({execution.duration_seconds:.1f}s)\n📊 {summary}")
            else:
                Config.notify_progress(f"✅ **{tool_name}** completed ({execution.duration_seconds:.1f}s)")
            
            tracker.add_execution(execution)
            return result
            
        except Exception as e:
            error_msg = str(e)
            recovery_tip = _get_error_recovery_tip(tool_name, error_msg)
            
            # Update execution tracking
            execution.status = "error"
            execution.error_message = error_msg[:100]
            execution.end_time = datetime.now()
            execution.duration_seconds = (execution.end_time - start_time).total_seconds()
            
            # Send error notification with recovery tip
            Config.notify_progress(
                f"❌ **{tool_name}** failed:\n"
                f"⚠️ {error_msg[:150]}\n"
                f"💡 **Suggestion**: {recovery_tip}"
            )
            
            tracker.add_execution(execution)
            raise
    
    tool._run = wrapped_run
    return tool


def send_tool_summary_to_whatsapp() -> None:
    """
    Send tool execution summary to WhatsApp at end of run.
    """
    tracker = get_tool_tracker()
    summary_message = tracker.format_for_whatsapp()
    Config.notify_progress(summary_message)
