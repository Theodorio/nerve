
#!/usr/bin/env python3

"""
Bug Bounty Pentest Crew — @CrewBase implementation.
Keeps your hierarchical process + GitHub Copilot LLM setup.
FIXED: Proper agent/task wiring, error handling, all tools connected.
Enhanced with WhatsApp notifications and tool tracking.
"""
from .config import Config
from crewai import Agent, Crew, Process, Task, LLM
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import Any
import os

# Import enhanced tool notification system
from .tool_notifier import wrap_tool_with_whatsapp_notifications, reset_tool_tracker, send_tool_summary_to_whatsapp

# Import tools from separate modules
from .tools.recon_tools import SubfinderTool, HttpxTool, NmapTool, GowitnessTool
from .tools.crawler_tools import KatanaTool, ArjunTool, PlaywrightCrawlTool
from .tools.scanner_tools import DalfoxTool, NucleiTool, SqlmapTool
from .tools.exploit_tools import XSSValidatorTool, CookieTheftValidatorTool
from .tools.severity_tools import CVSSCalculatorTool
from .tools.patch_tools import PatchGeneratorTool


@CrewBase
class BugBountyCrew:
    """Hierarchical bug bounty / pentesting crew with browser exploitation."""

    agents: list[BaseAgent]
    tasks: list[Task]

    def __init__(self):
        # GitHub Copilot Chat API via LiteLLM
        self.llm = LLM(
            model="github_copilot/gpt-4",
            temperature=0.3,
            max_tokens=2048,
            timeout=180,
            additional_params={"parallel_tool_calls": False}
        )
        self.enable_memory = os.getenv("ENABLE_MEMORY", "false").strip().lower() == "true"

    # -------------------------------------------------------------------------
    # MANAGER
    # -------------------------------------------------------------------------
    @agent
    def orchestrator(self) -> Agent:
        return Agent(
            config=self.agents_config['orchestrator'],
            llm=self.llm,
            allow_delegation=True,
            max_iter=15,
            verbose=True
        )

    # -------------------------------------------------------------------------
    # WORKER AGENTS
    # -------------------------------------------------------------------------
    @agent
    def recon_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['recon_agent'],
            llm=self.llm,
            tools=[
                wrap_tool_with_whatsapp_notifications(SubfinderTool()),
                wrap_tool_with_whatsapp_notifications(HttpxTool()),
                wrap_tool_with_whatsapp_notifications(NmapTool()),
                wrap_tool_with_whatsapp_notifications(GowitnessTool())
            ],
            allow_code_execution=True,
            max_iter=3,
            verbose=True
        )

    @agent
    def web_crawler_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['web_crawler_agent'],
            llm=self.llm,
            tools=[
                wrap_tool_with_whatsapp_notifications(KatanaTool()),
                wrap_tool_with_whatsapp_notifications(ArjunTool()),
                wrap_tool_with_whatsapp_notifications(PlaywrightCrawlTool())
            ],
            allow_code_execution=True,
            max_iter=3,
            verbose=True
        )

    @agent
    def vuln_scanner_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['vuln_scanner_agent'],
            llm=self.llm,
            tools=[
                wrap_tool_with_whatsapp_notifications(DalfoxTool()),
                wrap_tool_with_whatsapp_notifications(NucleiTool()),
                wrap_tool_with_whatsapp_notifications(SqlmapTool())
            ],
            allow_code_execution=True,
            max_iter=3,
            verbose=True
        )

    @agent
    def exploit_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['exploit_agent'],
            llm=self.llm,
            tools=[
                wrap_tool_with_whatsapp_notifications(XSSValidatorTool()),
                wrap_tool_with_whatsapp_notifications(CookieTheftValidatorTool())
            ],
            allow_code_execution=True,
            max_iter=3,
            verbose=True
        )

    @agent
    def severity_analyst_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['severity_analyst_agent'],
            llm=self.llm,
            tools=[wrap_tool_with_whatsapp_notifications(CVSSCalculatorTool())],
            max_iter=2,
            verbose=True
        )

    @agent
    def patch_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['patch_agent'],
            llm=self.llm,
            tools=[wrap_tool_with_whatsapp_notifications(PatchGeneratorTool())],
            max_iter=2,
            verbose=True
        )

    @agent
    def report_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['report_agent'],
            llm=self.llm,
            max_iter=2,
            verbose=True
        )

    # -------------------------------------------------------------------------
    # TASK HELPERS
    # -------------------------------------------------------------------------
    def _task_config_without_agent(self, task_name: str) -> dict:
        """Strip agent from task config so the orchestrator delegates."""
        config = dict(self.tasks_config[task_name])
        config.pop('agent', None)
        return config

    def _progress_callback(self, label: str):
        def callback(output: Any) -> None:
            summary = getattr(output, 'summary', '') or getattr(output, 'raw', '') or ''
            summary_line = ' '.join(str(summary).split()).strip()
            if summary_line:
                summary_line = summary_line[:220]
                Config.notify_progress(f'✓ **{label}** completed.\n📊 Summary: {summary_line}')
            else:
                Config.notify_progress(f'✓ **{label}** completed.')

        return callback

    def _tool_event_handler(self, tool_name: str, event_type: str):
        """Create handlers for tool events."""
        def handler(message: str = ""):
            if event_type == "start":
                Config.notify_progress(f'🔧 **{tool_name}** started...')
            elif event_type == "complete":
                Config.notify_progress(f'✅ **{tool_name}** completed.')
            elif event_type == "error":
                Config.notify_progress(f'❌ **{tool_name}** failed: {message}')
        return handler

    # -------------------------------------------------------------------------
    # TASKS
    # -------------------------------------------------------------------------
    @task
    def recon_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('recon_task'),
            callback=self._progress_callback('Reconnaissance')
        )

    @task
    def web_crawl_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('web_crawl_task'),
            callback=self._progress_callback('Web crawling')
        )

    @task
    def vuln_scan_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('vuln_scan_task'),
            callback=self._progress_callback('Vulnerability scanning')
        )

    @task
    def exploit_validation_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('exploit_validation_task'),
            callback=self._progress_callback('Exploit validation')
        )

    @task
    def severity_assessment_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('severity_assessment_task'),
            callback=self._progress_callback('Severity assessment')
        )

    @task
    def patch_generation_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('patch_generation_task'),
            callback=self._progress_callback('Patch generation')
        )

    @task
    def report_generation_task(self) -> Task:
        return Task(
            config=self._task_config_without_agent('report_generation_task'),
            output_file=str(Config.ACTIVE_REPORT_FILE),
            callback=self._progress_callback('Final report')
        )

    # -------------------------------------------------------------------------
    # CREW
    # -------------------------------------------------------------------------
    @crew
    def crew(self) -> Crew:
        """Assembles the hierarchical crew."""
        return Crew(
            agents=[
                self.recon_agent(),
                self.web_crawler_agent(),
                self.vuln_scanner_agent(),
                self.exploit_agent(),
                self.severity_analyst_agent(),
                self.patch_agent(),
                self.report_agent()
            ],
            tasks=[
                self.recon_task(),
                self.web_crawl_task(),
                self.vuln_scan_task(),
                self.exploit_validation_task(),
                self.severity_assessment_task(),
                self.patch_generation_task(),
                self.report_generation_task()
            ],
            process=Process.hierarchical,
            manager_agent=self.orchestrator(),
            verbose=True,
            memory=self.enable_memory,
            max_rpm=30
        )


# Backward-compatible class name expected by main.py
class Nerve(BugBountyCrew):
    pass


Nerve.agents_config = "config/agents.yaml"
Nerve.tasks_config = "config/tasks.yaml"