#!/usr/bin/env python
import sys
import warnings

from datetime import datetime

from nerve.crew import Nerve

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

# This main file is intended to be a way for you to run your
# crew locally, so refrain from adding unnecessary logic into this file.
# Replace with inputs you want to test with, it will automatically
# interpolate any tasks and agents information


def run_whatsapp():
    """Run the WhatsApp webhook bot."""
    import uvicorn

    uvicorn.run("nerve.whatsapp_bot:app", host="0.0.0.0", port=8000, reload=False)

def run():
    """
    Run the crew.
    """
    inputs = {
        'target_domain': 'kimi.com',  # Primary input for pentest target
        'callback_server': 'http://attacker.com',  # For XSS/callback exfiltration
        'current_year': str(datetime.now().year)
    }

    try:
        Nerve().crew().kickoff(inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")


def train():
    """
    Train the crew for a given number of iterations.
    """
    inputs = {
        'target_domain': 'example.com',  # Primary input for pentest target
        'callback_server': 'http://attacker.com',  # For XSS/callback exfiltration
        'current_year': str(datetime.now().year)
    }
    try:
        Nerve().crew().train(n_iterations=int(sys.argv[1]), filename=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while training the crew: {e}")

def replay():
    """
    Replay the crew execution from a specific task.
    """
    try:
        Nerve().crew().replay(task_id=sys.argv[1])

    except Exception as e:
        raise Exception(f"An error occurred while replaying the crew: {e}")

def test():
    """
    Test the crew execution and returns the results.
    """
    inputs = {
        "topic": "run a pentest readiness assessment on 192.168.1.1",
        "current_year": str(datetime.now().year)
    }

    try:
        Nerve().crew().test(n_iterations=int(sys.argv[1]), eval_llm=sys.argv[2], inputs=inputs)

    except Exception as e:
        raise Exception(f"An error occurred while testing the crew: {e}")

def run_with_trigger():
    """
    Run the crew with trigger payload.
    """
    import json

    if len(sys.argv) < 2:
        raise Exception("No trigger payload provided. Please provide JSON payload as argument.")

    try:
        trigger_payload = json.loads(sys.argv[1])
    except json.JSONDecodeError:
        raise Exception("Invalid JSON payload provided as argument")

    inputs = {
        "crewai_trigger_payload": trigger_payload,
        "topic": "",
        "current_year": ""
    }

    try:
        result = Nerve().crew().kickoff(inputs=inputs)
        return result
    except Exception as e:
        raise Exception(f"An error occurred while running the crew with trigger: {e}")
