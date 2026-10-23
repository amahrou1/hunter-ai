"""hunter-ai: an autonomous, policy-bound bug bounty runner.

Each testing phase is an AI agent (Claude Code in headless mode, pointed at
GLM / DeepSeek / Claude) that decides and acts. The orchestrator owns order,
state and completion, and the scope proxy and command checker enforce scope,
rate and the program rules in code, so safety does not depend on the model.
"""

__version__ = "0.38.0"
