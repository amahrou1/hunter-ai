"""hunter-ai: an autonomous, policy-bound bug bounty runner.

The orchestrator (plain Python) owns order, state, scope and completion.
AI agents (Claude Code in headless mode, pointed at GLM / DeepSeek / Claude)
are only called for judgment work inside a phase.
"""

__version__ = "0.8.0"
