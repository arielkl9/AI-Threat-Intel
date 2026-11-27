"""AI Threat Intelligence Pipeline.

Fetches cybersecurity RSS feeds, classifies and enriches items with LLMs
(OpenAI + Perplexity), researches CVEs, renders HTML email reports, and sends
them via the Gmail API.
"""

from __future__ import annotations

__version__ = "2.0.0"
__all__ = ["__version__"]
