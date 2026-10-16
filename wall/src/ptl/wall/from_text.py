"""Draft a WallPolicy from the user's plain-English limits.

This is the ONLY place an LLM touches the Wall, and it happens once, before the agent
runs. The draft is shown to the user (policy.explain()) and must be confirmed. The input
is the user's own words, never content from emails, files, or web pages.

The LLM is passed in as a plain function, so any provider works:
    draft = draft_policy(text, llm=lambda prompt: my_client.complete(prompt))
"""

from __future__ import annotations

import json
import re
from typing import Callable

from pydantic import ValidationError

from .policy import WallPolicy

PROMPT_TEMPLATE = """You convert a person's plain-English limits for their AI assistant into a strict JSON policy.

Rules:
- Deny by default. Only grant what the person clearly allows.
- If something is unclear, choose the stricter option (leave it out).
- Never use the target "unknown".
- Output ONLY the JSON object, nothing else.

Capabilities:
- read: look at their own emails, files, calendar
- create: make new files or calendar events (events may invite people)
- modify: change existing files or events (including adding participants)
- send: send emails
- share: give someone access to a file
- delete: delete emails, files, or events
- pay: send money

Target classes:
- self: the person's own account or their own data
- internal: people in the person's organization
- contact: known people outside the organization
- external: anyone else

Other fields:
- attachments_allowed_to: target classes that may receive attachments
- max_recipients: optional integer limit on recipients per action
- max_share_permission: "r" (read-only) or "rw" (read and write)
- forbidden_tools: tool names that must never be used

JSON schema:
{schema}

Example output:
{example}

The person's limits:
\"\"\"{user_text}\"\"\"
"""

_EXAMPLE = {
    "description": "Only email my contacts. Never delete anything.",
    "grants": [
        {"capability": "read", "targets": ["self"]},
        {"capability": "send", "targets": ["self", "internal", "contact"]},
    ],
    "attachments_allowed_to": ["self"],
    "max_share_permission": "r",
}


class PolicyDraftError(ValueError):
    """The LLM output could not be turned into a valid policy. Ask the user to rephrase."""


def build_prompt(user_text: str) -> str:
    schema = json.dumps(WallPolicy.model_json_schema(), indent=2)
    return PROMPT_TEMPLATE.format(schema=schema, example=json.dumps(_EXAMPLE, indent=2), user_text=user_text)


def _extract_json(raw: str) -> dict:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    text = fenced.group(1) if fenced else raw
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise PolicyDraftError("no JSON object found in the model output")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as e:
        raise PolicyDraftError(f"model output is not valid JSON: {e}") from e


def draft_policy(user_text: str, llm: Callable[[str], str]) -> WallPolicy:
    """Return a validated draft. The caller must show draft.explain() and get confirmation."""
    data = _extract_json(llm(build_prompt(user_text)))
    data.setdefault("description", user_text)
    try:
        return WallPolicy.model_validate(data)
    except ValidationError as e:
        raise PolicyDraftError(f"model output is not a valid policy: {e}") from e
