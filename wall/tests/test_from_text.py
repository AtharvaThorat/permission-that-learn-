import json

import pytest

from ptl.wall import PolicyDraftError, build_prompt, draft_policy
from ptl.wall import Capability as C
from ptl.wall import TargetClass as T

GOOD = {
    "grants": [
        {"capability": "read", "targets": ["self"]},
        {"capability": "send", "targets": ["self", "internal", "contact"]},
    ],
    "attachments_allowed_to": ["self"],
}


def test_prompt_contains_the_user_text_and_schema():
    p = build_prompt("Never delete anything.")
    assert "Never delete anything." in p
    assert "grants" in p and "max_share_permission" in p


def test_plain_json_output():
    policy = draft_policy("Only email my contacts.", llm=lambda _: json.dumps(GOOD))
    assert policy.allowed_targets(C.SEND) == frozenset({T.SELF, T.INTERNAL, T.CONTACT})
    assert policy.allowed_targets(C.DELETE) == frozenset()          # deny by default
    assert policy.description == "Only email my contacts."


def test_json_inside_a_code_fence_with_chatter():
    raw = "Sure! Here is the policy:\n```json\n" + json.dumps(GOOD) + "\n```\nLet me know."
    assert draft_policy("x", llm=lambda _: raw).allowed_targets(C.READ) == frozenset({T.SELF})


@pytest.mark.parametrize("raw", [
    "I cannot help with that.",
    "{not json}",
    json.dumps({"grants": [{"capability": "send", "targets": ["unknown"]}]}),
    json.dumps({"grants": [{"capability": "teleport", "targets": ["self"]}]}),
    json.dumps({"grants": [], "secret_backdoor": True}),
])
def test_bad_outputs_are_rejected(raw):
    with pytest.raises(PolicyDraftError):
        draft_policy("x", llm=lambda _: raw)
