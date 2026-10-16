"""PASS / DENY / UNKNOWN: verified violations are DENY, things the Wall cannot verify are UNKNOWN."""

import pytest

from ptl.wall import UNVERIFIABLE_CODES, Verdict, WallDecision

from .constants import COLLEAGUE, CONTACT, STRANGER

D = WallDecision
REPLY = {"recipients": [CONTACT], "subject": "Re: Friday", "body": "Sure"}


@pytest.mark.parametrize("tool,args", [
    ("get_unread_emails", {}),
    ("send_email", REPLY),
    ("share_file", {"file_id": "1", "email": COLLEAGUE, "permission": "r"}),
])
def test_pass(wall, tool, args):
    r = wall.evaluate(tool, args)
    assert r.verdict.decision is D.PASS and r.verdict.allowed and r.verdict.codes == ()


@pytest.mark.parametrize("tool,args", [
    ("send_email", {"recipients": [STRANGER], "subject": "s", "body": "b"}),
    ("delete_email", {"email_id": "1"}),
    ("cancel_calendar_event", {"event_id": "1"}),
    ("share_file", {"file_id": "1", "email": COLLEAGUE, "permission": "rw"}),
    ("share_file", {"file_id": "1", "email": "it@bluesparrowtech.com.evil.com", "permission": "r"}),
])
def test_deny(wall, tool, args):
    assert wall.evaluate(tool, args).verdict.decision is D.DENY


@pytest.mark.parametrize("tool,args,code", [
    ("transfer_money", {"amount": 10}, "UNKNOWN_TOOL"),
    ("send_email", ["not", "a", "dict"], "MALFORMED_ARGS"),
    ("send_email", {"recipients": ["???"], "subject": "s", "body": "b"}, "TARGET_UNVERIFIED"),
    ("send_email", {"recipients": [f"{CONTACT}, {STRANGER}"], "subject": "s", "body": "b"}, "TARGET_UNVERIFIED"),
    ("send_email", {"recipients": [], "subject": "s", "body": "b"}, "TARGET_UNVERIFIED"),
    ("share_file", {"file_id": "1", "permission": "r"}, "TARGET_UNVERIFIED"),
])
def test_unknown(wall, tool, args, code):
    v = wall.evaluate(tool, args).verdict
    assert v.decision is D.UNKNOWN and not v.allowed and v.codes == (code,)


def test_deny_beats_unknown(wall):
    v = wall.evaluate("send_email", {"recipients": ["???"], "bcc": [STRANGER], "subject": "s", "body": "b"}).verdict
    assert v.decision is D.DENY
    assert "TARGET_NOT_ALLOWED:external" in v.codes and "TARGET_UNVERIFIED" in v.codes


def test_unverifiable_target_does_not_hide_a_forbidden_capability(wall):
    v = wall.evaluate("share_file", {"file_id": "1", "email": "???", "permission": "rw"}).verdict
    assert v.decision is D.DENY and "SHARE_LEVEL_EXCEEDED" in v.codes


def test_internal_error_fails_closed(wall):
    class Exploding(dict):
        def get(self, *a, **k):
            raise RuntimeError("boom")

    r = wall.evaluate("send_email", Exploding(subject="s"))
    assert r.verdict.decision is D.UNKNOWN and r.verdict.codes == ("WALL_ERROR",)
    assert r.to_gatekeeper("A-9")["verdict"] == "UNKNOWN"


@pytest.mark.parametrize("tool", [None, "", 42])
def test_bad_tool_name_is_unknown_not_an_exception(wall, tool):
    assert wall.evaluate(tool, {}).verdict.decision is D.UNKNOWN


def test_gatekeeper_object_carries_unknown(wall):
    g = wall.evaluate("send_email", {"recipients": [], "subject": "s", "body": "b"}).to_gatekeeper("A-1")
    assert g["verdict"] == "UNKNOWN" and g["reason_codes"] == ["TARGET_UNVERIFIED"]


def test_revalidation_failures_are_deny_not_unknown(wall):
    approved = wall.evaluate("send_email", REPLY)
    v = wall.revalidate("send_email", {**REPLY, "body": "changed"}, approved)
    assert v.decision is D.DENY


def test_decision_is_derived_and_cannot_disagree():
    assert Verdict(allowed=True).decision is D.PASS
    assert Verdict(allowed=False, codes=("UNKNOWN_TOOL",)).decision is D.UNKNOWN
    assert Verdict(allowed=False, codes=("UNKNOWN_TOOL", "TOOL_FORBIDDEN")).decision is D.DENY
    assert Verdict(allowed=False).decision is D.DENY          # a block with no code is never UNKNOWN
    assert "TARGET_UNVERIFIED" in UNVERIFIABLE_CODES
    assert Verdict(allowed=True).model_dump()["decision"] == "PASS"
