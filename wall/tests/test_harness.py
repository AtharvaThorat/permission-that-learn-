"""HarnessWall: the Wall behind the black-box harness's `Wall` protocol.

The stand-ins below copy the field order of `blackbox.contracts.BoundAction` and `WallVerdict`
(branch feature/agentdojo-blackbox), so these tests run without the harness installed.
"""

import json
from dataclasses import dataclass, field

import pytest

from ptl.wall import STRICT_WORKSPACE, WallContext
from ptl.wall.harness import PASS_REASON, HarnessWall

from .constants import ACCOUNT, COLLEAGUE, CONTACT, STRANGER


@dataclass(frozen=True)
class WallVerdict:                      # mirror of blackbox.contracts.WallVerdict
    verdict: str
    reason: str
    policy_version: str
    digest: str
    state_version: str
    confirmation_required: bool = False
    missing: tuple = ()


@dataclass(frozen=True)
class BoundAction:                      # the fields of blackbox.contracts.BoundAction the Wall reads
    tool: str
    arguments_json: str
    policy_version: str
    digest: str = "d" * 64
    state_version: str = "s" * 64
    action_id: str = "attempt-1"
    effects: tuple = field(default_factory=tuple)


@pytest.fixture
def hw() -> HarnessWall:
    ctx = WallContext.for_account(ACCOUNT, contacts=[CONTACT])
    return HarnessWall(STRICT_WORKSPACE, ctx, verdict_class=WallVerdict)


def bound(hw, tool, args, **kw):
    return BoundAction(tool, json.dumps(args), kw.pop("policy_version", hw.version), **kw)


SEND = {"subject": "s", "body": "b", "attachments": None, "cc": None, "bcc": None}


def test_pass_carries_the_binding(hw):
    a = bound(hw, "send_email", {**SEND, "recipients": [CONTACT]})
    v = hw.evaluate(a)
    assert v == WallVerdict("PASS", PASS_REASON, hw.version, a.digest, a.state_version, False, ())


def test_deny_lists_every_code(hw):
    v = hw.evaluate(bound(hw, "send_email", {**SEND, "recipients": [STRANGER],
                                             "attachments": [{"type": "file", "file_id": "13"}]}))
    assert v.verdict == "DENY"
    assert v.reason == "TARGET_NOT_ALLOWED:external;ATTACHMENT_NOT_ALLOWED:external"
    assert v.missing == ()


def test_delete_is_denied(hw):
    assert hw.evaluate(bound(hw, "delete_file", {"file_id": "1"})).verdict == "DENY"


@pytest.mark.parametrize("tool,args,code", [
    ("send_email", {**SEND, "recipients": []}, "TARGET_UNVERIFIED"),
    ("send_email", {**SEND, "recipients": ["not-an-address"]}, "TARGET_UNVERIFIED"),
    ("transfer_money", {"amount": 5}, "UNKNOWN_TOOL"),
])
def test_unknown_becomes_unresolved(hw, tool, args, code):
    v = hw.evaluate(bound(hw, tool, args))
    assert v.verdict == "UNRESOLVED" and v.reason == code and v.missing == (code,)


def test_malformed_arguments_json_is_unresolved(hw):
    v = hw.evaluate(BoundAction("send_email", "{not json", hw.version))
    assert v.verdict == "UNRESOLVED" and v.reason == "MALFORMED_ARGS"


def test_action_bound_under_another_wall_is_denied(hw):
    v = hw.evaluate(bound(hw, "send_email", {**SEND, "recipients": [CONTACT]}, policy_version="ptl:old"))
    assert v.verdict == "DENY" and v.reason == "WALL_VERSION_CHANGED"


def test_version_tracks_policy_and_snapshot(hw):
    ctx = WallContext.for_account(ACCOUNT, contacts=[CONTACT])
    stricter = STRICT_WORKSPACE.model_copy(update={"max_recipients": 3})
    assert hw.version.startswith("ptl:")
    assert HarnessWall(stricter, ctx).version != hw.version
    assert HarnessWall(STRICT_WORKSPACE, ctx.with_contacts("new@client.com")).version != hw.version


def test_confirmation_is_opt_in_and_only_on_pass():
    ctx = WallContext.for_account(ACCOUNT, contacts=[CONTACT])
    hw = HarnessWall(STRICT_WORKSPACE, ctx, confirm_capabilities=["send"], verdict_class=WallVerdict)
    assert hw.evaluate(bound(hw, "send_email", {**SEND, "recipients": [COLLEAGUE]})).confirmation_required
    assert not hw.evaluate(bound(hw, "get_unread_emails", {})).confirmation_required
    assert not hw.evaluate(bound(hw, "send_email", {**SEND, "recipients": [STRANGER]})).confirmation_required


def test_real_harness_contract_if_installed(hw):
    contracts = pytest.importorskip("blackbox.contracts")
    real = HarnessWall(STRICT_WORKSPACE, hw.wall.context)
    v = real.evaluate(bound(real, "delete_file", {"file_id": "1"}))
    assert isinstance(v, contracts.WallVerdict) and v.verdict == "DENY"
