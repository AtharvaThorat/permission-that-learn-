import pytest
from pydantic import ValidationError

from ptl.wall import ALLOW_ALL, STRICT_WORKSPACE, Grant, ToolInventory, Wall, WallPolicy
from ptl.wall import Capability as C
from ptl.wall import TargetClass as T

from .constants import COLLEAGUE, CONTACT, STRANGER


# ------------------------------------------------------------------ inventory
def test_inventory_covers_all_24_workspace_tools():
    inv = ToolInventory.workspace()
    assert len(inv.tools) == 24
    counts = {}
    for spec in inv.tools.values():
        counts[spec.capability] = counts.get(spec.capability, 0) + 1
    assert counts[C.READ] == 14
    assert counts[C.DELETE] == 3


# ------------------------------------------------------------------ the pitch examples
def test_scam_email_with_attachment_is_blocked_for_two_reasons(wall):
    r = wall.evaluate("send_email", {
        "recipients": [STRANGER], "subject": "Q3", "body": "as requested",
        "attachments": [{"type": "file", "file_id": "13"}],
    })
    assert not r.verdict.allowed
    assert len(r.verdict.reasons) == 2
    assert r.action.fingerprint == "send_email:external"


def test_reply_to_contact_is_allowed(wall):
    r = wall.evaluate("send_email", {"recipients": [CONTACT], "subject": "Re: Friday", "body": "Sure"})
    assert r.verdict.allowed and r.verdict.reasons == ()


def test_one_bad_recipient_blocks_the_whole_email(wall):
    r = wall.evaluate("send_email", {"recipients": [CONTACT], "bcc": [STRANGER], "subject": "s", "body": "b"})
    assert not r.verdict.allowed


def test_delete_is_always_blocked(wall):
    for tool in ["delete_email", "delete_file", "cancel_calendar_event"]:
        assert not wall.evaluate(tool, {"email_id": "1", "file_id": "1", "event_id": "1"}).verdict.allowed


def test_reads_are_allowed(wall):
    assert wall.evaluate("get_unread_emails").verdict.allowed
    assert wall.evaluate("search_files", {"query": "budget"}).verdict.allowed


def test_calendar_invite_to_stranger_is_blocked(wall):
    r = wall.evaluate("create_calendar_event", {
        "title": "Sync", "start_time": "2024-05-20 10:00", "end_time": "2024-05-20 11:00",
        "participants": [COLLEAGUE, STRANGER],
    })
    assert not r.verdict.allowed
    ok = wall.evaluate("create_calendar_event", {
        "title": "Sync", "start_time": "2024-05-20 10:00", "end_time": "2024-05-20 11:00",
        "participants": [COLLEAGUE],
    })
    assert ok.verdict.allowed


def test_sharing_rules(wall):
    assert wall.evaluate("share_file", {"file_id": "1", "email": COLLEAGUE, "permission": "r"}).verdict.allowed
    assert not wall.evaluate("share_file", {"file_id": "1", "email": COLLEAGUE, "permission": "rw"}).verdict.allowed
    assert not wall.evaluate("share_file", {"file_id": "1", "email": CONTACT, "permission": "r"}).verdict.allowed
    # missing or odd permission fails closed (treated as 'rw')
    assert not wall.evaluate("share_file", {"file_id": "1", "email": COLLEAGUE}).verdict.allowed


def test_unknown_tool_is_blocked(wall):
    r = wall.evaluate("transfer_money", {"amount": 10})
    assert not r.verdict.allowed and r.action is None


def test_malformed_recipient_is_blocked(wall):
    r = wall.evaluate("send_email", {"recipients": ["john.doe@gmail.com, x@evil.com"], "subject": "s", "body": "b"})
    assert not r.verdict.allowed


def test_max_recipients(wall):
    many = [f"person{i}@bluesparrowtech.com" for i in range(11)]
    assert not wall.evaluate("send_email", {"recipients": many, "subject": "s", "body": "b"}).verdict.allowed


def test_forbidden_tool_beats_a_grant(ctx):
    policy = WallPolicy(
        grants=(Grant(capability=C.READ, targets=frozenset({T.SELF})),),
        forbidden_tools=frozenset({"get_received_emails"}),
    )
    w = Wall(policy, ctx)
    assert not w.evaluate("get_received_emails").verdict.allowed
    assert w.evaluate("get_unread_emails").verdict.allowed


def test_empty_policy_blocks_everything(ctx):
    w = Wall(WallPolicy(), ctx)
    for tool in ToolInventory.workspace().tools:
        assert not w.evaluate(tool).verdict.allowed


def test_allow_all_baseline_still_blocks_unknown(ctx):
    w = Wall(ALLOW_ALL, ctx)
    assert w.evaluate("send_email", {"recipients": [STRANGER], "subject": "s", "body": "b"}).verdict.allowed
    assert not w.evaluate("send_email", {"recipients": ["???"], "subject": "s", "body": "b"}).verdict.allowed


# ------------------------------------------------------------------ policy integrity
def test_unknown_can_never_be_granted():
    with pytest.raises(ValidationError):
        Grant(capability=C.SEND, targets=frozenset({T.UNKNOWN}))
    with pytest.raises(ValidationError):
        WallPolicy(attachments_allowed_to=frozenset({T.UNKNOWN}))


def test_duplicate_grants_are_rejected():
    with pytest.raises(ValidationError):
        WallPolicy(grants=(
            Grant(capability=C.SEND, targets=frozenset({T.SELF})),
            Grant(capability=C.SEND, targets=frozenset({T.EXTERNAL})),
        ))


def test_unexpected_fields_are_rejected():
    with pytest.raises(ValidationError):
        WallPolicy.model_validate({"grants": [], "allow_everything": True})


def test_policy_is_frozen():
    with pytest.raises(ValidationError):
        STRICT_WORKSPACE.max_recipients = 1000


def test_fingerprint_is_stable_and_detects_changes():
    same = WallPolicy.model_validate_json(STRICT_WORKSPACE.model_dump_json())
    assert same.fingerprint() == STRICT_WORKSPACE.fingerprint()
    changed = STRICT_WORKSPACE.model_copy(update={"max_recipients": 11})
    assert changed.fingerprint() != STRICT_WORKSPACE.fingerprint()


def test_wall_reports_policy_fingerprint(wall):
    assert wall.evaluate("get_unread_emails").policy_fingerprint == STRICT_WORKSPACE.fingerprint()


def test_explain_mentions_every_capability():
    text = STRICT_WORKSPACE.explain()
    for c in C:
        assert c.value.upper() in text
    assert "DELETE: never" in text
