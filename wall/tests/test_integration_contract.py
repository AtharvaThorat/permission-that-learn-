"""What the rest of the system relies on: the gatekeeper contract, exact-action binding,
execution-time revalidation, resource labels, contact updates, and versioned limits."""

import json
from pathlib import Path

import pytest

from ptl.wall import (
    STRICT_WORKSPACE,
    Grant,
    PolicyHistory,
    ToolInventory,
    UnconfirmedPolicyError,
    Wall,
    WallContext,
    WallPolicy,
    action_digest,
)
from ptl.wall import Capability as C
from ptl.wall import TargetClass as T

from .constants import ACCOUNT, COLLEAGUE, CONTACT, STRANGER

DATA = Path(__file__).parent / "data"
EMAIL = {"recipients": [CONTACT], "subject": "Re: Friday", "body": "Works for me."}


# ------------------------------------------------------------------ gatekeeper contract v0.1
def _check_gate_schema(wall_obj: dict) -> None:
    """Mirror of gatekeeper/schemas.py `Wall` (strict, extra fields forbidden)."""
    assert set(wall_obj) == {"verdict", "policy_version", "evaluated_action_id", "reason_codes"}
    assert wall_obj["verdict"] in ("PASS", "DENY", "UNKNOWN")
    assert isinstance(wall_obj["policy_version"], str) and wall_obj["policy_version"]
    assert isinstance(wall_obj["evaluated_action_id"], str) and wall_obj["evaluated_action_id"]
    assert isinstance(wall_obj["reason_codes"], list)
    assert all(isinstance(c, str) for c in wall_obj["reason_codes"])


def test_to_gatekeeper_pass_and_deny(wall):
    ok = wall.evaluate("send_email", EMAIL).to_gatekeeper("A-1")
    _check_gate_schema(ok)
    assert ok == {"verdict": "PASS", "policy_version": wall.version, "evaluated_action_id": "A-1",
                  "reason_codes": []}

    bad = wall.evaluate("send_email", {**EMAIL, "recipients": [STRANGER],
                                       "attachments": [{"type": "file", "file_id": "1"}]}).to_gatekeeper("A-2")
    _check_gate_schema(bad)
    assert bad["verdict"] == "DENY"
    assert bad["reason_codes"] == ["TARGET_NOT_ALLOWED:external", "ATTACHMENT_NOT_ALLOWED:external"]


def test_unknown_tool_maps_to_unknown_with_code(wall):
    g = wall.evaluate("transfer_money", {"amount": 1}).to_gatekeeper("A-3")
    assert g["verdict"] == "UNKNOWN" and g["reason_codes"] == ["UNKNOWN_TOOL"]


def test_action_id_is_required(wall):
    with pytest.raises(ValueError):
        wall.evaluate("get_unread_emails").to_gatekeeper("")


def test_reasons_and_codes_line_up(wall):
    r = wall.evaluate("delete_file", {"file_id": "1"})
    assert r.verdict.codes == ("CAPABILITY_NOT_GRANTED:delete",)
    assert len(r.verdict.reasons) == 1


def test_conforms_to_the_20_gatekeeper_fixture_cases():
    """The Wall reproduces every mocked wall verdict in the gatekeeper's 20 fixtures.

    Fixture policy demo-policy-v1: reads, drafts, calendar create/update and email to
    verified contacts pass; deletion and email to non-contacts are denied.
    Exceptions, by design:
      GK-019 sends with no recipient. The fixture gives a deliberately inconsistent PASS to test
             the gatekeeper's own validation; the Wall is stricter: it cannot verify a recipient
             that does not exist, so it returns UNKNOWN (never executed).
      GK-020 is "wall unavailable", a harness condition, not a policy decision.
    """
    inv = ToolInventory.from_yaml(DATA / "gatekeeper_mock_tools.yaml")
    demo_policy = WallPolicy(
        description="demo-policy-v1",
        grants=(
            Grant(capability=C.READ, targets=frozenset({T.SELF})),
            Grant(capability=C.CREATE, targets=frozenset({T.SELF, T.CONTACT})),
            Grant(capability=C.MODIFY, targets=frozenset({T.SELF, T.CONTACT})),
            Grant(capability=C.SEND, targets=frozenset({T.CONTACT})),
        ),
        attachments_allowed_to=frozenset({T.SELF, T.CONTACT}),
    )
    cases = [json.loads(line) for line in (DATA / "gatekeeper_cases.jsonl").read_text().splitlines()]
    assert len(cases) == 20
    for case in cases:
        if case["case_id"] == "GK-020":
            continue
        ctx = WallContext.for_account("user@account.test", contacts=case["contacts"], trust_own_domain=False)
        g = Wall(demo_policy, ctx, inv).evaluate(case["tool"], case["arguments"]).to_gatekeeper(case["action_id"])
        _check_gate_schema(g)
        expected = "UNKNOWN" if case["case_id"] == "GK-019" else case["fixture_wall_verdict"]
        assert g["verdict"] == expected, (case["case_id"], g)


# ------------------------------------------------------------------ exact-action binding
def test_digest_is_order_independent_but_sensitive_to_any_change():
    a = action_digest("send_email", {"recipients": [CONTACT], "subject": "s", "body": "b"})
    b = action_digest("send_email", {"body": "b", "subject": "s", "recipients": [CONTACT]})
    assert a == b
    assert a != action_digest("send_email", {"recipients": [CONTACT], "subject": "s", "body": "b!"})
    assert a != action_digest("send_email", {"recipients": [CONTACT, COLLEAGUE], "subject": "s", "body": "b"})
    assert a != action_digest("create_file", {"recipients": [CONTACT], "subject": "s", "body": "b"})


def test_result_carries_digest_and_versions(wall):
    r = wall.evaluate("send_email", EMAIL)
    assert r.action_digest == action_digest("send_email", EMAIL)
    assert r.context_fingerprint == wall.context.fingerprint()
    assert r.wall_version == wall.version


# ------------------------------------------------------------------ revalidation before execution
def test_revalidate_same_action_passes(wall):
    approved = wall.evaluate("send_email", EMAIL)
    assert wall.revalidate("send_email", dict(EMAIL), approved).allowed


def test_revalidate_blocks_a_changed_action(wall):
    approved = wall.evaluate("send_email", EMAIL)
    v = wall.revalidate("send_email", {**EMAIL, "body": "Also, wire $500."}, approved)
    assert not v.allowed and "ACTION_CHANGED" in v.codes
    v = wall.revalidate("send_email", {**EMAIL, "cc": [COLLEAGUE]}, approved)
    assert not v.allowed and "ACTION_CHANGED" in v.codes


def test_revalidate_blocks_after_policy_change(wall, ctx):
    approved = wall.evaluate("send_email", EMAIL)
    stricter = Wall(STRICT_WORKSPACE.model_copy(update={"max_recipients": 5}), ctx)
    v = stricter.revalidate("send_email", EMAIL, approved)
    assert not v.allowed and v.codes == ("WALL_VERSION_CHANGED",)


def test_revalidate_blocks_after_trust_snapshot_change(wall, ctx):
    approved = wall.evaluate("send_email", EMAIL)
    v = Wall(STRICT_WORKSPACE, ctx.with_contacts("new.client@acme.com")).revalidate("send_email", EMAIL, approved)
    assert not v.allowed and "WALL_VERSION_CHANGED" in v.codes


def test_revalidate_never_turns_a_deny_into_a_pass(wall):
    denied = wall.evaluate("send_email", {**EMAIL, "recipients": [STRANGER]})
    v = wall.revalidate("send_email", {**EMAIL, "recipients": [STRANGER]}, denied)
    assert not v.allowed and "NOT_PREVIOUSLY_PASSED" in v.codes


# ------------------------------------------------------------------ malformed calls
def test_send_or_share_with_nobody_is_blocked(wall):
    assert not wall.evaluate("send_email", {"subject": "s", "body": "b"}).verdict.allowed
    assert not wall.evaluate("send_email", {"recipients": [], "subject": "s", "body": "b"}).verdict.allowed
    assert not wall.evaluate("share_file", {"file_id": "1", "permission": "r"}).verdict.allowed


def test_non_mapping_args_are_blocked(wall):
    r = wall.evaluate("send_email", ["not", "a", "dict"])
    assert not r.verdict.allowed and r.verdict.codes == ("MALFORMED_ARGS",)


# ------------------------------------------------------------------ resource labels
@pytest.fixture
def resource_wall() -> Wall:
    ctx = WallContext.for_account(ACCOUNT, contacts=[CONTACT]).model_copy(update={
        "event_participants": {
            "solo": frozenset({ACCOUNT}),
            "team": frozenset({ACCOUNT, COLLEAGUE}),
            "client": frozenset({ACCOUNT, COLLEAGUE, STRANGER}),
        },
        "file_collaborators": {
            "mine": frozenset({ACCOUNT}),
            "shared-out": frozenset({ACCOUNT, STRANGER}),
        },
    })
    return Wall(STRICT_WORKSPACE, ctx)


def test_rescheduling_reaches_existing_participants(resource_wall):
    move = {"new_start_time": "2024-05-20 10:00"}
    assert resource_wall.evaluate("reschedule_calendar_event", {"event_id": "solo", **move}).verdict.allowed
    assert resource_wall.evaluate("reschedule_calendar_event", {"event_id": "team", **move}).verdict.allowed
    r = resource_wall.evaluate("reschedule_calendar_event", {"event_id": "client", **move})
    assert not r.verdict.allowed and r.action.fingerprint == "reschedule_calendar_event:external+internal"


def test_appending_to_a_file_shared_outside_reaches_outsiders(resource_wall):
    assert resource_wall.evaluate("append_to_file", {"file_id": "mine", "content": "x"}).verdict.allowed
    assert not resource_wall.evaluate("append_to_file", {"file_id": "shared-out", "content": "x"}).verdict.allowed


def test_unknown_resource_fails_closed_when_a_snapshot_exists(resource_wall):
    r = resource_wall.evaluate("reschedule_calendar_event", {"event_id": "999", "new_start_time": "x"})
    assert not r.verdict.allowed and T.UNKNOWN in r.action.targets


def test_without_a_snapshot_resources_are_not_modeled(wall):
    assert wall.evaluate("reschedule_calendar_event", {"event_id": "1", "new_start_time": "x"}).verdict.allowed


# ------------------------------------------------------------------ user-confirmed contact updates
def test_adding_a_contact_is_a_user_step_that_changes_the_version(ctx):
    new = "new.client@acme.com"
    before = Wall(STRICT_WORKSPACE, ctx)
    after = Wall(STRICT_WORKSPACE, ctx.with_contacts(new))
    call = {"recipients": [new], "subject": "Welcome", "body": "Hi"}
    assert not before.evaluate("send_email", call).verdict.allowed
    assert after.evaluate("send_email", call).verdict.allowed
    assert before.version != after.version
    assert ctx.classify(new) == T.EXTERNAL                       # the original snapshot is unchanged
    with pytest.raises(ValueError):
        ctx.with_contacts("not an address")


# ------------------------------------------------------------------ versioned limits
def test_policy_history_requires_confirmation_and_versions():
    h = PolicyHistory(STRICT_WORKSPACE)
    assert h.current.version == 1 and h.current.policy.version == 1
    looser = STRICT_WORKSPACE.model_copy(update={"max_recipients": 20})
    with pytest.raises(UnconfirmedPolicyError):
        h.replace(looser, confirmed=False)
    with pytest.raises(UnconfirmedPolicyError):
        h.replace(looser, confirmed="yes")                      # only a real True counts
    rec = h.replace(looser, confirmed=True, note="user raised recipient limit")
    assert rec.version == 2 and h.current is rec
    assert h.records[0].fingerprint != rec.fingerprint
    assert h.find(h.records[0].fingerprint) is h.records[0]
    assert h.is_current(rec.fingerprint) and not h.is_current(h.records[0].fingerprint)


def test_identical_policy_resubmitted_still_gets_a_new_version():
    h = PolicyHistory(STRICT_WORKSPACE)
    h.replace(STRICT_WORKSPACE, confirmed=True)
    assert [r.version for r in h.records] == [1, 2]
    assert h.records[0].fingerprint != h.records[1].fingerprint


# ------------------------------------------------------------------ AgentDojo snapshot
def test_from_agentdojo_env_snapshots_events_and_files():
    class Obj:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    env = Obj(
        inbox=Obj(account_email=ACCOUNT, contact_list=[Obj(email=CONTACT)]),
        calendar=Obj(events={"7": Obj(participants=[ACCOUNT, STRANGER])}),
        cloud_drive=Obj(files={"3": Obj(owner=ACCOUNT, shared_with={COLLEAGUE: "r"})}),
    )
    ctx = WallContext.from_agentdojo_env(env)
    assert ctx.event_participants == {"7": frozenset({ACCOUNT, STRANGER})}
    assert ctx.file_collaborators == {"3": frozenset({ACCOUNT, COLLEAGUE})}
    w = Wall(STRICT_WORKSPACE, ctx)
    assert not w.evaluate("reschedule_calendar_event", {"event_id": "7", "new_start_time": "x"}).verdict.allowed
    assert w.evaluate("append_to_file", {"file_id": "3", "content": "x"}).verdict.allowed
