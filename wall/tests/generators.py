"""Random policies and tool calls for property tests. Shared by the seeded fuzz tests and Hypothesis."""

from __future__ import annotations

import random

from ptl.wall import Grant, ToolInventory, WallPolicy
from ptl.wall import Capability as C
from ptl.wall import TargetClass as T

from .constants import ACCOUNT, COLLEAGUE, CONTACT, STRANGER

GRANTABLE = [T.SELF, T.INTERNAL, T.CONTACT, T.EXTERNAL]
TOOLS = sorted(ToolInventory.workspace().tools)
ADDRESSES = [
    ACCOUNT, COLLEAGUE, CONTACT, STRANGER,
    "BOSS@BlueSparrowTech.com",                 # internal, odd case
    "boss@bluesparrowtech.com.evil.com",         # lookalike
    "a@b.com, c@d.com",                          # two in one string
    "not-an-email", "", "x@bluesparrowtéch.com",  # malformed / non-ASCII
]


def _subset(rng: random.Random, items: list) -> frozenset:
    return frozenset(x for x in items if rng.random() < 0.5)


def gen_policy(rng: random.Random) -> WallPolicy:
    grants = []
    for cap in C:
        targets = _subset(rng, GRANTABLE)
        if targets:
            grants.append(Grant(capability=cap, targets=targets))
    return WallPolicy(
        grants=tuple(grants),
        forbidden_tools=frozenset(t for t in TOOLS if rng.random() < 0.1),
        attachments_allowed_to=_subset(rng, GRANTABLE),
        max_recipients=rng.choice([None, 1, 2, 3, 5]),
        max_share_permission=rng.choice(["r", "rw"]),
    )


def gen_call(rng: random.Random) -> tuple[str, dict]:
    tool = rng.choice(TOOLS)
    n = rng.randint(0, 4)
    addrs = [rng.choice(ADDRESSES) for _ in range(n)]
    args = {
        "recipients": addrs, "participants": addrs,
        "cc": [rng.choice(ADDRESSES)] if rng.random() < 0.3 else None,
        "bcc": [rng.choice(ADDRESSES)] if rng.random() < 0.3 else None,
        "email": rng.choice(ADDRESSES),
        "attachments": [{"type": "file", "file_id": "1"}] if rng.random() < 0.4 else None,
        "permission": rng.choice(["r", "rw", None, "admin"]),
        "subject": "s", "body": "b", "file_id": "1", "event_id": "1", "email_id": "1",
    }
    return tool, args


def weaken(policy: WallPolicy, rng: random.Random) -> WallPolicy:
    """Return a policy that grants a subset of `policy` (never more)."""
    grants = []
    for g in policy.grants:
        if rng.random() < 0.2:
            continue                                   # drop the whole grant
        kept = frozenset(t for t in g.targets if rng.random() < 0.7)
        if kept:
            grants.append(Grant(capability=g.capability, targets=kept))
    max_r = policy.max_recipients
    if rng.random() < 0.3:
        max_r = max(1, (max_r or 5) - rng.randint(0, 2))
    return WallPolicy(
        grants=tuple(grants),
        forbidden_tools=policy.forbidden_tools | frozenset(t for t in TOOLS if rng.random() < 0.05),
        attachments_allowed_to=frozenset(t for t in policy.attachments_allowed_to if rng.random() < 0.7),
        max_recipients=max_r,
        max_share_permission="r" if rng.random() < 0.3 else policy.max_share_permission,
    )
