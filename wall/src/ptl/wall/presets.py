"""Ready-made policies for experiments.

STRICT_WORKSPACE matches the running example in our pitch:
  "Handle my email and calendar. Only email people in my contacts.
   Never share files outside work. Never delete anything."
"""

from __future__ import annotations

from .models import Capability as C
from .models import TargetClass as T
from .policy import Grant, WallPolicy

STRICT_WORKSPACE = WallPolicy(
    description=(
        "Handle my email and calendar. Only email people in my contacts. "
        "Never share files outside work. Never delete anything."
    ),
    grants=(
        Grant(capability=C.READ, targets=frozenset({T.SELF})),
        Grant(capability=C.CREATE, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT})),
        Grant(capability=C.MODIFY, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT})),
        Grant(capability=C.SEND, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT})),
        Grant(capability=C.SHARE, targets=frozenset({T.INTERNAL})),
    ),
    attachments_allowed_to=frozenset({T.SELF, T.INTERNAL}),
    max_recipients=10,
    max_share_permission="r",
)

# Looser variant for experiments: the agent may email or invite anyone, but never deletes,
# never attaches files or events for strangers, and only shares files read-only inside work.
# Trades some attack protection (plain-text exfiltration to a stranger passes) for task success.
WORKSPACE_RELAXED = WallPolicy(
    description=(
        "Handle my email and calendar. Never delete anything. Never send files to strangers. "
        "Only share files read-only with people at work."
    ),
    grants=(
        Grant(capability=C.READ, targets=frozenset({T.SELF})),
        Grant(capability=C.CREATE, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT, T.EXTERNAL})),
        Grant(capability=C.MODIFY, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT, T.EXTERNAL})),
        Grant(capability=C.SEND, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT, T.EXTERNAL})),
        Grant(capability=C.SHARE, targets=frozenset({T.INTERNAL})),
    ),
    attachments_allowed_to=frozenset({T.SELF, T.INTERNAL, T.CONTACT}),
    max_recipients=10,
    max_share_permission="r",
)

# Read-only assistant: can look at the user's own data and do nothing else.
READ_ONLY = WallPolicy(
    description="Only read my email, calendar, and files. Never change or send anything.",
    grants=(Grant(capability=C.READ, targets=frozenset({T.SELF})),),
)

# Baseline for the "no protection" setup: allows every capability to every valid target.
ALLOW_ALL = WallPolicy(
    description="No limits (baseline only).",
    grants=tuple(
        Grant(capability=c, targets=frozenset({T.SELF, T.INTERNAL, T.CONTACT, T.EXTERNAL}))
        for c in C
    ),
    attachments_allowed_to=frozenset({T.SELF, T.INTERNAL, T.CONTACT, T.EXTERNAL}),
    max_share_permission="rw",
)
