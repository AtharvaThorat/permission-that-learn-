"""Versioned user limits: an append-only history of confirmed policies.

The Wall itself is frozen. Changing the limits means the user confirms a new policy, which
gets the next version number and a new fingerprint. Old versions stay in the history so a
log line ("decided under policy v2, fingerprint ab12...") can always be traced back.
Nothing here is reachable by the agent, the gatekeeper, or the memory.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from .policy import WallPolicy


class PolicyRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: int
    fingerprint: str
    policy: WallPolicy
    confirmed_by: str
    confirmed_at: str
    note: str = ""


class UnconfirmedPolicyError(PermissionError):
    """A policy change was attempted without the user's explicit confirmation."""


class PolicyHistory:
    """Append-only list of user-confirmed policies. `current` is the one the Wall should use."""

    def __init__(self, initial: WallPolicy, *, confirmed_by: str = "user", note: str = "initial limits"):
        self._records: list[PolicyRecord] = []
        self._append(initial, confirmed_by, note)

    def _append(self, policy: WallPolicy, confirmed_by: str, note: str) -> PolicyRecord:
        version = len(self._records) + 1
        stamped = policy.model_copy(update={"version": version})
        record = PolicyRecord(
            version=version,
            fingerprint=stamped.fingerprint(),
            policy=stamped,
            confirmed_by=confirmed_by,
            confirmed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            note=note,
        )
        self._records.append(record)
        return record

    @property
    def current(self) -> PolicyRecord:
        return self._records[-1]

    @property
    def records(self) -> tuple[PolicyRecord, ...]:
        return tuple(self._records)

    def replace(self, new_policy: WallPolicy, *, confirmed: bool, confirmed_by: str = "user",
                note: str = "") -> PolicyRecord:
        """Lock in a new policy. `confirmed` must be True: the user saw new_policy.explain() and said yes."""
        if confirmed is not True:
            raise UnconfirmedPolicyError("the user must confirm a new policy before it replaces the old one")
        return self._append(new_policy, confirmed_by, note)

    def find(self, fingerprint: str) -> PolicyRecord | None:
        return next((r for r in self._records if r.fingerprint == fingerprint), None)

    def is_current(self, fingerprint: str) -> bool:
        return fingerprint == self.current.fingerprint
