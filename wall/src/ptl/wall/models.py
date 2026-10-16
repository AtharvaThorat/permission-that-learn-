"""Core data types for the Wall.

Everything here is deliberately small and frozen (immutable). The Wall must be
deterministic: the same action and the same policy always give the same verdict.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, computed_field, field_validator


class Capability(str, Enum):
    """What kind of thing a tool call does."""

    READ = "read"        # look at the user's own data (emails, files, calendar)
    CREATE = "create"    # make something new (file, calendar event)
    MODIFY = "modify"    # change something that exists (append to file, reschedule)
    SEND = "send"        # communicate with people (email)
    SHARE = "share"      # give someone access to a file
    DELETE = "delete"    # remove something (email, file, event)
    PAY = "pay"          # move money (Banking suite, later)


class TargetClass(str, Enum):
    """Who an action reaches. Resolved by code from the environment, never by an LLM.

    Precedence when an address matches several: SELF, INTERNAL, CONTACT, EXTERNAL.
    So CONTACT means "a known person outside your organization".
    """

    SELF = "self"            # the user's own account, or no outside person at all
    INTERNAL = "internal"    # same organization (trusted email domain)
    CONTACT = "contact"      # known outside person (in the frozen contact snapshot)
    EXTERNAL = "external"    # anyone else with a valid address
    UNKNOWN = "unknown"      # malformed or suspicious address: never grantable


class Action(BaseModel):
    """A tool call translated into the terms the Wall reasons about."""

    model_config = ConfigDict(frozen=True)

    tool: str
    capability: Capability
    targets: tuple[TargetClass, ...] = (TargetClass.SELF,)
    target_addresses: tuple[str, ...] = ()
    has_attachments: bool = False
    share_permission: str | None = None  # "r" or "rw" for share_file

    @field_validator("targets")
    @classmethod
    def _default_to_self(cls, v: tuple[TargetClass, ...]) -> tuple[TargetClass, ...]:
        return v if v else (TargetClass.SELF,)

    @property
    def fingerprint(self) -> str:
        """Short signature used later by the gatekeeper and memory, e.g. 'send_email:contact'."""
        classes = "+".join(sorted({t.value for t in self.targets}))
        return f"{self.tool}:{classes}"


class WallDecision(str, Enum):
    """Three-way outcome sent to the gatekeeper.

    PASS     every check was verified and no limit is violated.
    DENY     a limit is verifiably violated (DENY wins if there are also unverifiable parts).
    UNKNOWN  nothing is violated, but the Wall could not verify the action. Never executed.
    """

    PASS = "PASS"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


# Codes meaning "could not verify", as opposed to "verified violation".
UNVERIFIABLE_CODES = frozenset({"UNKNOWN_TOOL", "MALFORMED_ARGS", "TARGET_UNVERIFIED", "WALL_ERROR"})


class Verdict(BaseModel):
    """The Wall's answer. `reasons` is empty when allowed, and explains every violation otherwise.

    `codes` carries the same violations in machine-readable form (for logs and the gatekeeper),
    e.g. "TARGET_NOT_ALLOWED:external". `reasons` is the human-readable text.
    `decision` is derived from `allowed` and `codes`, so it can never disagree with them.
    """

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reasons: tuple[str, ...] = ()
    codes: tuple[str, ...] = ()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def decision(self) -> WallDecision:
        if self.allowed:
            return WallDecision.PASS
        if self.codes and all(c in UNVERIFIABLE_CODES for c in self.codes):
            return WallDecision.UNKNOWN
        return WallDecision.DENY
