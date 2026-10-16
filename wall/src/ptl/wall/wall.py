"""The Wall: turn a raw tool call into an Action and check it against the frozen policy."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict

from .context import WallContext
from .inventory import ToolInventory
from .models import Action, TargetClass, Verdict
from .policy import WallPolicy, normalize_share_permission


class UnknownToolError(KeyError):
    """Raised when a tool is not in the inventory. The Wall treats this as a block."""


def action_digest(tool: str, args: Mapping[str, Any]) -> str:
    """Hash of the exact tool call (tool + every argument). Binds an approval to this one action.

    Any change to any argument, including the email body, gives a different digest.
    """
    canonical = json.dumps({"tool": tool, "args": args}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


class WallResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool: str
    action: Action | None
    verdict: Verdict
    policy_fingerprint: str
    context_fingerprint: str = ""
    action_digest: str = ""

    @property
    def wall_version(self) -> str:
        """One opaque string for "which limits and which trust snapshot made this decision"."""
        return f"{self.policy_fingerprint}.{self.context_fingerprint}"

    def to_gatekeeper(self, action_id: str) -> dict:
        """The `wall` object of the gatekeeper contract (data/gatekeeper_contract.md, v0.1).

        PASS / DENY / UNKNOWN, `policy_version`, `evaluated_action_id`, `reason_codes`. The harness
        supplies `action_id`; it must be the same ID it sends to the gatekeeper for this action.
        """
        if not action_id:
            raise ValueError("action_id is required")
        return {
            "verdict": self.verdict.decision.value,
            "policy_version": self.wall_version,
            "evaluated_action_id": action_id,
            "reason_codes": list(self.verdict.codes),
        }

    def blocked_message(self) -> str:
        """Text to return to the agent instead of running the tool. Lists reasons, not the policy."""
        return f"Blocked by policy: the '{self.tool}' call was not run ({'; '.join(self.verdict.reasons)})."


class Wall:
    """Deterministic gate. Same tool call + same policy + same context = same verdict, always."""

    def __init__(self, policy: WallPolicy, context: WallContext, inventory: ToolInventory | None = None):
        self._policy = policy
        self._context = context
        self._inventory = inventory or ToolInventory.workspace()
        self._fingerprint = policy.fingerprint()
        self._context_fingerprint = context.fingerprint()

    @property
    def policy(self) -> WallPolicy:
        return self._policy

    @property
    def context(self) -> WallContext:
        return self._context

    @property
    def fingerprint(self) -> str:
        return self._fingerprint

    @property
    def version(self) -> str:
        return f"{self._fingerprint}.{self._context_fingerprint}"

    def to_action(self, tool: str, args: Mapping[str, Any]) -> Action:
        spec = self._inventory.get(tool)
        if spec is None:
            raise UnknownToolError(tool)

        addresses: list[str] = []
        targets: list[TargetClass] = []

        def add(raw: object) -> None:
            addresses.append(str(raw))
            targets.append(self._context.classify(raw))

        for arg in spec.target_args:
            value = args.get(arg)
            if value is None:
                continue
            items = value if isinstance(value, (list, tuple)) else [value]
            for item in items:
                add(item)

        if spec.requires_target and not targets:
            targets.append(TargetClass.UNKNOWN)            # e.g. an email with no recipient

        if spec.resource_arg is not None:
            people = self._context.resource_people(spec.resource_kind, args.get(spec.resource_arg))
            if people is None:
                targets.append(TargetClass.UNKNOWN)        # unknown event/file: fail closed
            else:
                for person in sorted(people):
                    if self._context.classify(person) is not TargetClass.SELF:
                        targets.append(self._context.classify(person))

        has_attachments = bool(args.get(spec.attachment_arg)) if spec.attachment_arg else False
        permission = (
            normalize_share_permission(args.get(spec.permission_arg)) if spec.permission_arg else None
        )
        return Action(
            tool=tool,
            capability=spec.capability,
            targets=tuple(targets),
            target_addresses=tuple(addresses),
            has_attachments=has_attachments,
            share_permission=permission,
        )

    def evaluate(self, tool: str, args: Mapping[str, Any] | None = None) -> WallResult:
        """Check one proposed tool call. Never raises: anything the Wall cannot handle is UNKNOWN."""
        try:
            return self._evaluate(tool, args)
        except Exception as exc:  # fail closed: a bug in the Wall must never become a PASS
            verdict = Verdict(allowed=False, reasons=(f"wall internal error: {type(exc).__name__}",),
                              codes=("WALL_ERROR",))
            return WallResult(tool=str(tool), action=None, verdict=verdict,
                              policy_fingerprint=self._fingerprint,
                              context_fingerprint=self._context_fingerprint)

    def _evaluate(self, tool: str, args: Mapping[str, Any] | None) -> WallResult:
        args = args or {}
        if not isinstance(tool, str) or not tool:
            raise TypeError("tool name must be a non-empty string")
        common = {
            "tool": tool,
            "policy_fingerprint": self._fingerprint,
            "context_fingerprint": self._context_fingerprint,
        }
        if not isinstance(args, Mapping):
            verdict = Verdict(allowed=False, reasons=("tool arguments are not a mapping",), codes=("MALFORMED_ARGS",))
            return WallResult(action=None, verdict=verdict, **common)
        digest = action_digest(tool, args)
        try:
            action = self.to_action(tool, args)
        except UnknownToolError:
            verdict = Verdict(allowed=False, reasons=(f"unknown tool '{tool}' is not in the inventory",),
                              codes=("UNKNOWN_TOOL",))
            return WallResult(action=None, verdict=verdict, action_digest=digest, **common)
        return WallResult(action=action, verdict=self._policy.check(action), action_digest=digest, **common)

    def revalidate(self, tool: str, args: Mapping[str, Any] | None, approved: WallResult) -> Verdict:
        """Check again right before execution, against an earlier PASS (e.g. one the user approved).

        Blocks if the action changed in any way, if the limits or trust snapshot changed since,
        or if the action no longer passes. Call this in the executor, after the gatekeeper.
        """
        now = self.evaluate(tool, args)
        reasons, codes = list(now.verdict.reasons), list(now.verdict.codes)
        if not approved.verdict.allowed:
            reasons.append("the earlier wall result was not a pass")
            codes.append("NOT_PREVIOUSLY_PASSED")
        if now.action_digest != approved.action_digest or now.tool != approved.tool:
            reasons.append("the action changed after it was checked")
            codes.append("ACTION_CHANGED")
        if now.wall_version != approved.wall_version:
            reasons.append("the user's limits or trust snapshot changed after the check")
            codes.append("WALL_VERSION_CHANGED")
        return Verdict(allowed=not reasons, reasons=tuple(reasons), codes=tuple(codes))
