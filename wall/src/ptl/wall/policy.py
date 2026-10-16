"""The Wall policy: the user's hard limits, checked by plain code.

Design rules:
  1. Deny by default. Only what is explicitly granted is allowed.
  2. Every target of an action must be allowed (strictest target wins).
  3. The policy is frozen. Nothing at runtime, including learning, can change it.
     Only the user can replace it with a new policy, which gets a new fingerprint.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import Action, Capability, TargetClass, Verdict

_SHARE_RANK = {"r": 1, "rw": 2}


def normalize_share_permission(value: object) -> str:
    """Map AgentDojo's SharingPermission (or a string) to 'r' or 'rw'. Unknown -> 'rw' (fail closed)."""
    text = str(getattr(value, "value", value)).strip().lower()
    return text if text in _SHARE_RANK else "rw"


class Grant(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    capability: Capability
    targets: frozenset[TargetClass]

    @field_validator("targets")
    @classmethod
    def _no_unknown(cls, v: frozenset[TargetClass]) -> frozenset[TargetClass]:
        if TargetClass.UNKNOWN in v:
            raise ValueError("'unknown' targets can never be granted")
        if not v:
            raise ValueError("a grant must list at least one target class")
        return v


class WallPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = 1
    description: str = ""
    grants: tuple[Grant, ...] = ()
    forbidden_tools: frozenset[str] = frozenset()
    attachments_allowed_to: frozenset[TargetClass] = frozenset()
    max_recipients: int | None = Field(default=None, ge=1)
    max_share_permission: Literal["r", "rw"] = "r"

    @model_validator(mode="after")
    def _validate(self) -> "WallPolicy":
        caps = [g.capability for g in self.grants]
        dupes = {c.value for c in caps if caps.count(c) > 1}
        if dupes:
            raise ValueError(f"each capability may be granted once; duplicated: {sorted(dupes)}")
        if TargetClass.UNKNOWN in self.attachments_allowed_to:
            raise ValueError("attachments can never be allowed to 'unknown' targets")
        return self

    # ------------------------------------------------------------------ queries
    def allowed_targets(self, capability: Capability) -> frozenset[TargetClass]:
        for g in self.grants:
            if g.capability == capability:
                return g.targets
        return frozenset()

    def check(self, action: Action) -> Verdict:
        reasons: list[str] = []
        codes: list[str] = []

        if action.tool in self.forbidden_tools:
            reasons.append(f"tool '{action.tool}' is forbidden")
            codes.append("TOOL_FORBIDDEN")

        allowed = self.allowed_targets(action.capability)
        if not allowed:
            reasons.append(f"capability '{action.capability.value}' is not allowed")
            codes.append(f"CAPABILITY_NOT_GRANTED:{action.capability.value}")
        else:
            bad = sorted({t.value for t in action.targets if t not in allowed and t is not TargetClass.UNKNOWN})
            if bad:
                reasons.append(f"'{action.capability.value}' is not allowed to: {', '.join(bad)}")
                codes.extend(f"TARGET_NOT_ALLOWED:{b}" for b in bad)

        if action.has_attachments:
            bad = sorted({
                t.value for t in action.targets
                if t not in self.attachments_allowed_to and t is not TargetClass.UNKNOWN
            })
            if bad:
                reasons.append(f"attachments are not allowed to: {', '.join(bad)}")
                codes.extend(f"ATTACHMENT_NOT_ALLOWED:{b}" for b in bad)

        if self.max_recipients is not None and len(action.target_addresses) > self.max_recipients:
            reasons.append(
                f"{len(action.target_addresses)} recipients exceeds the limit of {self.max_recipients}"
            )
            codes.append("TOO_MANY_RECIPIENTS")

        if action.capability == Capability.SHARE:
            level = normalize_share_permission(action.share_permission)
            if _SHARE_RANK[level] > _SHARE_RANK[self.max_share_permission]:
                reasons.append(f"sharing with '{level}' access exceeds '{self.max_share_permission}'")
                codes.append("SHARE_LEVEL_EXCEEDED")

        # Unknown targets (malformed address, no recipient, unknown event/file) are never granted,
        # but they are "could not verify", not a verified violation: the code makes that UNKNOWN.
        n_unknown = sum(1 for t in action.targets if t is TargetClass.UNKNOWN)
        if n_unknown:
            reasons.append(f"could not verify {n_unknown} target(s)")
            codes.append("TARGET_UNVERIFIED")

        return Verdict(allowed=not reasons, reasons=tuple(reasons), codes=tuple(codes))

    # ------------------------------------------------------------------ identity
    def canonical_json(self) -> str:
        data = self.model_dump(mode="json")
        data["grants"] = sorted(
            ({"capability": g["capability"], "targets": sorted(g["targets"])} for g in data["grants"]),
            key=lambda g: g["capability"],
        )
        data["forbidden_tools"] = sorted(data["forbidden_tools"])
        data["attachments_allowed_to"] = sorted(data["attachments_allowed_to"])
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def fingerprint(self) -> str:
        """Stable hash of the policy. Log it with every run to prove the Wall never changed."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()[:16]

    # ------------------------------------------------------------------ for humans
    def explain(self) -> str:
        """Plain-English summary shown to the user to confirm before the Wall is locked."""
        names = {
            TargetClass.SELF: "yourself",
            TargetClass.INTERNAL: "people in your organization",
            TargetClass.CONTACT: "your known outside contacts",
            TargetClass.EXTERNAL: "anyone else",
        }
        order = [TargetClass.SELF, TargetClass.INTERNAL, TargetClass.CONTACT, TargetClass.EXTERNAL]

        def who(ts: frozenset[TargetClass]) -> str:
            return ", ".join(names[t] for t in order if t in ts)

        lines = []
        for cap in Capability:
            ts = self.allowed_targets(cap)
            if not ts:
                lines.append(f"- {cap.value.upper()}: never")
            elif ts == frozenset({TargetClass.SELF}):
                lines.append(f"- {cap.value.upper()}: your own data only")
            else:
                lines.append(f"- {cap.value.upper()}: allowed for {who(ts)}")
        lines.append(
            f"- ATTACHMENTS: {'only to ' + who(self.attachments_allowed_to) if self.attachments_allowed_to else 'never'}"
        )
        if self.max_recipients:
            lines.append(f"- At most {self.max_recipients} recipients per action")
        lines.append(f"- File sharing: at most {'read-only' if self.max_share_permission == 'r' else 'read and write'}")
        if self.forbidden_tools:
            lines.append(f"- Never use: {', '.join(sorted(self.forbidden_tools))}")
        lines.append("- Anything not listed above is blocked.")
        return "\n".join(lines)
