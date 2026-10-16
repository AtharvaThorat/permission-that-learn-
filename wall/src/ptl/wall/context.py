"""Who is who: classify an email address into a TargetClass.

Security rules followed here:
  * Classification is pure code over a frozen snapshot. No LLM, no reading of email bodies.
  * Exact domain match only. "bluesparrowtech.com.evil.com" is NOT internal.
  * Anything odd (non-ASCII, several addresses in one string, bad format) is UNKNOWN,
    and UNKNOWN can never be granted, so odd input always fails closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, field_validator

from .models import TargetClass

_EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)+$")
_ANGLE_RE = re.compile(r"<([^<>]*)>")


def normalize_address(raw: object) -> str | None:
    """Return a clean lowercase address, or None if it is not exactly one valid address."""
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    angle = _ANGLE_RE.findall(text)
    if len(angle) > 1:
        return None
    if len(angle) == 1:                     # "Bob Smith <bob@x.com>"
        text = angle[0].strip()
    text = text.lower()
    if not text.isascii() or not _EMAIL_RE.match(text):
        return None
    return text


class WallContext(BaseModel):
    """A frozen snapshot of who the user trusts, taken when the user confirms the Wall.

    It also snapshots who can already see each calendar event and file (resource labels),
    so that modifying a shared event or file counts as reaching those people.
    """

    model_config = ConfigDict(frozen=True)

    account_email: str
    trusted_contacts: frozenset[str] = frozenset()
    trusted_domains: frozenset[str] = frozenset()
    event_participants: dict[str, frozenset[str]] | None = None   # event_id -> participant addresses
    file_collaborators: dict[str, frozenset[str]] | None = None   # file_id -> owner + shared_with

    @field_validator("account_email")
    @classmethod
    def _clean_account(cls, v: str) -> str:
        clean = normalize_address(v)
        if clean is None:
            raise ValueError(f"invalid account email: {v!r}")
        return clean

    @field_validator("trusted_contacts")
    @classmethod
    def _clean_contacts(cls, v: frozenset[str]) -> frozenset[str]:
        return frozenset(a for a in (normalize_address(x) for x in v) if a)

    @field_validator("trusted_domains")
    @classmethod
    def _clean_domains(cls, v: frozenset[str]) -> frozenset[str]:
        return frozenset(d.strip().lower() for d in v if d and d.strip())

    @field_validator("event_participants", "file_collaborators")
    @classmethod
    def _clean_resources(cls, v: dict | None) -> dict[str, frozenset[str]] | None:
        if v is None:
            return None
        # Keep raw strings so a malformed address still classifies as UNKNOWN (fail closed).
        return {str(k): frozenset(str(a).strip() for a in people) for k, people in v.items()}

    def resource_people(self, kind: str, resource_id: object) -> frozenset[str] | None:
        """People who can already see this event/file, or None if the resource is not in the snapshot.

        None means "unknown resource": the Wall treats it as an UNKNOWN target and fails closed.
        If no snapshot was taken at all (the mapping is None), resources are not modeled and the
        action is treated as touching only the user's own data, as before.
        """
        table = self.event_participants if kind == "event" else self.file_collaborators
        if table is None:
            return frozenset()
        return table.get(str(resource_id))

    def fingerprint(self) -> str:
        """Stable hash of the trust snapshot. Changes when the user adds a contact or domain."""
        data = {
            "account_email": self.account_email,
            "trusted_contacts": sorted(self.trusted_contacts),
            "trusted_domains": sorted(self.trusted_domains),
            "event_participants": None if self.event_participants is None
            else {k: sorted(v) for k, v in sorted(self.event_participants.items())},
            "file_collaborators": None if self.file_collaborators is None
            else {k: sorted(v) for k, v in sorted(self.file_collaborators.items())},
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]

    def with_contacts(self, *addresses: str) -> WallContext:
        """Return a new context with extra trusted contacts.

        Call this only from a user-facing step (the user adds a contact and confirms). The agent
        must never be able to call it. The new context has a new fingerprint, so approvals made
        under the old one are not silently reused.
        """
        added = {normalize_address(a) for a in addresses}
        if None in added:
            raise ValueError(f"invalid contact address in {addresses!r}")
        return self.model_copy(update={"trusted_contacts": self.trusted_contacts | frozenset(added)})

    def classify(self, raw: object) -> TargetClass:
        addr = normalize_address(raw)
        if addr is None:
            return TargetClass.UNKNOWN
        if addr == self.account_email:
            return TargetClass.SELF
        domain = addr.rsplit("@", 1)[1]
        if domain in self.trusted_domains:
            return TargetClass.INTERNAL
        if addr in self.trusted_contacts:
            return TargetClass.CONTACT
        return TargetClass.EXTERNAL

    @classmethod
    def for_account(
        cls,
        account_email: str,
        contacts: Iterable[str] = (),
        extra_domains: Iterable[str] = (),
        trust_own_domain: bool = True,
    ) -> WallContext:
        acct = normalize_address(account_email)
        if acct is None:
            raise ValueError(f"invalid account email: {account_email!r}")
        domains = set(extra_domains)
        if trust_own_domain:
            domains.add(acct.rsplit("@", 1)[1])
        return cls(
            account_email=acct,
            trusted_contacts=frozenset(contacts),
            trusted_domains=frozenset(domains),
        )

    @classmethod
    def from_agentdojo_env(cls, env: object, extra_domains: Iterable[str] = ()) -> WallContext:
        """Snapshot an AgentDojo Workspace environment.

        Reads env.inbox.account_email and env.inbox.contact_list, plus, when present,
        env.calendar.events (participants) and env.cloud_drive.files (owner, shared_with).

        Take this snapshot ONCE, at the start, from the clean pre-environment. AgentDojo
        auto-builds contact_list from email participants, so re-reading it mid-run could
        let an address that appeared in an attacker's email become a "contact".
        """
        inbox = env.inbox
        contacts = [str(getattr(c, "email", "")) for c in getattr(inbox, "contact_list", [])]
        base = cls.for_account(str(inbox.account_email), contacts, extra_domains)

        update: dict = {}
        calendar = getattr(env, "calendar", None)
        if calendar is not None:
            update["event_participants"] = {
                str(eid): frozenset(str(p) for p in getattr(ev, "participants", []))
                for eid, ev in getattr(calendar, "events", {}).items()
            }
        drive = getattr(env, "cloud_drive", None)
        if drive is not None:
            update["file_collaborators"] = {
                str(fid): frozenset([str(f.owner), *(str(p) for p in getattr(f, "shared_with", {}))])
                for fid, f in getattr(drive, "files", {}).items()
            }
        return cls.model_validate({**base.model_dump(), **update}) if update else base
