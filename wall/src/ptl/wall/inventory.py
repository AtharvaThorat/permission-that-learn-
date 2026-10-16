"""Tool inventory: which capability each tool has and which arguments name people."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from .models import Capability


class ToolSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    capability: Capability
    target_args: tuple[str, ...] = ()
    attachment_arg: str | None = None
    permission_arg: str | None = None
    resource_arg: str | None = None                      # argument naming an existing event/file
    resource_kind: Literal["event", "file"] | None = None  # who can already see it reaches via this action
    requires_target: bool = False                         # e.g. send/share: no recipient means malformed

    @model_validator(mode="after")
    def _resource_pair(self) -> ToolSpec:
        if (self.resource_arg is None) != (self.resource_kind is None):
            raise ValueError(f"{self.name}: resource_arg and resource_kind must be set together")
        return self


class ToolInventory(BaseModel):
    model_config = ConfigDict(frozen=True)

    suite: str
    tools: dict[str, ToolSpec]

    def get(self, name: str) -> ToolSpec | None:
        return self.tools.get(name)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ToolInventory:
        return cls._from_dict(yaml.safe_load(Path(path).read_text()))

    @classmethod
    def workspace(cls) -> ToolInventory:
        """The bundled, hand-labeled inventory for AgentDojo's Workspace suite (loaded once, cached)."""
        return _load_workspace()

    @classmethod
    def _from_dict(cls, data: dict) -> ToolInventory:
        tools = {
            name: ToolSpec(name=name, **(spec or {}))
            for name, spec in data["tools"].items()
        }
        return cls(suite=data["suite"], tools=tools)


@lru_cache(maxsize=1)
def _load_workspace() -> ToolInventory:
    text = resources.files("ptl.wall").joinpath("workspace_tools.yaml").read_text()
    return ToolInventory._from_dict(yaml.safe_load(text))
