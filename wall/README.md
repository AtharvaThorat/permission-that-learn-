# The Wall

**Layer 1 of Permissions That Learn: the user's fixed limits, checked by plain code before any agent tool call runs.**

An AI agent can be tricked by a hidden instruction in an email, or simply overstep on its own.
The Wall sits outside the agent and checks every proposed tool call against limits the user
set and confirmed, such as *"only email my contacts, never share files outside work, never
delete anything"*. It runs no LLM at check time, so no text the agent reads can talk it out
of a decision. The gatekeeper and the approval memory only ever see actions the Wall has
already passed, and nothing they learn can move it.

```
                     ┌─────────────── THE WALL (this package) ───────────────┐
agent proposes  ───► │ tool call ─► Action ─► who does it reach? ─► policy    │
a tool call          │              (labels)   (frozen snapshot)    check    │
                     └──────────────────────────────┬────────────────────────┘
                              DENY / UNKNOWN        │ PASS
                     "blocked by policy" ◄──────────┤
                      back to the agent             ▼
                                         gatekeeper (ALLOW / ASK / BLOCK)
                                                    │
                                                    ▼
                                  Wall.revalidate(...) right before execution
```

| | |
|---|---|
| **Scope** | AgentDojo Workspace suite (email, calendar, cloud drive): all 24 tools hand-labeled |
| **Output** | `PASS`, `DENY`, or `UNKNOWN`, with readable reasons and stable reason codes |
| **Dependencies** | `pydantic`, `pyyaml`. No model, no network |
| **Tests** | 107 unit, contract and property tests (Python 3.11 and 3.13), plus an end-to-end check inside the AgentDojo harness |
| **Owner** | Atharva (Wall). Gatekeeper: Siddharth. AgentDojo harness: Kaustubh |

---

## Contents

1. [What is built](#what-is-built)
2. [Quick start](#quick-start)
3. [The verdict: PASS, DENY, UNKNOWN](#the-verdict-pass-deny-unknown)
4. [How a call is checked](#how-a-call-is-checked)
5. [Plugging in: harness, gatekeeper, executor](#plugging-in-harness-gatekeeper-executor)
6. [Reason codes](#reason-codes)
7. [Policies and presets](#policies-and-presets)
8. [Changing the limits](#changing-the-limits)
9. [Results on AgentDojo](#results-on-agentdojo)
10. [Guarantees and how they are tested](#guarantees-and-how-they-are-tested)
11. [Known limits](#known-limits)
12. [Project layout](#project-layout)
13. [Status and next steps](#status-and-next-steps)
---

## What is built

Everything below is implemented on `feature/wall`, covered by tests, and passing CI (ruff and
pytest on Python 3.11, also checked on 3.13). "Verified by" names the evidence, so a reader can
check each claim.

### 1. Tool labels for the whole Workspace suite

| | |
|---|---|
| **What** | All 24 AgentDojo Workspace tools hand-labeled with a capability (`read`, `create`, `modify`, `send`, `share`, `delete`), the arguments that name people, the attachment argument, the sharing-level argument, whether a recipient is required, and which event or file the call touches |
| **Where** | `workspace_tools.yaml`, `inventory.py` |
| **Why** | Code tells you what a tool *can* do; the labels say what it means for the user. Labeling by hand avoids trusting an automatic scan |
| **Verified by** | `test_wall.py` checks all 24 are present (14 read, 3 delete). Tool names and argument names were checked against AgentDojo's source (commit 089ed468, suite v1.2.2) |

### 2. Who-does-it-reach classification

| | |
|---|---|
| **What** | Every address in a call is classified as `self`, `internal`, `contact`, `external`, or `unknown` from a frozen snapshot of the user's account, trusted domains, and contacts. Display names (`Bob <bob@x.com>`) and case are normalized; lookalike domains, subdomains, non-ASCII text and several addresses in one string are caught |
| **Where** | `context.py` (`WallContext.classify`, `normalize_address`) |
| **Also built** | Resource labels: rescheduling or cancelling an event, or appending to a file, also counts everyone who can already see it (`event_participants`, `file_collaborators`). `WallContext.from_agentdojo_env()` takes the snapshot from a clean AgentDojo environment |
| **Verified by** | `test_context.py` (8 tests: classes, normalization, lookalikes, malformed input, AgentDojo snapshot); resource cases in `test_integration_contract.py` |

### 3. The policy and the check

| | |
|---|---|
| **What** | `WallPolicy`: a frozen, deny-by-default set of grants (capability to target classes), plus limits on attachments, recipient count (`max_recipients`), and sharing level (`r` or `rw`), and an optional forbidden-tool list. `check()` lists every problem as readable text and as a stable reason code |
| **Where** | `policy.py`, `presets.py` |
| **Presets** | `STRICT_WORKSPACE` (the pitch's limits), `WORKSPACE_RELAXED`, `READ_ONLY`, `ALLOW_ALL` (baseline) |
| **Safety** | `unknown` can never be granted; unknown fields are rejected; each capability is granted once; policies cannot be edited in place; `fingerprint()` hashes the policy so any change is visible; `explain()` prints it in plain English for the user to confirm |
| **Verified by** | `test_wall.py` (21 tests: pitch examples, delete always blocked, one bad recipient blocks the email, sharing rules, policy integrity, fingerprints, `explain`) |

### 4. Three-way verdict: PASS, DENY, UNKNOWN

| | |
|---|---|
| **What** | `Wall.evaluate(tool, args)` returns `PASS`, `DENY` (a verified violation), or `UNKNOWN` (nothing violated, but the Wall cannot verify the call). The decision is derived from the reason codes, so it cannot disagree with them, and `DENY` beats `UNKNOWN` |
| **Fail closed** | `evaluate` never raises: unknown tools, non-dict arguments, malformed or missing recipients, unknown events or files, bad tool names, and internal errors all become `UNKNOWN`, never `PASS` |
| **Where** | `models.py` (`Verdict.decision`, `WallDecision`, `UNVERIFIABLE_CODES`), `wall.py` |
| **Verified by** | `test_decision.py` (23 tests covering each outcome, DENY beating UNKNOWN, internal errors, bad tool names) and a property test that the verdict always matches its codes |

### 5. Gatekeeper contract output

| | |
|---|---|
| **What** | `WallResult.to_gatekeeper(action_id)` emits the exact `wall` object of the gatekeeper contract v0.1: `verdict`, `policy_version`, `evaluated_action_id`, `reason_codes`, and no extra fields. `blocked_message()` gives the text returned to the agent instead of running a blocked tool |
| **Verified by** | `test_integration_contract.py` mirrors the gatekeeper's strict schema and replays the gatekeeper's own 20 fixture cases (using `tests/data/gatekeeper_mock_tools.yaml` for its mock tool names). The Wall matches every policy case; the documented exceptions are GK-019 (`UNKNOWN` by design) and GK-020 (a harness condition) |

### 6. Approval bound to the exact action

| | |
|---|---|
| **What** | `action_digest` hashes the tool plus every argument (key order ignored). `wall_version` combines the policy fingerprint and the snapshot fingerprint. `Wall.revalidate(tool, args, approved=...)` re-runs the Wall right before execution and blocks with `ACTION_CHANGED`, `WALL_VERSION_CHANGED`, or `NOT_PREVIOUSLY_PASSED` |
| **Why** | An approval for "reply to John" cannot be reused for "reply to John and bcc a stranger", or after the user tightens a limit |
| **Verified by** | `test_integration_contract.py` (digest sensitivity, changed body or cc, policy change, contact change, a DENY never becoming a pass) and a property test that `revalidate` is never looser than `evaluate` |

### 7. User-confirmed changes to the limits

| | |
|---|---|
| **What** | `PolicyHistory`: an append-only list of policy versions. `replace()` refuses unless `confirmed` is exactly `True`. `WallContext.with_contacts()` is the user step for adding a contact. Both change `wall_version`, so old approvals stop working |
| **Where** | `versioning.py`, `context.py` |
| **Verified by** | `test_integration_contract.py` (confirmation required, versions increase, identical resubmission still versioned, contact addition changes the version) |

### 8. Plain-English policy drafting

| | |
|---|---|
| **What** | `draft_policy(text, llm=...)` asks any LLM (a plain `str -> str` function) to turn the user's own words into a policy once, before the agent runs. Output is strictly validated: non-JSON, unknown fields, or `unknown` targets raise `PolicyDraftError`. The user confirms `explain()` before it is used |
| **Where** | `from_text.py`; `scripts/check_draft_policy.py` sends 10 phrasings to an OpenAI-compatible endpoint and flags any draft looser than `STRICT_WORKSPACE` |
| **Verified by** | `test_from_text.py` (8 tests with a stubbed LLM). **Not yet run with a real model** |

### 9. Replay against AgentDojo and labeled actions

| | |
|---|---|
| **What** | `scripts/replay_agentdojo.py` runs every Workspace user task (40) and injection task (14) through the Wall under each preset, without an LLM. Injection tasks 6 to 13 ship no reference calls, so their essential calls were reconstructed from each goal's text |
| **Output** | `benchmarks/agentdojo_workspace_v1.2.2_wall_labels.jsonl`: 504 calls (376 AgentDojo reference calls, 128 reconstructed), each with its verdict in gatekeeper format. Reusable as labeled actions for the gatekeeper and the evaluation |
| **Result** | Strict limits stop all 14 injection goals and block 11 of 40 honest tasks; see [Results on AgentDojo](#results-on-agentdojo). These numbers were rechecked against the committed labels file |

### 10. Property tests and CI

| | |
|---|---|
| **What** | Seven guarantees checked on 3,000 seeded random cases each, and again under Hypothesis: deny by default, `unknown` never allowed, a weaker policy never allows more, allowed means every target was granted, deterministic results, `revalidate` never looser than `evaluate`, verdict matches codes |
| **CI** | `.github/workflows/wall-ci.yml` runs `ruff check .` and `pytest -q` on Python 3.11 for every change under `wall/` |
| **Count** | 107 tests: `test_wall.py` 21, `test_decision.py` 23, `test_integration_contract.py` 22, `test_harness.py` 11 (one runs only where the harness is installed), `test_context.py` 8, `test_from_text.py` 8, `test_properties.py` 7, `test_properties_hypothesis.py` 7 |

### 11. Adapter for the AgentDojo harness

| | |
|---|---|
| **What** | `HarnessWall` plugs the Wall into the AgentDojo black-box harness (branch `feature/agentdojo-blackbox`) in place of its stand-in `ReferenceWall`. It implements the harness's `Wall` protocol: a `version` property and `evaluate(BoundAction) -> WallVerdict` |
| **Mapping** | PASS to `PASS` (reason `WALL_PASS`); DENY to `DENY`; UNKNOWN to `UNRESOLVED` (the harness's name for it), with the codes in `missing`. The reason string is the Wall's codes joined by `;`, and the agent sees it as `PermissionError: <codes>`. An action bound under another wall version is `DENY` with `WALL_VERSION_CHANGED` |
| **Snapshot** | `HarnessWall.for_agentdojo_workspace(policy)` takes the trust snapshot once from AgentDojo's clean default Workspace environment. Every Workspace task starts from that same state (injection tasks only change text), so one snapshot is correct for all of them, and its fingerprint matches the replay labels (`e874a3bafdaf87b7.fe26418d8c589b4b`) |
| **Confirmation** | `confirm_capabilities` (empty by default) marks PASS actions that still need the user, which the harness turns into ASK |
| **Where** | `harness.py` (imports no harness code at load time), `scripts/check_in_harness.py` |
| **Verified by** | `test_harness.py` (11 tests, against stand-ins with the harness's field layout, plus one against the real `blackbox.contracts`). `scripts/check_in_harness.py` runs the Wall inside the real harness pipeline on real AgentDojo v1.2.2 tools with a scripted agent: **8 of 8 scenarios as expected**. Reads and an email to a colleague run; exfiltration to the attacker, delete, cancel, and `rw` sharing are `DENY`; no or malformed recipient is `UNRESOLVED`; and no blocked call changed the environment. The harness's own 75 tests also pass at that branch |

### What is not built or not verified yet

| Item | Status |
|---|---|
| Running with a real acting model | Not yet. The Wall now runs inside the harness pipeline (item 11), but only with a scripted agent. No real model's choices have gone through it yet |
| Harness using the Wall by default | Not yet. The harness still defaults to its `ReferenceWall`; it needs `Dependencies(wall=HarnessWall...)` or a config option, on the harness side |
| A real proposed call from the team's acting model | Not yet run through `evaluate`; planned for the Oct 17 checkpoint |
| Gatekeeper handling `UNKNOWN` end to end | The gatekeeper's schema accepts it; its decision logic for `UNKNOWN` is not yet confirmed |
| AgentDojo tool names in the gatekeeper | The gatekeeper's fixtures use mock names (`email.send`); the live pipeline needs AgentDojo names (`send_email`) |
| `draft_policy` with a real LLM | Built and unit-tested with a stub; `scripts/check_draft_policy.py` has not been run with an API key |
| Reading content (email bodies, file text) | Not built, by design. Content attacks to allowed people are the gatekeeper's job |
| Suites other than Workspace | Not built. Banking (a `pay` capability with amount limits) is a stretch goal |

---


## Quick start

```bash
cd wall
uv venv --python 3.11 && source .venv/bin/activate      # or: python -m venv .venv
uv pip install -e ".[dev]"                               # or: pip install -e ".[dev]"
pytest -q                                                # 107 tests, includes Hypothesis properties
python examples/demo.py                                  # the pitch examples, live
```

```python
from ptl.wall import STRICT_WORKSPACE, Wall, WallContext

ctx = WallContext.for_account("emma.johnson@bluesparrowtech.com", contacts=["john.doe@gmail.com"])
wall = Wall(STRICT_WORKSPACE, ctx)

# An injected instruction tries to send files to a stranger
r = wall.evaluate("send_email", {
    "recipients": ["records@outside-audit.com"], "subject": "Q3", "body": "As requested",
    "attachments": [{"type": "file", "file_id": "13"}],
})

r.verdict.decision      # WallDecision.DENY
r.verdict.reasons       # ("'send' is not allowed to: external", "attachments are not allowed to: external")
r.verdict.codes         # ("TARGET_NOT_ALLOWED:external", "ATTACHMENT_NOT_ALLOWED:external")
r.action.fingerprint    # "send_email:external"   coarse key, used later by the memory
r.action_digest         # hash of the exact call (every argument), binds an approval to it
r.wall_version          # policy hash + trust-snapshot hash, log it with every decision
r.to_gatekeeper("A-17") # the `wall` object of the gatekeeper contract v0.1
r.blocked_message()     # text to return to the agent instead of running the tool
```

---

## The verdict: PASS, DENY, UNKNOWN

| Verdict | Meaning | Examples (`STRICT_WORKSPACE`) | What happens |
|---|---|---|---|
| `PASS` | Every check was verified; no limit is violated | read unread emails; reply to a contact; share read-only with a colleague | Goes to the gatekeeper |
| `DENY` | A limit is verifiably violated | delete anything; email a stranger; attach a file for an outsider; share with `rw`; a lookalike domain | Blocked. The user is never asked |
| `UNKNOWN` | Nothing is violated, but the Wall cannot verify the action | an unknown tool; a malformed address; a send or share with no recipient; arguments that are not a dict; an event or file not in the snapshot; an internal error | Blocked. Never executed |

How the decision is made:

- It is **derived** from `allowed` and the reason codes, so the three can never disagree.
  `PASS` carries no codes. `UNKNOWN` means *every* code is one of the "could not verify" codes
  (`UNKNOWN_TOOL`, `MALFORMED_ARGS`, `TARGET_UNVERIFIED`, `WALL_ERROR`). Anything else is `DENY`.
- **`DENY` beats `UNKNOWN`.** An email to one malformed address and one stranger is `DENY`,
  and both problems are listed.
- **Only `PASS` may ever execute.** Neither a user approval nor anything the memory learns turns
  `DENY` or `UNKNOWN` into `PASS`. The two are kept apart only so the logs and the evaluation can
  tell "the agent broke a rule" from "the agent produced something unverifiable".
- **`evaluate` never raises.** A bug inside the Wall becomes `UNKNOWN` with `WALL_ERROR`, never a pass.

> **Team decision to confirm:** `UNKNOWN` is currently handled exactly like `DENY` (returned to
> the agent as blocked). If the team ever wants to show `UNKNOWN` to the user instead, that change
> belongs in the harness, and the executor must still refuse anything that is not `PASS`.

---

## How a call is checked

**1. Tool call to Action** (`wall.py`, `inventory.py`, `workspace_tools.yaml`). Each Workspace
tool is hand-labeled with what it does and which arguments name people.

| Capability | Workspace tools |
|---|---|
| `read` | 14 tools: get or search emails, contacts, calendar, files |
| `create` | `create_calendar_event` (participants), `create_file` |
| `modify` | `reschedule_calendar_event`, `add_calendar_event_participants`, `append_to_file` |
| `send` | `send_email` (recipients, cc, bcc; attachments) |
| `share` | `share_file` (email; permission `r` or `rw`) |
| `delete` | `delete_email`, `delete_file`, `cancel_calendar_event` |

**2. Who does it reach?** (`context.py`). Every address is classified by code against a frozen
snapshot taken when the user confirms the Wall:

| Target | Meaning | Precedence |
|---|---|---|
| `self` | the user's own account, or no outside person | 1 |
| `internal` | exact match on a trusted domain (the user's own, by default) | 2 |
| `contact` | a known outside person in the contact snapshot | 3 |
| `external` | any other valid address | 4 |
| `unknown` | malformed, non-ASCII, several addresses in one string, or no recipient at all | never grantable |

**3. Who else does it reach?** (resource labels). Rescheduling or cancelling an event emails
every participant, and appending to a file changes it for every collaborator. For these tools
the Wall also counts the people who can already see the event or file, from the clean-environment
snapshot (`event_participants`, `file_collaborators`). An ID that is not in the snapshot becomes
`unknown`.

**4. The policy check** (`policy.py`). A `WallPolicy` grants each capability to a set of target
classes, and adds limits on attachments, recipient count, and sharing level. Every problem is
reported twice: as readable text (`reasons`) and as a stable code (`codes`).

---

## Plugging in: harness, gatekeeper, executor

The Wall runs **twice** per action: when the agent proposes it, and again right before the
executor runs it.

```python
from ptl.wall import Wall, WallContext, WallDecision

# Once per task, from the CLEAN pre-environment, before the agent runs
ctx = WallContext.from_agentdojo_env(pre_environment)    # contacts, event participants, file collaborators
wall = Wall(policy_history.current.policy, ctx)

# 1. The agent proposes a tool call
result = wall.evaluate(call.function, dict(call.args))
log(action_id, result.to_gatekeeper(action_id))
if result.verdict.decision is not WallDecision.PASS:
    tool_output = result.blocked_message()               # DENY or UNKNOWN: do not execute, do not ask
else:
    request["wall"] = result.to_gatekeeper(action_id)     # gatekeeper contract v0.1
    decision = gatekeeper.evaluate(request)               # ALLOW / ASK / BLOCK

# 2. Right before executing an ALLOW, or an ASK the user approved
check = wall.revalidate(call.function, dict(call.args), approved=result)
if check.allowed:
    run_tool(call)
# Otherwise check.codes says why: ACTION_CHANGED, WALL_VERSION_CHANGED, NOT_PREVIOUSLY_PASSED
```

**In the AgentDojo harness** (branch `feature/agentdojo-blackbox`), pass the Wall in through the
harness's dependencies instead of its stand-in `ReferenceWall`:

```python
from blackbox.contracts import Dependencies
from blackbox.factory import build_agentdojo_pipeline
from ptl.wall import STRICT_WORKSPACE
from ptl.wall.harness import HarnessWall

wall = HarnessWall.for_agentdojo_workspace(STRICT_WORKSPACE)      # one clean snapshot, all tasks
pipeline = build_agentdojo_pipeline("configs/blackbox/wall_only.json", Dependencies(wall=wall))
```

The harness then binds each call, asks the Wall, stops anything that is not `PASS`, and rechecks
the Wall before execution. `python scripts/check_in_harness.py` (with the harness on
`PYTHONPATH`) runs the 8-scenario end-to-end check.

**The gatekeeper object** (`to_gatekeeper`) matches the strict `Wall` schema in the gatekeeper
(`gatekeeper/schemas.py`, contract v0.1). No extra fields:

```json
{
  "verdict": "DENY",
  "policy_version": "e874a3bafdaf87b7.fe26418d8c589b4b",
  "evaluated_action_id": "injection_task_0:0",
  "reason_codes": ["TARGET_NOT_ALLOWED:external"]
}
```

`policy_version` is `wall_version`: the policy fingerprint, a dot, then the trust-snapshot
fingerprint. The harness supplies `action_id`, and it must be the same ID it sends to the
gatekeeper for that action.

**Why approval is bound to the exact action.** `action_digest` hashes the tool and every
argument (key order does not matter, any changed value does). `revalidate` re-runs the Wall and
blocks if the digest, the policy, or the trust snapshot changed since the earlier check. So an
approval for "reply to John" cannot be reused for "reply to John, bcc a stranger".

**Take the snapshot once, from the clean environment.** AgentDojo builds `contact_list` from
every address in the starting inbox. Re-reading it mid-run could turn an address from an
attacker's email into a "contact". The starting list already contains a few spam senders (for
example `security-facebook-com@gmail.com`); the injection tasks' attacker address
(`mark.black-2134@gmail.com`) is not among them.

**Checked against AgentDojo.** Field names (`FunctionCall.function`, `.args`, `env.inbox`,
`env.calendar.events`, `env.cloud_drive.files`) were checked against AgentDojo main
(commit 089ed468, June 2026), suite v1.2.2.

**Tool names.** The Wall uses AgentDojo's real names (`send_email`, `share_file`). The
gatekeeper's 20 fixtures use mock names (`email.send`), which are labeled in
`tests/data/gatekeeper_mock_tools.yaml`. The Wall reproduces the fixture verdict for every
policy case. The one deliberate difference is GK-019 (a send with no recipient), where the fixture
says `PASS` to exercise the gatekeeper's own validation and the Wall returns `UNKNOWN`. GK-020 is
"wall unavailable", a harness condition. For the live pipeline, the gatekeeper needs to accept
AgentDojo tool names.

---

## Reason codes

| Code | Verdict | Meaning |
|---|---|---|
| `TOOL_FORBIDDEN` | DENY | The tool is on the policy's forbidden list |
| `CAPABILITY_NOT_GRANTED:<capability>` | DENY | e.g. `CAPABILITY_NOT_GRANTED:delete` |
| `TARGET_NOT_ALLOWED:<class>` | DENY | The action reaches a class the capability is not granted for, e.g. `external` |
| `ATTACHMENT_NOT_ALLOWED:<class>` | DENY | Files or events would go to a class not allowed attachments |
| `TOO_MANY_RECIPIENTS` | DENY | More addresses than `max_recipients` |
| `SHARE_LEVEL_EXCEEDED` | DENY | `rw` sharing when the limit is `r` (a missing or odd level counts as `rw`) |
| `UNKNOWN_TOOL` | UNKNOWN | The tool is not in the inventory |
| `MALFORMED_ARGS` | UNKNOWN | The arguments are not a key/value object |
| `TARGET_UNVERIFIED` | UNKNOWN | A malformed address, no recipient, or an event/file not in the snapshot |
| `WALL_ERROR` | UNKNOWN | An internal error, or a tool name that is not a non-empty string |
| `NOT_PREVIOUSLY_PASSED` | DENY (revalidate) | The earlier result being executed was not a PASS |
| `ACTION_CHANGED` | DENY (revalidate) | The tool or any argument changed after the check |
| `WALL_VERSION_CHANGED` | DENY (revalidate) | The limits or the trust snapshot changed after the check |

`UNVERIFIABLE_CODES` in `models.py` is the single list of codes that mean "could not verify".

---

## Policies and presets

A `WallPolicy` is a frozen Pydantic model. Unknown fields are rejected, `unknown` can never be
granted, and each capability is granted at most once. `explain()` renders it in plain English for
the user to confirm.

| Preset | User's limits in words | Used for |
|---|---|---|
| `STRICT_WORKSPACE` | Handle my email and calendar. Only email people in my contacts. Never share files outside work. Never delete anything. | The pitch example; the main "wall on" setup |
| `WORKSPACE_RELAXED` | Email or invite anyone, but never delete, never send files to strangers, share read-only inside work only. | Studying the safety vs. task-success trade-off |
| `READ_ONLY` | Only read my email, calendar, and files. | Lower bound on automation |
| `ALLOW_ALL` | No limits. | The "no protection" baseline (still blocks `unknown`) |

**Drafting a policy from plain English** (`from_text.py`). An LLM may draft a policy once, from
the user's own words; a human confirms it before it is locked. The LLM is never used at check time.

```python
from ptl.wall import draft_policy
draft = draft_policy("Only email my contacts. Never delete anything.", llm=my_llm_fn)  # any str -> str
print(draft.explain())      # show the user, get a yes, then lock it in
```

Bad or unsafe drafts (unknown fields, `unknown` targets, non-JSON) raise `PolicyDraftError`.
`scripts/check_draft_policy.py` sends 10 phrasings of the pitch's limits to any OpenAI-compatible
endpoint and flags every draft looser than `STRICT_WORKSPACE`.

---

## Changing the limits

```python
from ptl.wall import PolicyHistory

history = PolicyHistory(STRICT_WORKSPACE)                 # v1, confirmed at setup
print(new_policy.explain())                                # show the user
history.replace(new_policy, confirmed=True, note="...")    # v2; raises unless confirmed is exactly True
ctx = ctx.with_contacts("new.client@acme.com")             # the user adds a contact
```

History is append-only, and both changes alter `wall_version`, so `revalidate` rejects any
approval made under the old limits. Only user-facing code may call these. Nothing in the agent,
gatekeeper, or memory path does.

---

## Results on AgentDojo

`scripts/replay_agentdojo.py` runs the reference tool calls AgentDojo ships for every Workspace
task through the Wall, with no LLM involved. Injection tasks 6 to 13 ship no reference calls, so
their essential calls were reconstructed from each task's goal text (marked
`reconstructed_from_goal`).

| Preset | Attacks stopped by the Wall alone | Honest user tasks blocked |
|---|---:|---:|
| `STRICT_WORKSPACE` | 14 / 14 | 11 / 40 |
| `WORKSPACE_RELAXED` | 9 / 14 | 5 / 40 |
| `READ_ONLY` | 14 / 14 | 22 / 40 |
| `ALLOW_ALL` | 0 / 14 | 0 / 40 |

- **Strict limits stop every injection goal**, mostly because each one sends to an outside
  address or deletes something. One caveat: injection task 13 (a phishing link to everyone the
  user meets today) is only partly stopped. Its emails to three outsiders are blocked, but its
  emails to two colleagues pass, because the Wall does not read email bodies. That part is the
  gatekeeper's job.
- **The cost is 11 of 40 honest tasks.** Two are intended ("delete the largest file" under
  "never delete"). The other nine email, invite, or share with people outside the inbox snapshot
  (for example `john.doe@clientcorp.com`). In the full system, these are where the user would
  add a contact or loosen a limit.
- **`WORKSPACE_RELAXED` shows the trade-off:** it blocks 5 honest tasks instead of 11 but lets
  5 attacks through (plain-text exfiltration and the phishing emails).

These are an upper bound on what the Wall stops and a lower bound on what it blocks, since a real
agent can take different paths. `benchmarks/agentdojo_workspace_v1.2.2_wall_labels.jsonl` holds
every replayed call with its verdict in gatekeeper format (504 rows across the 4 presets), for
reuse as labeled actions. None of those rows involve an unverifiable call, so adding `UNKNOWN`
left every one of them unchanged.

```bash
pip install agentdojo
python scripts/replay_agentdojo.py                                   # summary for every preset
python scripts/replay_agentdojo.py --policy STRICT_WORKSPACE --details
python scripts/replay_agentdojo.py --jsonl results/wall_labels.jsonl
```

---

## Guarantees and how they are tested

1. **Deny by default.** Anything not explicitly granted is blocked.
2. **Every target must pass.** One external address in `bcc` blocks the whole email.
3. **Fail closed.** Malformed input is `UNKNOWN`, an odd share level counts as `rw`, an internal error is `UNKNOWN`.
4. **Exact domains only.** `bluesparrowtech.com.evil.com` and subdomains are not internal.
5. **Frozen.** Policies are immutable. Only the user replaces one, and that changes its fingerprint.
6. **Bound to the exact action.** Any change to the tool, an argument, the policy, or the snapshot invalidates an earlier check.
7. **Explainable.** Every block lists every reason and code.
8. **No LLM at check time.** Injected text has no path into a decision.

Property tests (`tests/test_properties.py`: 3,000 seeded random cases per property, plus the same
properties under Hypothesis) check that: an empty policy denies everything; `unknown` targets are
never allowed; a weaker policy never allows more; an allowed action had every target granted;
results are deterministic and leave the policy unchanged; `revalidate` is never looser than
`evaluate`; and the verdict always matches its codes.

| Test file | Covers |
|---|---|
| `test_wall.py` | Pitch examples, inventory, sharing rules, policy integrity, fingerprints |
| `test_context.py` | Address normalization and classification, lookalike domains, AgentDojo snapshot |
| `test_decision.py` | PASS / DENY / UNKNOWN, DENY beats UNKNOWN, fail-closed errors |
| `test_integration_contract.py` | Gatekeeper contract v0.1, the 20 gatekeeper fixtures, binding, revalidation, resource labels, versioning |
| `test_from_text.py` | Validation of LLM-drafted policies |
| `test_properties*.py` | The guarantees above, on random inputs |

---

## Known limits

- **The Wall checks who and what, not content.** It never reads email bodies or file contents, by
  design, so injected text cannot influence it. Content attacks sent to allowed people (injection
  task 13) are left to the gatekeeper.
- **Objects created mid-run are not in the snapshot**, so modifying them afterwards is `UNKNOWN`
  (fail closed). No AgentDojo reference solution does this.
- **The starting contacts are AgentDojo's**, which include a few spam senders. The Wall trusts the
  snapshot it is given; a curated contact list would be stricter.
- **Only the Workspace suite is labeled.** Banking (a `pay` capability with amount limits) is a
  stretch goal.
- **Not yet run with a real acting model.** Results above come from replayed reference calls and a
  scripted agent inside the harness.

---

## Project layout

```
wall/
├── src/ptl/wall/
│   ├── models.py             Capability, TargetClass, Action, Verdict, WallDecision, UNVERIFIABLE_CODES
│   ├── workspace_tools.yaml  hand labels for all 24 Workspace tools, incl. resource labels
│   ├── inventory.py          loads the labels (cached)
│   ├── context.py            address classification, trust and resource snapshot, with_contacts()
│   ├── policy.py             WallPolicy, Grant, check(), fingerprint(), explain()
│   ├── wall.py               Wall.evaluate() / revalidate(), WallResult.to_gatekeeper(), action_digest()
│   ├── versioning.py         PolicyHistory: append-only, user-confirmed policy versions
│   ├── from_text.py          plain English to a draft policy via an LLM, validated
│   ├── presets.py            STRICT_WORKSPACE, WORKSPACE_RELAXED, READ_ONLY, ALLOW_ALL
│   └── harness.py            HarnessWall: the Wall behind the AgentDojo harness's Wall protocol
├── scripts/
│   ├── replay_agentdojo.py   replay AgentDojo reference calls through the Wall (needs agentdojo)
│   ├── check_in_harness.py   run the Wall inside the harness on real tools (needs the harness branch)
│   └── check_draft_policy.py test plain-English drafting with a real LLM (needs openai and a key)
├── benchmarks/               replay output: labeled wall verdicts for every Workspace task
├── tests/                    unit, contract, and property tests (+ gatekeeper fixtures in tests/data/)
└── examples/demo.py          the pitch examples
```

CI (`.github/workflows/wall-ci.yml`) runs `ruff check .` and `pytest -q` on Python 3.11 for any
change under `wall/`.

---

## Status and next steps

**Done:** see [What is built](#what-is-built) for each component and its evidence.

**Next:**

1. Agree with the harness on the first email/calendar task, and run a real proposed tool call from
   it through `evaluate` (Oct 17 checkpoint).
2. Confirm with the gatekeeper that `UNKNOWN` is accepted end to end and that AgentDojo tool names
   are supported.
3. Have the harness use `HarnessWall` by default (a `Dependencies(wall=...)` call or a config
   option on the harness side), then run real tasks with the acting model and compare with the replay.
4. Run `scripts/check_draft_policy.py` with a real model and record the result.
