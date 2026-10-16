"""Property tests: the guarantees the rest of the system relies on.

Seeded random fuzzing, so these always run, even without Hypothesis installed.
test_properties_hypothesis.py runs the same properties with Hypothesis (and shrinking).
"""

import random

from ptl.wall import ALLOW_ALL, UNVERIFIABLE_CODES, TargetClass, Wall, WallContext, WallDecision, WallPolicy, action_digest

from .constants import ACCOUNT, CONTACT
from .generators import gen_call, gen_policy, weaken

CTX = WallContext.for_account(ACCOUNT, contacts=[CONTACT])
N = 3000


def check_deny_by_default(rng):
    tool, args = gen_call(rng)
    assert not Wall(WallPolicy(), CTX).evaluate(tool, args).verdict.allowed


def check_unknown_targets_always_blocked(rng):
    policy = rng.choice([gen_policy(rng), ALLOW_ALL])
    tool, args = gen_call(rng)
    r = Wall(policy, CTX).evaluate(tool, args)
    if r.action and TargetClass.UNKNOWN in r.action.targets:
        assert not r.verdict.allowed


def check_weaker_policy_never_allows_more(rng):
    strong = gen_policy(rng)
    weak = weaken(strong, rng)
    tool, args = gen_call(rng)
    if Wall(weak, CTX).evaluate(tool, args).verdict.allowed:
        assert Wall(strong, CTX).evaluate(tool, args).verdict.allowed


def check_allowed_means_every_target_granted(rng):
    policy = gen_policy(rng)
    tool, args = gen_call(rng)
    r = Wall(policy, CTX).evaluate(tool, args)
    if r.verdict.allowed:
        granted = policy.allowed_targets(r.action.capability)
        assert all(t in granted for t in r.action.targets)
        assert tool not in policy.forbidden_tools


def check_deterministic_and_policy_unchanged(rng):
    policy = gen_policy(rng)
    before = policy.fingerprint()
    wall = Wall(policy, CTX)
    tool, args = gen_call(rng)
    assert wall.evaluate(tool, args).verdict == wall.evaluate(tool, args).verdict
    assert policy.fingerprint() == before


def check_revalidate_never_looser_than_evaluate(rng):
    policy = gen_policy(rng)
    wall = Wall(policy, CTX)
    tool, args = gen_call(rng)
    first = wall.evaluate(tool, args)
    again = wall.revalidate(tool, args, first)
    assert again.allowed == first.verdict.allowed
    other_tool, other_args = gen_call(rng)
    if (other_tool, other_args) != (tool, args) and wall.revalidate(other_tool, other_args, first).allowed:
        assert action_digest(other_tool, other_args) == first.action_digest


def check_decision_matches_codes(rng):
    """PASS only when allowed; UNKNOWN only when every code is 'could not verify'; else DENY."""
    policy = rng.choice([gen_policy(rng), ALLOW_ALL])
    tool, args = gen_call(rng)
    v = Wall(policy, CTX).evaluate(tool, args).verdict
    assert (v.decision is WallDecision.PASS) == v.allowed
    if v.decision is WallDecision.UNKNOWN:
        assert v.codes and set(v.codes) <= UNVERIFIABLE_CODES
    if v.decision is WallDecision.DENY:
        assert set(v.codes) - UNVERIFIABLE_CODES or not v.codes


PROPERTIES = [
    check_deny_by_default,
    check_unknown_targets_always_blocked,
    check_weaker_policy_never_allows_more,
    check_allowed_means_every_target_granted,
    check_deterministic_and_policy_unchanged,
    check_revalidate_never_looser_than_evaluate,
    check_decision_matches_codes,
]


def _fuzz(prop):
    rng = random.Random(1234)
    for _ in range(N):
        prop(rng)


def test_deny_by_default():
    _fuzz(check_deny_by_default)


def test_unknown_targets_always_blocked():
    _fuzz(check_unknown_targets_always_blocked)


def test_weaker_policy_never_allows_more():
    _fuzz(check_weaker_policy_never_allows_more)


def test_allowed_means_every_target_granted():
    _fuzz(check_allowed_means_every_target_granted)


def test_deterministic_and_policy_unchanged():
    _fuzz(check_deterministic_and_policy_unchanged)


def test_revalidate_never_looser_than_evaluate():
    _fuzz(check_revalidate_never_looser_than_evaluate)


def test_decision_matches_codes():
    _fuzz(check_decision_matches_codes)
