"""Same properties as test_properties.py, driven by Hypothesis (skipped if it is not installed)."""

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from .test_properties import PROPERTIES  # noqa: E402


@pytest.mark.parametrize("prop", PROPERTIES, ids=lambda p: p.__name__)
@settings(max_examples=500, deadline=None)
@given(rng=st.randoms(use_true_random=False))
def test_property(prop, rng):
    prop(rng)
