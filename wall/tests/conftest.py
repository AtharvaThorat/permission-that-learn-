import pytest

from ptl.wall import STRICT_WORKSPACE, Wall, WallContext

from .constants import ACCOUNT, CONTACT


@pytest.fixture
def ctx() -> WallContext:
    return WallContext.for_account(ACCOUNT, contacts=[CONTACT])


@pytest.fixture
def wall(ctx: WallContext) -> Wall:
    return Wall(STRICT_WORKSPACE, ctx)
