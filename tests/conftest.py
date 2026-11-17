import asyncio

import pytest

from penumbra.engine import Investigation


@pytest.fixture(scope="module")
def closed_inv():
    inv = Investigation(backend="offline")
    asyncio.run(inv.run())
    return inv


def run_inv(**kw) -> Investigation:
    inv = Investigation(backend="offline", **kw)
    asyncio.run(inv.run())
    return inv
