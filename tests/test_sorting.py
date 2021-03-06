import pytest

from brownie.test import given, strategy
from brownie.convert.datatypes import EthAddress

@pytest.mark.xfail
@given(strategy('uint256[]', max_value=0xffffffffffffffffffffffffffffffffffffffff))
def test_sorting_checksum(addrs):
    addrs = [EthAddress(addr.to_bytes(20, 'big', signed=False)) for addr in addrs]
    
    sort_old = sorted(addrs)
    sort_new = sorted(addrs, key=lambda addr: int(addr, 16))

    assert sort_old == sort_new


@given(strategy('uint256[]', max_value=0xffffffffffffffffffffffffffffffffffffffff))
def test_sorting_lower(addrs):
    addrs = [EthAddress(addr.to_bytes(20, 'big', signed=False)) for addr in addrs]
    
    sort_old = sorted(addrs, key=lambda addr: addr.lower())
    sort_new = sorted(addrs, key=lambda addr: int(addr, 16))

    assert sort_old == sort_new

