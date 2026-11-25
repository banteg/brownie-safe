from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from eth_utils import to_checksum_address
from safe_eth.safe import Safe

import brownie_safe as module

ADDRESS = to_checksum_address('0xaabbcc' + '00' * 17)


class CustomSafeBase(module.BrownieSafeBase):
    pass


@pytest.mark.parametrize('base', [module.BrownieSafeBase, CustomSafeBase])
@pytest.mark.parametrize('version', Safe.available_versions())
def test_wraps_every_safe_class_the_sdk_resolves(version, base):
    safe_class = type(Safe.from_version(version, ADDRESS, Mock()))
    wrapper = module._wrap(base, safe_class)
    # Brownie Safe behaviour takes precedence over the SDK's.
    assert wrapper.__mro__.index(base) < wrapper.__mro__.index(safe_class)
    assert module._wrap(base, safe_class) is wrapper


def test_brownie_safe_wraps_the_resolved_class_with_the_given_base(monkeypatch):
    resolved = type('SafeV999', (), {})
    wrap = Mock()
    monkeypatch.setattr(module, 'web3', SimpleNamespace(provider=SimpleNamespace(endpoint_uri='http://localhost')))
    monkeypatch.setattr(module, 'EthereumClient', Mock())
    monkeypatch.setattr(module, 'Safe', Mock(return_value=resolved()))
    monkeypatch.setattr(module, 'MultiSend', Mock())
    monkeypatch.setattr(module, '_QueueService', Mock())
    monkeypatch.setattr(module, '_wrap', wrap)

    safe = module.BrownieSafe(ADDRESS, base=CustomSafeBase)

    wrap.assert_called_once_with(CustomSafeBase, resolved)
    assert safe is wrap.return_value.return_value
