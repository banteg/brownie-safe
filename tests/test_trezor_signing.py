import sys
from unittest.mock import MagicMock, Mock

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from safe_eth.eth import EthereumClient
from safe_eth.safe.safe_tx import SafeTx

from brownie_safe import BrownieSafeBase


def test_trezor_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "trezorlib", None)

    with pytest.raises(ImportError, match=r"brownie-safe\[trezor\]"):
        BrownieSafeBase.sign_with_trezor(None, None)


@pytest.mark.parametrize("force_eth_sign", [False, True])
def test_trezor_session_signing(monkeypatch, force_eth_sign):
    pytest.importorskip("trezorlib")
    from trezorlib import client, ethereum, tools
    from trezorlib.cli import get_passphrase

    signing_account = Account.from_key(b"\x01" * 32)
    safe_tx = SafeTx(
        ethereum_client=EthereumClient("http://127.0.0.1:1"),
        safe_address="0x0000000000000000000000000000000000001001",
        to="0x0000000000000000000000000000000000001002",
        value=0,
        data=b"\x00\x01\xff",
        operation=0,
        safe_tx_gas=0,
        base_gas=0,
        gas_price=0,
        gas_token=None,
        refund_receiver=None,
        safe_nonce=0,
        safe_version="1.4.1",
        chain_id=31337,
    )
    original_hash = safe_tx.safe_tx_hash
    path = tools.parse_path("m/44'/60'/0'/0/0")
    session = MagicMock()
    session.__enter__.return_value = session
    session.features.model = "T"
    session.version = (2, 12, 5)

    device = Mock()
    device.get_session.return_value = session
    default_session = Mock(return_value=session)
    monkeypatch.setattr(client, "get_default_client", Mock(return_value=device))
    monkeypatch.setattr(client, "get_default_session", default_session)
    get_address = Mock(return_value=signing_account.address)
    monkeypatch.setattr(ethereum, "get_address", get_address)
    def sign_test_typed_data(_session, _path, typed_data):
        return Account.sign_typed_data(signing_account.key, full_message=typed_data)

    def sign_test_message(_session, _path, message):
        return signing_account.sign_message(encode_defunct(primitive=message))

    sign_typed_data = Mock(side_effect=sign_test_typed_data)
    sign_message = Mock(side_effect=sign_test_message)
    monkeypatch.setattr(ethereum, "sign_typed_data", sign_typed_data)
    monkeypatch.setattr(ethereum, "sign_message", sign_message)

    signature = BrownieSafeBase.sign_with_trezor(
        None, safe_tx, use_passphrase=force_eth_sign, force_eth_sign=force_eth_sign
    )

    get_address.assert_called_once_with(session, path)
    session.__exit__.assert_called_once_with(None, None, None)
    if force_eth_sign:
        default_session.assert_called_once_with(device, get_passphrase)
        device.get_session.assert_not_called()
        sign_message.assert_called_once_with(session, path, original_hash)
        sign_typed_data.assert_not_called()
        assert signature[-1] in (31, 32)
    else:
        device.get_session.assert_called_once_with()
        default_session.assert_not_called()
        sign_typed_data.assert_called_once()
        assert sign_typed_data.call_args.args[:2] == (session, path)
        assert sign_typed_data.call_args.args[2]["message"]["data"] == "0x0001ff"
        sign_message.assert_not_called()
        assert signature[-1] in (27, 28)

    assert safe_tx.safe_tx_hash == original_hash
    assert safe_tx.signatures == signature
    assert safe_tx.signers == [signing_account.address]
