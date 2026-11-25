from unittest.mock import Mock

import pytest

import brownie_safe as module


@pytest.mark.parametrize(
    'balance, value, fees, top_up_to',
    [
        (0, 10, {'gasPrice': '0x3'}, 70),
        (10, 10, {'maxFeePerGas': '0x5', 'maxPriorityFeePerGas': '0x1'}, 110),
        (71, 10, {'gasPrice': '0x3'}, None),
        (0, 0, {'gasPrice': '0x0'}, None),
    ],
)
def test_preview_sender_funding(monkeypatch, balance, value, fees, top_up_to):
    owner = module.Account('0x' + '12' * 20)
    send = Mock()
    monkeypatch.setattr(owner, '_transact', send)
    set_balance = Mock()
    monkeypatch.setattr(module.web3.manager, 'request_blocking', set_balance)
    sender = module._PreviewAccount(owner, 'anvil_setBalance')
    monkeypatch.setattr(sender, 'balance', lambda: balance)

    tx = {'gas': '0x14', 'value': value, **fees}
    assert sender._transact(tx, None) is send.return_value
    send.assert_called_once_with(tx, None)
    if top_up_to is None:
        set_balance.assert_not_called()
    else:
        set_balance.assert_called_once_with('anvil_setBalance', [owner.address, hex(top_up_to)])
