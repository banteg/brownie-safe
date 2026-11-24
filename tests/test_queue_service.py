from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from eth_utils import encode_hex, to_checksum_address
from safe_eth.eth.constants import NULL_ADDRESS
from safe_eth.safe.api import SafeAPIException
from safe_eth.safe.safe_signature import SafeSignature, SafeSignatureContract
from safe_eth.safe.safe_tx import SafeTx
from safe_eth.safe.signatures import signature_to_bytes

import brownie_safe as module

ADDRESS = to_checksum_address('0xaabbcc' + '00' * 17)
RECIPIENT = to_checksum_address('0x1122aabb' + '00' * 16)
TX_URL = 'https://api.safe.global/queue/api/v1/multisig-transactions'


def response(body=None, status=200):
    return Mock(status_code=status, text=str(body), json=Mock(return_value=body))


def transaction(*, safe_version='1.4.1', chain_id=1, **overrides):
    fields = dict(
        to=RECIPIENT, value=10**18, data=b'\x12\x34', operation=0,
        safe_tx_gas=123, base_gas=456, gas_price=0, gas_token=NULL_ADDRESS,
        refund_receiver=NULL_ADDRESS, safe_nonce=9,
    )
    fields.update(overrides)
    return SafeTx(None, ADDRESS, safe_version=safe_version, chain_id=chain_id, **fields)


def record(tx, **overrides):
    fields = {
        'safe': ADDRESS.lower(), 'chainId': str(tx.chain_id), 'txHash': None,
        'safeTxHash': encode_hex(tx.safe_tx_hash), 'confirmations': [], 'nonce': str(tx.safe_nonce),
    }
    fields.update(overrides)
    return fields


@pytest.fixture
def safe(monkeypatch):
    instance = object.__new__(module.BrownieSafeBase)
    instance.address = ADDRESS
    instance.retrieve_nonce = Mock(return_value=8)
    instance.build_multisig_tx = transaction
    instance.ethereum_client = Mock(get_chain_id=Mock(return_value=1))
    monkeypatch.delenv('SAFE_AUTH_TOKEN', raising=False)
    monkeypatch.setenv('SAFE_TRANSACTION_SERVICE_API_KEY', 'test-key')
    monkeypatch.setattr(module, 'web3', SimpleNamespace(provider=SimpleNamespace(endpoint_uri='http://localhost')))
    monkeypatch.setattr(module, 'EthereumClient', Mock(return_value=instance.ethereum_client))
    monkeypatch.setattr(module, 'Safe', Mock(return_value=Mock(get_version=Mock(return_value='1.4.1'))))
    monkeypatch.setitem(module.PATCHED_SAFE_VERSIONS, '1.4.1', Mock(return_value=instance))
    monkeypatch.setattr(module, 'MultiSend', Mock())
    legacy_client = Mock(http_session=SimpleNamespace(headers={}))
    monkeypatch.setattr(module, 'TransactionServiceApi', Mock(return_value=legacy_client))
    return instance


def test_propose_and_confirm(safe, monkeypatch):
    module.BrownieSafe(ADDRESS)
    session = safe._queue_service.http_session
    assert session.headers['Authorization'] == 'Bearer test-key'
    tx = transaction()
    first = tx.sign(b'\x01' * 32)
    second = tx.sign(b'\x02' * 32)
    request = Mock(side_effect=[response(record(tx), status=201), response(status=204), response(status=409)])
    monkeypatch.setattr(session, 'request', request)

    safe.post_transaction(tx)
    safe.post_signature(tx, encode_hex(second))
    safe.post_signature(tx, second)

    proposal, confirmation, repeated_confirmation = request.call_args_list
    assert proposal.args == ('POST', TX_URL)
    assert proposal.kwargs['json'] == {
        'safe': ADDRESS, 'chainId': 1, 'to': RECIPIENT, 'value': str(10**18),
        'data': '0x1234', 'operation': 0, 'safeTxGas': '123', 'baseGas': '456',
        'gasPrice': '0', 'gasToken': NULL_ADDRESS, 'refundReceiver': NULL_ADDRESS,
        'nonce': '9', 'signatures': [encode_hex(first), encode_hex(second)], 'originName': 'Brownie Safe',
    }
    assert confirmation.args == ('POST', f'{TX_URL}/{encode_hex(tx.safe_tx_hash)}/signatures')
    assert confirmation.kwargs['json'] == {'signatures': [encode_hex(second)]}
    assert repeated_confirmation == confirmation
    module.TransactionServiceApi.assert_not_called()
    assert safe.transaction_service.http_session.headers['Authorization'] == 'Bearer test-key'


def test_reposting_only_adds_missing_confirmations(safe, monkeypatch):
    module.BrownieSafe(ADDRESS)
    tx = transaction()
    tx.sign(b'\x01' * 32)
    already_signed = tx.signers[0].lower()
    missing = tx.sign(b'\x02' * 32)
    request = Mock(side_effect=[
        response(status=409),
        response(record(tx, confirmations=[{'owner': already_signed}])),
        response(status=201),
        response({'detail': 'invalid signature'}, status=422),
    ])
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)

    safe.post_transaction(tx)
    assert request.call_args_list[1].args == ('GET', f'{TX_URL}/{encode_hex(tx.safe_tx_hash)}')
    assert request.call_args_list[2].kwargs['json'] == {'signatures': [encode_hex(missing)]}
    with pytest.raises(SafeAPIException, match='HTTP 422.*invalid signature'):
        safe.post_signature(tx, missing)


def test_reposting_retries_a_conflicted_batch(safe, monkeypatch):
    module.BrownieSafe(ADDRESS)
    tx = transaction()
    tx.sign(b'\x01' * 32)
    original_owner, = tx.signers
    racing_signature = tx.sign(b'\x02' * 32)
    racing_owner, = set(tx.signers) - {original_owner}
    missing = tx.sign(b'\x03' * 32)
    request = Mock(side_effect=[
        response(status=409),
        response(record(tx, confirmations=[{'owner': original_owner}])),
        response(status=409),
        response(record(tx, confirmations=[{'owner': original_owner}, {'owner': racing_owner}])),
        response(status=201),
    ])
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)

    safe.post_transaction(tx)
    assert set(request.call_args_list[2].kwargs['json']['signatures']) == {
        encode_hex(racing_signature), encode_hex(missing),
    }
    assert request.call_args_list[4].kwargs['json']['signatures'] == [encode_hex(missing)]


def test_packed_confirmations_repack_contract_offsets_and_retry(safe, monkeypatch):
    module.BrownieSafe(ADDRESS)
    tx = transaction()
    eoa, = SafeSignature.parse_signature(tx.sign(b'\x01' * 32), tx.safe_tx_hash)
    contract = SafeSignatureContract(
        signature_to_bytes(0, int(RECIPIENT, 16), 65),
        tx.safe_tx_hash, tx.safe_tx_hash_preimage, b'contract signature',
    )
    packed = SafeSignature.export_signatures([eoa, contract])
    request = Mock(side_effect=[
        response(status=409), response(record(tx, confirmations=[{'owner': eoa.owner}])), response(status=201),
    ])
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)

    safe.post_signature(tx, packed)
    assert request.call_args_list[0].kwargs['json']['signatures'] == [
        encode_hex(contract.export_signature()), encode_hex(eoa.export_signature()),
    ]
    assert request.call_args_list[2].kwargs['json']['signatures'] == [encode_hex(contract.export_signature())]


@pytest.mark.parametrize('is_owner', [False, True])
def test_repost_checks_current_ownership_of_former_proposer(safe, monkeypatch, is_owner):
    module.BrownieSafe(ADDRESS)
    tx = transaction()
    signature = tx.sign(b'\x01' * 32)
    owner, = tx.signers
    owner_call = Mock(return_value=Mock(call=Mock(return_value=is_owner)))
    tx.contract = SimpleNamespace(functions=SimpleNamespace(isOwner=owner_call))
    replies = [response(status=409), response(record(tx, proposedBy=owner.lower(), proposedVia='DELEGATE'))]
    if is_owner:
        replies.append(response(status=201))
    request = Mock(side_effect=replies)
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)

    safe.post_transaction(tx)
    owner_call.assert_called_once_with(owner)
    assert request.call_count == len(replies)
    if is_owner:
        assert request.call_args.kwargs['json']['signatures'] == [encode_hex(signature)]


@pytest.mark.parametrize('operation', ['confirm', 'repost', 'unsigned-repost'])
def test_cross_chain_legacy_hash_cannot_add_a_confirmation(safe, monkeypatch, operation):
    module.BrownieSafe(ADDRESS)
    tx = transaction(safe_version='1.2.0')
    other_chain = transaction(safe_version='1.2.0', chain_id=10)
    assert other_chain.safe_tx_hash == tx.safe_tx_hash
    get_transaction = response(record(other_chain))
    repost = operation != 'confirm'
    request = Mock(side_effect=[response(status=409), get_transaction] if repost else [get_transaction])
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)

    with pytest.raises(SafeAPIException, match='outside'):
        if operation == 'unsigned-repost':
            safe._queue_service.post_transaction(tx)
        elif repost:
            tx.sign(b'\x01' * 32)
            safe.post_transaction(tx)
        else:
            safe.post_signature(tx, tx.sign(b'\x01' * 32))
    assert [call.args[0] for call in request.call_args_list] == (['POST', 'GET'] if repost else ['GET'])


def test_pending_transactions_and_nonce(safe, monkeypatch):
    module.BrownieSafe(ADDRESS)
    tx = transaction(to=NULL_ADDRESS)
    eoa_signature = tx.sign(b'\x01' * 32)
    contract = SafeSignatureContract(
        signature_to_bytes(0, int(RECIPIENT, 16), 65),
        tx.safe_tx_hash, tx.safe_tx_hash_preimage, b'contract signature',
    )
    approver = to_checksum_address('0x' + 'ff' * 20)
    queued = record(
        tx, data='0x1234', to=None, operation=0, value=str(10**18),
        safeTxGas='123', baseGas='456', gasPrice='0', gasToken=None, refundReceiver=None,
        confirmations=[
            {'owner': RECIPIENT.lower(), 'signature': encode_hex(contract.export_signature())},
            {'owner': tx.signers[0].lower(), 'signature': encode_hex(eoa_signature)},
            {'owner': approver.lower(), 'signature': None, 'signatureType': 'APPROVED_HASH'},
        ],
    )
    request = Mock(side_effect=[
        response({'results': [record(tx, nonce='12', txHash='0x01')], 'next': 'next-page'}),
        response({'results': [], 'next': None}),
        response({'results': [dict(queued, nonce='7'), dict(queued, nonce='8', txHash='0x01')], 'next': 'next-page'}),
        response({'results': [queued], 'next': None}),
    ])
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)

    assert safe.pending_nonce() == 13
    assert safe.pending_nonce() == 8
    pending, = safe.pending_transactions
    assert pending.safe_tx_hash == tx.safe_tx_hash
    signatures = SafeSignature.parse_signature(pending.signatures, pending.safe_tx_hash)
    assert [signature.owner for signature in signatures] == sorted([RECIPIENT, *tx.signers, approver], key=str.lower)
    assert signatures[0].contract_signature == b'contract signature'
    assert signatures[-1].v == 1
    calls = request.call_args_list
    assert all(call.args == ('GET', f'{TX_URL}/queue') for call in calls)
    assert [call.kwargs['params'] for call in calls] == [
        {'safes': f'{ADDRESS}:1', 'nonceOrder': 'desc', 'limit': 1, 'offset': 0},
        {'safes': f'{ADDRESS}:1', 'nonceOrder': 'desc', 'limit': 1, 'offset': 0},
        {'safes': f'{ADDRESS}:1', 'nonceOrder': 'asc', 'limit': 100, 'offset': 0},
        {'safes': f'{ADDRESS}:1', 'nonceOrder': 'asc', 'limit': 100, 'offset': 2},
    ]


@pytest.mark.parametrize('highest_only', [False, True])
def test_pending_queue_rejects_an_empty_continuation_page(safe, monkeypatch, highest_only):
    module.BrownieSafe(ADDRESS)
    request = Mock(return_value=response({'results': [], 'next': 'next-page'}))
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)
    with pytest.raises(SafeAPIException, match='empty page'):
        if highest_only:
            safe.pending_nonce()
        else:
            _ = safe.pending_transactions


def test_proposal_rejects_a_different_response_hash(safe, monkeypatch):
    module.BrownieSafe(ADDRESS)
    tx = transaction()
    tx.sign(b'\x01' * 32)
    request = Mock(return_value=response(record(tx, safeTxHash='0x' + '00' * 32), status=201))
    monkeypatch.setattr(safe._queue_service.http_session, 'request', request)
    with pytest.raises(SafeAPIException, match='different Safe transaction hash'):
        safe.post_transaction(tx)
    assert request.call_args.kwargs['allow_redirects'] is False


@pytest.mark.parametrize('auth_token', [None, 'custom-key'])
def test_custom_base_url_keeps_transaction_service(safe, auth_token):
    base_url = 'https://custom.safe.example'
    module.BrownieSafe(ADDRESS, base_url=base_url, auth_token=auth_token)
    assert safe._queue_service is None
    client = safe.transaction_service
    assert module.TransactionServiceApi.call_args.args[2] == base_url
    assert client.http_session.headers == ({'Authorization': f'Bearer {auth_token}'} if auth_token else {})
    tx = transaction()
    signature = tx.sign(b'\x01' * 32)
    safe.post_transaction(tx)
    safe.post_signature(tx, signature)
    client.post_transaction.assert_called_once_with(tx)
    client.post_signatures.assert_called_once_with(tx.safe_tx_hash, signature)
