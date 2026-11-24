from abc import ABCMeta
import os
import re
from copy import copy
from typing import Dict, List, Optional, Union
import click
from web3 import Web3  # don't move below brownie import
from brownie import Contract, accounts, chain, history, web3
from brownie.convert.datatypes import EthAddress
from brownie.network.account import LocalAccount
from brownie.network.transaction import TransactionReceipt
from eth_abi import encode
from eth_utils import is_address, to_checksum_address, encode_hex, keccak
from safe_eth.safe import Safe
from safe_eth.eth import EthereumClient
from safe_eth.eth.constants import NULL_ADDRESS
from safe_eth.safe.api import SafeAPIException, TransactionServiceApi
from safe_eth.safe.safe import SafeV111, SafeV120, SafeV130, SafeV141
from safe_eth.safe.enums import SafeOperationEnum
from safe_eth.safe.multi_send import MultiSend, MultiSendOperation, MultiSendTx
from safe_eth.safe.safe_signature import SafeSignature
from safe_eth.safe.safe_tx import SafeTx
from safe_eth.safe.signatures import signature_split, signature_to_bytes
from safe_eth.util.http import prepare_http_session
from hexbytes import HexBytes
from trezorlib import ethereum, tools, ui
from trezorlib.client import TrezorClient
from trezorlib.messages import EthereumSignMessage
from trezorlib.transport import get_transport
from functools import cached_property


class ExecutionFailure(Exception):
    pass


class ApiError(Exception):
    pass


class _QueueService:
    transactions_url = 'https://api.safe.global/queue/api/v1/multisig-transactions'

    def __init__(self, chain_id: int, auth_token: str | None):
        self.chain_id = chain_id
        self.http_session = prepare_http_session(10, 100)
        self.request_timeout = int(os.environ.get('SAFE_TRANSACTION_SERVICE_REQUEST_TIMEOUT', 10))
        if auth_token:
            self.http_session.headers['Authorization'] = f'Bearer {auth_token}'

    def _request(self, method, path='', **kwargs):
        response = self.http_session.request(
            method, self.transactions_url + path, timeout=self.request_timeout,
            allow_redirects=False, **kwargs,
        )
        status = response.status_code
        if not 200 <= status < 300 and not (method == 'POST' and status == 409):
            raise SafeAPIException(f'Safe Queue Service {method} {path or "/"}: HTTP {status}: {response.text}')
        return response

    def _check_transaction(self, transaction, address, safe_tx_hash=None):
        if int(transaction['chainId']) != self.chain_id or transaction['safe'].lower() != address.lower():
            raise SafeAPIException(f'Safe Queue Service returned a transaction outside {address}:{self.chain_id}')
        if safe_tx_hash is not None and HexBytes(transaction['safeTxHash']) != safe_tx_hash:
            raise SafeAPIException('Safe Queue Service returned a different Safe transaction hash')

    def queued_transactions(self, address, *, nonce_order='asc', limit=100):
        params = {
            'safes': f'{address}:{self.chain_id}',
            'nonceOrder': nonce_order,
            'limit': limit,
            'offset': 0,
        }
        while True:
            page = self._request('GET', '/queue', params=params).json()
            results = page['results']
            if not results and page['next'] is not None:
                raise SafeAPIException('Safe Queue Service returned an empty page with a next page')
            for transaction in results:
                self._check_transaction(transaction, address)
                yield transaction
            if page['next'] is None:
                return
            params = dict(params, offset=params['offset'] + len(results))

    def _hash_for_chain(self, safe_tx: SafeTx):
        if safe_tx.chain_id != self.chain_id:
            raise SafeAPIException('Safe transaction chain does not match the Queue Service client')
        return safe_tx.safe_tx_hash

    def post_transaction(self, safe_tx: SafeTx):
        safe_tx_hash = self._hash_for_chain(safe_tx)
        signatures = SafeSignature.parse_signature(safe_tx.signatures, safe_tx_hash)
        response = self._request('POST', json={
            'chainId': self.chain_id,
            'safe': safe_tx.safe_address,
            'to': safe_tx.to,
            'value': str(safe_tx.value),
            'data': encode_hex(safe_tx.data) if safe_tx.data else None,
            'operation': safe_tx.operation,
            'safeTxGas': str(safe_tx.safe_tx_gas),
            'baseGas': str(safe_tx.base_gas),
            'gasPrice': str(safe_tx.gas_price),
            'gasToken': safe_tx.gas_token,
            'refundReceiver': safe_tx.refund_receiver,
            'nonce': str(safe_tx.safe_nonce),
            'signatures': [encode_hex(signature.export_signature()) for signature in signatures],
            'originName': 'Brownie Safe',
        })
        if response.status_code == 409:
            # The legacy proposal endpoint also accepted new confirmations on existing proposals.
            self._confirm_reposted_transaction(safe_tx, signatures)
        else:
            self._check_transaction(response.json(), safe_tx.safe_address, safe_tx_hash)

    def _get_transaction(self, safe_tx):
        transaction = self._request('GET', f'/{encode_hex(safe_tx.safe_tx_hash)}').json()
        self._check_transaction(transaction, safe_tx.safe_address, safe_tx.safe_tx_hash)
        return transaction

    def pending_signatures(self, transaction, safe_tx):
        self._check_transaction(transaction, safe_tx.safe_address, safe_tx.safe_tx_hash)
        signatures = [
            signature
            for confirmation in transaction['confirmations']
            for signature in SafeSignature.parse_signature(confirmation['signature'], safe_tx.safe_tx_hash)
        ]
        return bytes(SafeSignature.export_signatures(signatures))

    def _confirm_reposted_transaction(self, safe_tx, signatures):
        remaining = {signature.owner.lower(): signature.export_signature() for signature in signatures}
        previous_size = None
        while True:
            transaction = self._get_transaction(safe_tx)
            for confirmation in transaction['confirmations']:
                remaining.pop(confirmation['owner'].lower(), None)
            if proposer := transaction.get('proposedBy'):
                remaining.pop(proposer.lower(), None)
            if not remaining:
                return
            if len(remaining) == previous_size:
                raise SafeAPIException('Safe Queue Service confirmation conflict persisted after refreshing the transaction')
            previous_size = len(remaining)
            if self._post_signatures(safe_tx.safe_tx_hash, remaining.values()).status_code != 409:
                return

    def _post_signatures(self, safe_tx_hash, signatures):
        return self._request(
            'POST', f'/{encode_hex(safe_tx_hash)}/signatures',
            json={'signatures': [encode_hex(signature) for signature in signatures]},
        )

    def post_signature(self, safe_tx: SafeTx, signature):
        safe_tx_hash = self._hash_for_chain(safe_tx)
        # Pre-1.3 Safe hashes can match across chains; the confirmation endpoint only takes a hash.
        if 'chainId' not in safe_tx.eip712_structured_data['domain']:
            self._get_transaction(safe_tx)
        # A conflict on this single-signature request means the owner already confirmed.
        self._post_signatures(safe_tx_hash, [HexBytes(signature)])


class ContractWrapper:
    def __init__(self, account, instance):
        self.account = account
        self.instance = instance

    def __call__(self, address):
        address = to_address(address)
        return Contract(address, owner=self.account)
    
    def __getattr__(self, attr):
        return getattr(self.instance, attr)
    

def to_address(address):
    if is_address(address):
        return to_checksum_address(address)
    return web3.ens.address(address)


class BrownieSafeBase(metaclass=ABCMeta):
    _queue_service = None

    def __init__(self, address, ethereum_client):
        super().__init__(address, ethereum_client)
        
        # safe-eth-py shadows the .contract method after 4.3.2
        # we use a wrapper that satisfies both use cases
        # 1. web3 safe contract instance using __getattr__
        # 2. instantiating contract instance with safe as an owner using __call__
        self.contract = ContractWrapper(self.account, self.contract)
        
        if self.client == 'anvil':
            web3.manager.request_blocking('anvil_setNextBlockBaseFeePerGas', ['0x0'])

    def __str__(self):
        return EthAddress(self.address)

    def __repr__(self):
        return f'BrownieSafe("{self.address}")'

    @cached_property
    def client(self):
        client_version = web3.client_version
        match = re.search('(anvil|hardhat|ganache)', client_version.lower())
        return match.group(1) if match else client_version

    @property
    def account(self) -> LocalAccount:
        """
        Unlocked Brownie account for Gnosis Safe.
        """
        return accounts.at(self.address, force=True)

    def pending_nonce(self) -> int:
        """
        Subsequent nonce which accounts for the on-chain nonce and pending transactions.
        """
        if self._queue_service is not None:
            queued = self._queue_service.queued_transactions(self.address, nonce_order='desc', limit=1)
            latest = next(queued, None)
            next_nonce = int(latest['nonce']) + 1 if latest else 0
        else:
            results = self.transaction_service.get_transactions(self.address)
            next_nonce = max((int(tx['nonce']) + 1 for tx in results), default=0)
        return max(self.retrieve_nonce(), next_nonce)

    def tx_from_receipt(self, receipt: TransactionReceipt, operation: SafeOperationEnum = SafeOperationEnum.CALL, safe_nonce: int = None) -> SafeTx:
        """
        Convert Brownie transaction receipt to a Safe transaction.
        """
        if safe_nonce is None:
            safe_nonce = self.pending_nonce()

        return self.build_multisig_tx(receipt.receiver, receipt.value, receipt.input, operation=operation.value, safe_nonce=safe_nonce)

    def multisend_from_receipts(self, receipts: List[TransactionReceipt] = None, safe_nonce: int = None) -> SafeTx:
        """
        Convert multiple Brownie transaction receipts (or history) to a multisend Safe transaction.
        """
        if receipts is None:
            receipts = history.from_sender(self.address)

        if safe_nonce is None:
            safe_nonce = self.pending_nonce()

        txs = [MultiSendTx(MultiSendOperation.CALL, tx.receiver, tx.value, tx.input) for tx in receipts]
        data = self.multisend.build_tx_data(txs)
        return self.build_multisig_tx(self.multisend.address, 0, data, SafeOperationEnum.DELEGATE_CALL.value, safe_nonce=safe_nonce)

    def get_signer(self, signer: Optional[Union[LocalAccount, str]] = None) -> LocalAccount:
        if signer is None:
            signer = click.prompt('signer', type=click.Choice(accounts.load()))

        if isinstance(signer, str):
            # Avoids a previously impersonated account with no signing capabilities
            accounts.clear()
            signer = accounts.load(signer)

        assert isinstance(signer, LocalAccount), 'Signer must be a name of brownie account or LocalAccount'
        return signer

    def sign_transaction(self, safe_tx: SafeTx, signer=None) -> SafeTx:
        """
        Sign a Safe transaction with a private key account.
        """
        signer = self.get_signer(signer)
        return safe_tx.sign(signer.private_key)

    def sign_with_trezor(self, safe_tx: SafeTx, derivation_path: str = "m/44'/60'/0'/0/0", use_passphrase: bool = False, force_eth_sign: bool = False) -> bytes:
        """
        Sign a Safe transaction with a Trezor wallet.

        Defaults to no passphrase (and skips passphrase prompt) by default.
        Uses on-device passphrase input if `use_passphrase` is truthy

        Defaults to EIP-712 signatures on wallets & fw revisions that support it:
        - TT fw >v2.4.3 (clear signing only)
        - T1: not yet, and maybe only blind signing
        Otherwise (or if `force_eth_sign` is truthy), use eth_sign instead
        """
        path = tools.parse_path(derivation_path)
        transport = get_transport()
        # if not using passphrase, then set env var so that prompt is skipped
        if not use_passphrase:
            os.environ["PASSPHRASE"] = ""
        # default to on-device passphrase input if `use_passphrase` is truthy
        client = TrezorClient(transport=transport, ui=ui.ClickUI(passphrase_on_host=not use_passphrase))
        account = ethereum.get_address(client, path)

        if force_eth_sign:
            use_eip712 = False
        elif client.features.model == 'T': # Trezor T
            use_eip712 = (client.features.major_version, client.features.minor_version, client.features.patch_version) >= (2, 4, 3) # fw ver >= 2.4.3
        else:
            use_eip712 = False

        if use_eip712:
            trez_sig = ethereum.sign_typed_data(client, path, safe_tx.eip712_structured_data)
            v, r, s = signature_split(trez_sig.signature)
        else:
            # have to use this instead of trezorlib.ethereum.sign_message
            # because that takes a string instead of bytes
            trez_sig = client.call(
                EthereumSignMessage(
                    address_n=path,
                    message=safe_tx.safe_tx_hash
                )
            )
            v, r, s = signature_split(trez_sig.signature)
            # Gnosis adds 4 to `v` to denote an eth_sign signature
            v += 4

        signature = signature_to_bytes(v, r, s)
        if account not in safe_tx.signers:
            new_owners = safe_tx.signers + [account]
            new_owner_pos = sorted(new_owners, key=lambda x: int(x, 16)).index(account)
            safe_tx.signatures = (
                safe_tx.signatures[: 65 * new_owner_pos]
                + signature
                + safe_tx.signatures[65 * new_owner_pos :]
            )
        return signature

    def sign_with_frame(self, safe_tx: SafeTx, frame_rpc="http://127.0.0.1:1248") -> bytes:
        """
        Sign a Safe transaction using Frame. Use this option with hardware wallets.
        """
        # Requesting accounts triggers a connection prompt
        frame = Web3(Web3.HTTPProvider(frame_rpc, {'timeout': 600}))
        account = frame.eth.accounts[0]
        signature = frame.manager.request_blocking('eth_signTypedData_v4', [account, safe_tx.eip712_structured_data])
        # Convert to a format expected by Gnosis Safe
        v, r, s = signature_split(signature)
        # Ledger doesn't support EIP-155
        if v in {0, 1}:
            v += 27
        signature = signature_to_bytes(v, r, s)
        if account not in safe_tx.signers:
            new_owners = safe_tx.signers + [account]
            new_owner_pos = sorted(new_owners, key=lambda x: int(x, 16)).index(account)
            safe_tx.signatures = (
                safe_tx.signatures[: 65 * new_owner_pos]
                + signature
                + safe_tx.signatures[65 * new_owner_pos :]
            )
        return signature

    def post_transaction(self, safe_tx: SafeTx):
        """
        Submit a Safe transaction to a transaction service.
        Prompts for a signature if needed.
        """
        if not safe_tx.sorted_signers:
            self.sign_transaction(safe_tx)

        service = self._queue_service or self.transaction_service
        service.post_transaction(safe_tx)

    def post_signature(self, safe_tx: SafeTx, signature: bytes):
        """
        Submit a confirmation signature to a transaction service.
        """
        if self._queue_service is None:
            self.transaction_service.post_signatures(safe_tx.safe_tx_hash, signature)
        else:
            self._queue_service.post_signature(safe_tx, signature)

    @property
    def pending_transactions(self) -> List[SafeTx]:
        """
        Retrieve pending transactions from the transaction service.
        """
        queue = self._queue_service
        if queue is None:
            results = self.transaction_service.get_transactions(self.address)
            pending = (tx for tx in reversed(results) if not tx['isExecuted'])
        else:
            pending = (tx for tx in queue.queued_transactions(self.address) if tx['txHash'] is None)
        nonce = self.retrieve_nonce()
        transactions = []
        for tx in pending:
            if int(tx['nonce']) < nonce:
                continue
            safe_tx = self.build_multisig_tx(
                to=to_checksum_address(tx['to'] or NULL_ADDRESS),
                value=int(tx['value']),
                data=HexBytes(tx['data'] or b''),
                operation=tx['operation'],
                safe_tx_gas=int(tx['safeTxGas']),
                base_gas=int(tx['baseGas']),
                gas_price=int(tx['gasPrice']),
                gas_token=to_checksum_address(tx['gasToken'] or NULL_ADDRESS),
                refund_receiver=to_checksum_address(tx['refundReceiver'] or NULL_ADDRESS),
                safe_nonce=int(tx['nonce']),
            )
            if queue is None:
                safe_tx.signatures = self.confirmations_to_signatures(tx['confirmations'])
            else:
                safe_tx.signatures = queue.pending_signatures(tx, safe_tx)
            transactions.append(safe_tx)
        return transactions

    def confirmations_to_signatures(self, confirmations: List[Dict]) -> bytes:
        """
        Convert service confirmations to combined signatures.
        """
        sorted_confirmations = sorted(confirmations, key=lambda conf: int(conf['owner'], 16))
        signatures = [bytes(HexBytes(conf['signature'])) for conf in sorted_confirmations]
        return b''.join(signatures)

    @cached_property
    def transaction_service(self) -> TransactionServiceApi:
        """Client for the Transaction Service, including its indexed history."""
        service = TransactionServiceApi(
            self.ethereum_client.get_network(), self.ethereum_client, self._transaction_service_base_url,
        )
        if self._auth_token:
            service.http_session.headers['Authorization'] = f'Bearer {self._auth_token}'
        return service

    def estimate_gas(self, safe_tx: SafeTx) -> int:
        """
        Estimate gas limit for successful execution.
        """
        return self.estimate_tx_gas(safe_tx.to, safe_tx.value, safe_tx.data, safe_tx.operation)

    def set_storage(self, account: str, slot: int, value: int):
        params = [account, hex(slot), encode_hex(encode(['uint'], [value]))]
        method = {
            'anvil': 'anvil_setStorageAt',
            'hardhat': 'hardhat_setStorageAt',
            'ganache': 'evm_setAccountStorageAt',
        }
        web3.manager.request_blocking(method[self.client], params)

    def preview_tx(self, safe_tx: SafeTx, events=True, call_trace=False) -> TransactionReceipt:
        tx = copy(safe_tx)
        safe = Contract.from_abi('Gnosis Safe', self.address, self.contract.abi)
        # Replace pending nonce with the subsequent nonce, this could change the safe_tx_hash
        tx.safe_nonce = safe.nonce()
        # Forge signatures from the needed amount of owners, skip the one which submits the tx
        # Owners must be sorted numerically, sorting as checksum addresses may yield wrong order
        threshold = safe.getThreshold()
        sorted_owners = sorted(safe.getOwners(), key=lambda x: int(x, 16))
        owners = [accounts.at(owner, force=True) for owner in sorted_owners[:threshold]]
        # Signautres are encoded as [bytes32 r, bytes32 s, bytes8 v]
        # Pre-validated signatures are encoded as r=owner, s unused and v=1.
        # https://docs.gnosis.io/safe/docs/contracts_signatures/#pre-validated-signatures
        tx.signatures = b''.join([encode(['address', 'uint'], [str(owner), 0]) + b'\x01' for owner in owners])

        # approvedHashes are in slot 8 and have type of mapping(address => mapping(bytes32 => uint256))
        for owner in owners[:threshold]:
            outer_key = keccak(encode(['address', 'uint'], [str(owner), 8]))
            slot = int.from_bytes(keccak(tx.safe_tx_hash + outer_key), 'big')
            self.set_storage(tx.safe_address, slot, 1)

        payload = tx.w3_tx.build_transaction()
        receipt = owners[0].transfer(payload['to'], payload['value'], gas_limit=payload['gas'], data=payload['data'])

        if 'ExecutionSuccess' not in receipt.events:
            receipt.info()
            receipt.call_trace(True)
            raise ExecutionFailure()

        if events:
            receipt.info()
        if call_trace:
            receipt.call_trace(True)
        return receipt

    def preview(self, safe_tx: SafeTx, events=True, call_trace=False, reset=True, include_pending=False):
        """
        Dry run a Safe transaction in a forked network environment.
        """
        if reset:
            chain.reset()
        if include_pending:
            self.preview_pending(events=events, call_trace=call_trace)
        return self.preview_tx(safe_tx, events=events, call_trace=call_trace)

    def execute_transaction(self, safe_tx: SafeTx, signer=None) -> TransactionReceipt:
        """
        Execute a fully signed transaction likely retrieved from the pending_transactions method.
        """
        payload = safe_tx.w3_tx.build_transaction()
        signer = self.get_signer(signer)
        receipt = signer.transfer(payload['to'], payload['value'], gas_limit=payload['gas'], data=payload['data'])
        return receipt

    def execute_transaction_with_frame(self, safe_tx: SafeTx, frame_rpc="http://127.0.0.1:1248") -> bytes:
        """
        Execute a fully signed transaction with frame. Use this option with hardware wallets.
        """
        # Requesting accounts triggers a connection prompt
        frame = Web3(Web3.HTTPProvider(frame_rpc, {'timeout': 600}))
        account = frame.eth.accounts[0]
        frame.manager.request_blocking('wallet_switchEthereumChain', [{'chainId': hex(chain.id)}])
        payload = safe_tx.w3_tx.build_transaction()
        tx = {
            "from": account,
            "to": self.address,
            "value": payload["value"],
            "nonce": frame.eth.get_transaction_count(account),
            "gas": web3.to_hex(payload["gas"]),
            "data": HexBytes(payload["data"]),
        }
        frame.eth.send_transaction(tx)

    def preview_pending(self, events=True, call_trace=False):
        """
        Dry run all pending transactions in a forked environment.
        """
        for safe_tx in self.pending_transactions:
            self.preview_tx(safe_tx, events=events, call_trace=call_trace)


class BrownieSafeV111(BrownieSafeBase, SafeV111):
    pass

class BrownieSafeV120(BrownieSafeBase, SafeV120):
    pass

class BrownieSafeV130(BrownieSafeBase, SafeV130):
    pass

class BrownieSafeV141(BrownieSafeBase, SafeV141):
    pass


PATCHED_SAFE_VERSIONS = {
    '1.1.1': BrownieSafeV111,
    '1.2.0': BrownieSafeV120,
    '1.3.0': BrownieSafeV130,
    '1.4.1': BrownieSafeV141,
}


def BrownieSafe(address, base_url=None, multisend=None, auth_token=None):
    """
    Create a BrownieSafe from an address or ENS name.

    Pass base_url to use a custom Safe Transaction Service for off-chain operations.
    """
    address = to_address(address)
    ethereum_client = EthereumClient(web3.provider.endpoint_uri)
    safe = Safe(address, ethereum_client)
    version = safe.get_version()
    brownie_safe = PATCHED_SAFE_VERSIONS[version](address, ethereum_client)
    brownie_safe.multisend = MultiSend(ethereum_client, multisend, call_only=True)

    brownie_safe._transaction_service_base_url = base_url
    brownie_safe._auth_token = auth_token or os.environ.get('SAFE_AUTH_TOKEN')
    if not base_url:
        queue_token = brownie_safe._auth_token or os.environ.get('SAFE_TRANSACTION_SERVICE_API_KEY')
        brownie_safe._queue_service = _QueueService(ethereum_client.get_chain_id(), queue_token)

    return brownie_safe
