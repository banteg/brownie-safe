import os
import warnings
from copy import copy
from typing import Dict, List, Optional, Union
from enum import Enum

import click
from gnosis.eth import EthereumClient, EthereumNetwork
from web3 import Web3  # don't move below brownie import
from brownie import Contract, accounts, chain, history, web3
from brownie.convert.datatypes import EthAddress
from brownie.network.account import LocalAccount
from brownie.network.transaction import TransactionReceipt
from eth_abi import encode_abi
from eth_utils import is_address, to_checksum_address, encode_hex, keccak
from gnosis.safe import Safe, SafeOperation
from gnosis.safe.multi_send import MultiSend, MultiSendOperation, MultiSendTx
from gnosis.safe.safe_tx import SafeTx
from gnosis.safe.signatures import signature_split, signature_to_bytes
from gnosis.safe.api import TransactionServiceApi
from gnosis.eth.ethereum_client import EthereumNetworkNotSupported
from hexbytes import HexBytes
from trezorlib import ethereum, tools, ui
from trezorlib.client import TrezorClient
from trezorlib.messages import EthereumSignMessage
from trezorlib.transport import get_transport

MULTISEND_CALL_ONLY = '0x40A2aCCbd92BCA938b02010E17A5b8929b49130D'
multisends = {
    10: '0x998739BFdAAdde7C933B942a68053933098f9EDa',
    250: '0x10B62CC1E8D9a9f1Ad05BCC491A7984697c19f7E',
    288: '0x2Bd65cd56cAAC777f87d7808d13DEAF88e54E0eA',
    43114: '0x998739BFdAAdde7C933B942a68053933098f9EDa'
}


class EthereumNetworkBackport(Enum):
    ARBITRUM_ONE = 42161
    AURORA_MAINNET = 1313161554
    AVALANCHE_C_CHAIN = 43114
    BASE = 8453
    BASE_GOERLI = 84531
    BINANCE_SMART_CHAIN_MAINNET = 56
    CELO = 42220
    ENERGY_WEB_CHAIN = 246
    GOERLI = 5
    MAINNET = 1
    POLYGON = 137
    OPTIMISM = 10
    ENERGY_WEB_VOLTA_TESTNET = 73799
    GNOSIS = 100
    FANTOM = 250
    BOBA_NETWORK = 288


class TransactionServiceBackport(TransactionServiceApi):
    URL_BY_NETWORK = {
        EthereumNetworkBackport.ARBITRUM_ONE: "https://safe-transaction-arbitrum.safe.global",
        EthereumNetworkBackport.AURORA_MAINNET: "https://safe-transaction-aurora.safe.global",
        EthereumNetworkBackport.AVALANCHE_C_CHAIN: "https://safe-transaction-avalanche.safe.global",
        EthereumNetworkBackport.BASE: "https://safe-transaction-base.safe.global",
        EthereumNetworkBackport.BASE_GOERLI: "https://safe-transaction-base-testnet.safe.global",
        EthereumNetworkBackport.BINANCE_SMART_CHAIN_MAINNET: "https://safe-transaction-bsc.safe.global",
        EthereumNetworkBackport.CELO: "https://safe-transaction-celo.safe.global",
        EthereumNetworkBackport.ENERGY_WEB_CHAIN: "https://safe-transaction-ewc.safe.global",
        EthereumNetworkBackport.GOERLI: "https://safe-transaction-goerli.safe.global",
        EthereumNetworkBackport.MAINNET: "https://safe-transaction-mainnet.safe.global",
        EthereumNetworkBackport.POLYGON: "https://safe-transaction-polygon.safe.global",
        EthereumNetworkBackport.OPTIMISM: "https://safe-transaction-optimism.safe.global",
        EthereumNetworkBackport.ENERGY_WEB_VOLTA_TESTNET: "https://safe-transaction-volta.safe.global",
        EthereumNetworkBackport.GNOSIS: "https://safe-transaction-gnosis-chain.safe.global",
        EthereumNetworkBackport.FANTOM: "https://safe-txservice.fantom.network",
        EthereumNetworkBackport.BOBA_NETWORK: "https://safe-transaction.mainnet.boba.network",
    }

    def __init__(self, network: EthereumNetwork, ethereum_client: Optional[EthereumClient] = None, base_url: Optional[str] = None):
        self.network = network
        self.ethereum_client = ethereum_client
        self.base_url = base_url or self.URL_BY_NETWORK.get(EthereumNetworkBackport(network.value))
        if not self.base_url:
            raise EthereumNetworkNotSupported(network)


warnings.filterwarnings('ignore', 'The function signature for resolver.*')


class ExecutionFailure(Exception):
    pass


class ApiError(Exception):
    pass


class BrownieSafe(Safe):

    def __init__(self, address, base_url=None, multisend=None):
        """
        Create an BrownieSafe from an address or a ENS name and use a default connection.
        """
        address = to_checksum_address(address) if is_address(address) else web3.ens.resolve(address)
        ethereum_client = EthereumClient(web3.provider.endpoint_uri)
        self.transaction_service = TransactionServiceBackport(ethereum_client.get_network(), ethereum_client, base_url)
        self.multisend = multisend or multisends.get(chain.id, MULTISEND_CALL_ONLY)
        super().__init__(address, ethereum_client)
        if web3.clientVersion.startswith('anvil'):
            web3.manager.request_blocking('anvil_setNextBlockBaseFeePerGas', ['0x0'])

    def __str__(self):
        return EthAddress(self.address)

    def __repr__(self):
        return f'BrownieSafe("{self.address}")'

    @property
    def account(self) -> LocalAccount:
        """
        Unlocked Brownie account for Gnosis Safe.
        """
        return accounts.at(self.address, force=True)

    def contract(self, address) -> Contract:
        """
        Instantiate a Brownie Contract owned by Safe account.
        """
        address = to_checksum_address(address) if is_address(address) else web3.ens.resolve(address)
        return Contract(address, owner=self.account)

    def pending_nonce(self) -> int:
        """
        Subsequent nonce which accounts for pending transactions in the transaction service.
        """
        results = self.transaction_service.get_transactions(self.address)
        return results[0]['nonce'] + 1 if results else 0

    def tx_from_receipt(self, receipt: TransactionReceipt, operation: SafeOperation = SafeOperation.CALL, safe_nonce: int = None) -> SafeTx:
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
        data = MultiSend(
            ethereum_client=self.ethereum_client, address=self.multisend
        ).build_tx_data(txs)
        return self.build_multisig_tx(self.multisend, 0, data, SafeOperation.DELEGATE_CALL.value, safe_nonce=safe_nonce)

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

        See also https://github.com/gnosis/safe-cli/blob/master/safe_cli/api/gnosis_transaction.py
        """
        if not safe_tx.sorted_signers:
            self.sign_transaction(safe_tx)

        self.transaction_service.post_transaction(safe_tx)

    def post_signature(self, safe_tx: SafeTx, signature: bytes):
        """
        Submit a confirmation signature to a transaction service.
        """
        self.transaction_service.post_signatures(safe_tx.safe_tx_hash, signature)

    @property
    def pending_transactions(self) -> List[SafeTx]:
        """
        Retrieve pending transactions from the transaction service.
        """
        results = self.transaction_service._get_request(f'/api/v1/safes/{self.address}/transactions/').json()['results']
        nonce = self.retrieve_nonce()
        transactions = [
            self.build_multisig_tx(
                to=tx['to'],
                value=int(tx['value']),
                data=HexBytes(tx['data'] or b''),
                operation=tx['operation'],
                safe_tx_gas=tx['safeTxGas'],
                base_gas=tx['baseGas'],
                gas_price=int(tx['gasPrice']),
                gas_token=tx['gasToken'],
                refund_receiver=tx['refundReceiver'],
                signatures=self.confirmations_to_signatures(tx['confirmations']),
                safe_nonce=tx['nonce'],
            )
            for tx in reversed(results)
            if tx['nonce'] >= nonce and not tx['isExecuted']
        ]
        return transactions

    def confirmations_to_signatures(self, confirmations: List[Dict]) -> bytes:
        """
        Convert confirmations as returned by the transaction service to combined signatures.
        """
        sorted_confirmations = sorted(confirmations, key=lambda conf: int(conf['owner'], 16))
        signatures = [bytes(HexBytes(conf['signature'])) for conf in sorted_confirmations]
        return b''.join(signatures)

    def estimate_gas(self, safe_tx: SafeTx) -> int:
        """
        Estimate gas limit for successful execution.
        """
        return self.estimate_tx_gas(safe_tx.to, safe_tx.value, safe_tx.data, safe_tx.operation)

    def set_storage(self, account: str, slot: int, value: int):
        params = [account, hex(slot), encode_hex(encode_abi(['uint'], [value]))]

        if web3.clientVersion.startswith('anvil'):
            web3.manager.request_blocking('anvil_setStorageAt', params)
        elif web3.clientVersion.startswith('Hardhat'):
            web3.manager.request_blocking('hardhat_setStorageAt', params)
        else:
            raise NotImplementedError(f'setting storage is not supported for {web3.clientVersion}')

    def preview_tx(self, safe_tx: SafeTx, events=True, call_trace=False) -> TransactionReceipt:
        tx = copy(safe_tx)
        safe = Contract.from_abi('Gnosis Safe', self.address, self.get_contract().abi)
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
        tx.signatures = b''.join([encode_abi(['address', 'uint'], [str(owner), 0]) + b'\x01' for owner in owners])

        # approvedHashes are in slot 8 and have type of mapping(address => mapping(bytes32 => uint256))
        for owner in owners[:threshold]:
            outer_key = keccak(encode_abi(['address', 'uint'], [str(owner), 8]))
            slot = int.from_bytes(keccak(tx.safe_tx_hash + outer_key), 'big')
            self.set_storage(tx.safe_address, slot, 1)

        payload = tx.w3_tx.buildTransaction()
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
        payload = safe_tx.w3_tx.buildTransaction()
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
        payload = safe_tx.w3_tx.buildTransaction()
        tx = {
            "from": account,
            "to": self.address,
            "value": payload["value"],
            "nonce": frame.eth.get_transaction_count(account),
            "gas": web3.toHex(payload["gas"]),
            "data": HexBytes(payload["data"]),
        }
        frame.eth.send_transaction(tx)

    def preview_pending(self, events=True, call_trace=False):
        """
        Dry run all pending transactions in a forked environment.
        """
        for safe_tx in self.pending_transactions:
            self.preview_tx(safe_tx, events=events, call_trace=call_trace)
