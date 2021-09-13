from copy import copy
from typing import List, Union
from urllib.parse import urljoin

import click
import requests
from brownie import Contract, accounts, chain, history, web3
from brownie.convert.datatypes import EthAddress
from brownie.network.account import LocalAccount
from brownie.network.transaction import TransactionReceipt
from eth_abi import encode_abi
from gnosis.eth import EthereumClient
from gnosis.safe import Safe, SafeOperation
from gnosis.safe.multi_send import MultiSend, MultiSendOperation, MultiSendTx
from gnosis.safe.safe_tx import SafeTx


MULTISEND_CALL_ONLY = '0x40A2aCCbd92BCA938b02010E17A5b8929b49130D'
multisends = {
    250: '0x10B62CC1E8D9a9f1Ad05BCC491A7984697c19f7E',
}
transaction_service = {
    1: 'https://safe-transaction.mainnet.gnosis.io',
    4: 'https://safe-transaction.rinkeby.gnosis.io',
    5: 'https://safe-transaction.goerli.gnosis.io',
    56: 'https://safe-transaction.bsc.gnosis.io',
    100: 'https://safe-transaction.xdai.gnosis.io',
    137: 'https://safe-transaction.polygon.gnosis.io',
    250: 'https://safe.fantom.network',
    246: 'https://safe-transaction.ewc.gnosis.io',
    42161: 'https://safe-transaction.arbitrum.gnosis.io',
    73799: 'https://safe-transaction.volta.gnosis.io',
}


class ExecutionFailure(Exception):
    pass


class ApiError(Exception):
    pass


class ApeSafe(Safe):

    def __init__(self, address, base_url=None, multisend=None):
        """
        Create an ApeSafe from an address or a ENS name and use a default connection.
        """
        if not web3.isChecksumAddress(address):
            address = web3.ens.resolve(address)
        ethereum_client = EthereumClient(web3.provider.endpoint_uri)
        self.base_url = base_url or transaction_service[chain.id]
        self.multisend = multisend or multisends.get(chain.id, MULTISEND_CALL_ONLY)
        super().__init__(address, ethereum_client)

    def __str__(self):
        return EthAddress(self.address)

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
        if not web3.isChecksumAddress(address):
            address = web3.ens.resolve(address)
        return Contract(address, owner=self.account)

    def pending_nonce(self) -> int:
        """
        Subsequent nonce which accounts for pending transactions in the transaction service.
        """
        url = urljoin(self.base_url, f'/api/v1/safes/{self.address}/multisig-transactions/')
        results = requests.get(url).json()['results']
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
        data = MultiSend(self.multisend, self.ethereum_client).build_tx_data(txs)
        return self.build_multisig_tx(self.multisend, 0, data, SafeOperation.DELEGATE_CALL.value, safe_nonce=safe_nonce)

    def sign_transaction(self, safe_tx: SafeTx, signer: Union[LocalAccount, str] = None) -> SafeTx:
        """
        Sign a Safe transaction with a local Brownie account.
        """
        if signer is None:
            signer = click.prompt('signer', type=click.Choice(accounts.load()))
        
        if isinstance(signer, str):
            # Avoids a previously impersonated account with no signing capabilities
            accounts.clear()
            signer = accounts.load(signer)
        
        safe_tx.sign(signer.private_key)
        return safe_tx

    def post_transaction(self, safe_tx: SafeTx):
        """
        Submit a Safe transaction to a transaction service.
        Estimates gas cost and prompts for a signature if needed.

        See also https://github.com/gnosis/safe-cli/blob/master/safe_cli/api/gnosis_transaction.py
        """
        if not safe_tx.sorted_signers:
            self.sign_transaction(safe_tx)
        
        sender = safe_tx.sorted_signers[0]

        url = urljoin(self.base_url, f'/api/v1/safes/{self.address}/multisig-transactions/')
        data = {
            'to': safe_tx.to,
            'value': safe_tx.value,
            'data': safe_tx.data.hex() if safe_tx.data else None,
            'operation': safe_tx.operation,
            'gasToken': safe_tx.gas_token,
            'safeTxGas': safe_tx.safe_tx_gas,
            'baseGas': safe_tx.base_gas,
            'gasPrice': safe_tx.gas_price,
            'refundReceiver': safe_tx.refund_receiver,
            'nonce': safe_tx.safe_nonce,
            'contractTransactionHash': safe_tx.safe_tx_hash.hex(),
            'sender': sender,
            'signature': safe_tx.signatures.hex() if safe_tx.signatures else None,
            'origin': 'github.com/banteg/ape-safe',
        }
        response = requests.post(url, json=data)
        if not response.ok:
            raise ApiError(f'Error posting transaction: {response.content}')

    def estimate_gas(self, safe_tx: SafeTx) -> int:
        """
        Estimate gas limit for successful execution.
        """
        return self.estimate_tx_gas(safe_tx.to, safe_tx.value, safe_tx.data, safe_tx.operation)

    def preview(self, safe_tx: SafeTx, events=True, call_trace=False, reset=True, gas_limit=None):
        """
        Dry run a Safe transaction in a forked network environment.
        """
        if reset:
            chain.reset()
        tx = copy(safe_tx)
        safe = Contract.from_abi('Gnosis Safe', self.address, self.get_contract().abi)
        # Replace pending nonce with the subsequent nonce
        tx.safe_nonce = safe.nonce()
        # Forge signatures from the needed amount of owners, skip the one which submits the tx
        # Owners must be sorted numerically, sorting as checksum addresses may yield wrong order
        owners = [accounts.at(owner, force=True) for owner in sorted(safe.getOwners(), key=str.lower)]
        threshold = safe.getThreshold()
        for owner in owners[1:threshold]:
            safe.approveHash(tx.safe_tx_hash.hex(), {'from': owner, 'gas_price': 0, 'gas_limit': gas_limit})

        # Signautres are encoded as [bytes32 r, bytes32 s, bytes8 v]
        # Pre-validated signatures are encoded as r=owner, s unused and v=1.
        # https://docs.gnosis.io/safe/docs/contracts_signatures/#pre-validated-signatures
        signatures = b''.join([encode_abi(['address', 'uint'], [str(owner), 0]) + b'\x01' for owner in owners[:threshold]])
        args = [
            tx.to,
            tx.value,
            tx.data,
            tx.operation,
            tx.safe_tx_gas,
            tx.base_gas,
            tx.gas_price,
            tx.gas_token,
            tx.refund_receiver,
            signatures,
        ]

        receipt = safe.execTransaction(*args, {'from': owners[0], 'gas_price': 0, 'gas_limit': gas_limit})
        if 'ExecutionSuccess' not in receipt.events:
            receipt.info()
            receipt.call_trace(True)
            raise ExecutionFailure()
        
        if events:
            receipt.info()

        if call_trace:
            receipt.call_trace(True)

        # Offset gas refund for clearing storage when on-chain signatures are consumed.
        # https://github.com/gnosis/safe-contracts/blob/v1.1.1/contracts/GnosisSafe.sol#L140
        refunded_gas = 15_000 * (threshold - 1)
        click.secho(f'recommended gas limit: {receipt.gas_used + refunded_gas}', fg='green', bold=True)

        return receipt

    def preview_pending(self, events=True, call_trace=False):
        """
        Dry run all pending transactions in a forked environment.
        """
        safe = Contract.from_abi('Gnosis Safe', self.address, self.get_contract().abi)
        url = urljoin(self.base_url, f'/api/v1/safes/{self.address}/transactions/')
        txs = requests.get(url).json()['results']
        nonce = safe.nonce()
        pending = [tx for tx in reversed(txs) if not tx['isExecuted'] and tx['nonce'] >= nonce]
        for tx in pending:
            safe_tx = self.build_multisig_tx(tx['to'], int(tx['value']), tx['data'] or b'', operation=tx['operation'], safe_nonce=tx['nonce'])
            self.preview(safe_tx, events=events, call_trace=call_trace, reset=False)
