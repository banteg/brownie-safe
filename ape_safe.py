from copy import copy
from typing import List, Union
from urllib.parse import urljoin

import click
import requests
from brownie import Contract, accounts, chain, history, web3
from brownie.network.account import LocalAccount
from brownie.network.transaction import TransactionReceipt
from eth_abi import encode_abi
from gnosis.eth import EthereumClient
from gnosis.safe import Safe, SafeOperation
from gnosis.safe.multi_send import MultiSend, MultiSendOperation, MultiSendTx
from gnosis.safe.safe_tx import SafeTx


class ExecutionFailure(Exception):
    pass


class ApiError(Exception):
    pass


class ApeSafe(Safe):
    base_url = 'https://safe-transaction.mainnet.gnosis.io'
    multisend = '0x8D29bE29923b68abfDD21e541b9374737B49cdAD'

    def __init__(self, address, ethereum_client: EthereumClient = None):
        """
        Create an ApeSafe from an address or a ENS name and use a default connection.
        """
        if not web3.isChecksumAddress(address):
            address = web3.ens.resolve(address)
        if ethereum_client is None:
            ethereum_client = EthereumClient()
        super().__init__(address, ethereum_client)

    @property
    def account(self):
        return accounts.at(self.address, force=True)

    def contract(self, address) -> Contract:
        if not web3.isChecksumAddress(address):
            address = web3.ens.resolve(address)
        return Contract(address, owner=self.account)

    def pending_nonce(self):
        """
        Return the next nonce accounting for pending transactions in the Transaction service.
        """
        url = urljoin(self.base_url, f'/api/v1/safes/{self.address}/multisig-transactions/')
        results = requests.get(url).json()['results']
        return results[0]['nonce'] + 1 if results else 0

    def tx_from_receipt(self, receipt: TransactionReceipt, operation: SafeOperation = SafeOperation.CALL, safe_nonce: int = None):
        """
        Convert Brownie receipt into a Safe transaction.
        """
        if safe_nonce is None:
            safe_nonce = self.pending_nonce()
        
        return self.build_multisig_tx(receipt.receiver, receipt.value, receipt.input, operation=operation.value, safe_nonce=safe_nonce)

    def multisend_from_receipts(self, receipts: List[TransactionReceipt] = None, safe_nonce: int = None):
        """
        Convert Brownie tx receipts (or history) to a multisend Safe transaction.
        """
        if receipts is None:
            receipts = history.from_sender(self.address)
        
        if safe_nonce is None:
            safe_nonce = self.pending_nonce()
        
        txs = [MultiSendTx(MultiSendOperation.CALL, tx.receiver, tx.value, tx.input) for tx in receipts]
        data = MultiSend(self.multisend, self.ethereum_client).build_tx_data(txs)
        return self.build_multisig_tx(self.multisend, 0, data, SafeOperation.DELEGATE_CALL.value, safe_nonce=safe_nonce)

    def sign_transaction(self, safe_tx: SafeTx, signer: Union[LocalAccount, str] = None):
        """
        Sign a Safe transaction using a local Brownie account.
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
        Prompts for a signature and estimates gas cost if needed.

        See also https://github.com/gnosis/safe-cli/blob/master/safe_cli/api/gnosis_transaction.py
        """
        if not safe_tx.sorted_signers:
            self.sign_transaction(safe_tx)
        
        sender = safe_tx.sorted_signers[0]

        if safe_tx.safe_tx_gas == 0:
            safe_tx.safe_tx_gas = self.estimate_gas(safe_tx)
        
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
        return self.estimate_tx_gas(safe_tx.to, safe_tx.value, safe_tx.data, safe_tx.operation)

    def preview(self, safe_tx: SafeTx, events=True, call_trace=False):
        """
        Dry run a Safe transaction in a forked environment.
        """
        chain.reset()
        tx = copy(safe_tx)
        safe = Contract.from_abi('Gnosis Safe', self.address, self.get_contract().abi)
        # replace pending nonce with the subsequent nonce
        tx.safe_nonce = safe.nonce()
        # Forge signatures from the needed amount of owners, skip the one which submits the tx
        owners = [accounts.at(owner, force=True) for owner in sorted(safe.getOwners())]
        threshold = safe.getThreshold()
        for owner in owners[1:threshold]:
            safe.approveHash(tx.safe_tx_hash.hex(), {'from': owner})
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

        receipt = safe.execTransaction(*args, {'from': owners[0]})
        if 'ExecutionSuccess' not in receipt.events:
            receipt.info()
            receipt.call_trace(True)
            raise ExecutionFailure()
        
        if events:
            receipt.info()

        if call_trace:
            receipt.call_trace(True)

        return receipt
