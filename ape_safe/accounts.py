import json
from itertools import islice
from pathlib import Path
from typing import Iterator, List, Optional, Set, Type, Union

import click
from ape.api.accounts import AccountAPI, AccountContainerAPI, TransactionAPI
from ape.contracts import ContractInstance
from ape.exceptions import ContractLogicError
from ape.logging import logger
from ape.types import AddressType, MessageSignature, SignableMessage
from ape.utils import cached_property
from ape_ethereum.transactions import TransactionType
from eip712.common import create_safe_tx_def
from eth_utils import to_bytes

from .client import SafeClient, SafeTx
from .exceptions import NotEnoughSignatures, SafeLogicError


class AccountContainer(AccountContainerAPI):
    @property
    def _account_files(self) -> Iterator[Path]:
        yield from self.data_folder.glob("*.json")

    @property
    def aliases(self) -> Iterator[str]:
        for p in self._account_files:
            yield p.stem

    def __len__(self) -> int:
        return len([*self._account_files])

    @property
    def accounts(self) -> Iterator[AccountAPI]:
        for account_file in self._account_files:
            yield SafeAccount(account_file_path=account_file)  # type: ignore

    def save_account(self, alias: str, address: str):
        """
        Save a new Safe to your ape configuration.
        """
        chain_id = self.provider.chain_id
        account_data = {"address": address, "deployed_chain_ids": [chain_id]}
        path = self.data_folder.joinpath(f"{alias}.json")
        path.write_text(json.dumps(account_data))

    def load_account(self, alias: str) -> "SafeAccount":
        account_path = self.data_folder.joinpath(f"{alias}.json")
        return SafeAccount(account_file_path=account_path)

    def delete_account(self, alias: str):
        path = self.data_folder.joinpath(f"{alias}.json")

        if path.exists():
            path.unlink()


class SafeAccount(AccountAPI):
    account_file_path: Path  # NOTE: Cache any relevant data here

    @property
    def alias(self) -> str:
        return self.account_file_path.stem

    @property
    def account_file(self) -> dict:
        return json.loads(self.account_file_path.read_text())

    @property
    def address(self) -> AddressType:
        return self.network_manager.ethereum.decode_address(self.account_file["address"])

    @property
    def contract(self) -> ContractInstance:
        return self.chain_manager.contracts.instance_at(self.address)

    @cached_property
    def client(self) -> SafeClient:
        if self.provider.chain_id not in self.account_file["deployed_chain_ids"]:
            raise  # Not valid on this chain

        return SafeClient(address=self.address, chain_id=self.provider.chain_id)

    @property
    def version(self) -> str:
        try:
            return self.client.safe_details.version
        except Exception:
            return self.contract.VERSION()

    @property
    def signers(self) -> Set[AddressType]:
        # NOTE: Signers are in order because of `Set`
        try:
            return set(self.client.safe_details.owners)
        except Exception:
            return set(self.contract.getOwners())

    @property
    def confirmations_required(self) -> int:
        try:
            return self.client.safe_details.threshold
        except Exception:
            return self.contract.getThreshold()

    @property
    def next_nonce(self) -> int:
        try:
            return self.client.get_next_nonce()
        except Exception:
            return self.contract._view_methods_["nonce"]()

    def sign_message(self, msg: SignableMessage) -> Optional[MessageSignature]:
        raise NotImplementedError("Safe accounts do not support message signing!")

    @property
    def safe_tx_def(self) -> Type[SafeTx]:
        return create_safe_tx_def(
            version=self.version,
            contract_address=self.address,
            chain_id=self.provider.chain_id,
        )

    def create_safe_tx(self, txn: Optional[TransactionAPI] = None, **safe_tx_kwargs) -> SafeTx:
        safe_tx = {}
        safe_tx["to"] = safe_tx_kwargs.get(
            "to", txn.receiver if txn else self.address  # Self-call, e.g. rejection
        )
        safe_tx["value"] = safe_tx_kwargs.get("value", txn.value if txn else 0)
        safe_tx["data"] = safe_tx_kwargs.get("data", txn.data if txn else b"")
        safe_tx["nonce"] = safe_tx_kwargs.get("nonce", self.nonce)
        safe_tx["operation"] = safe_tx_kwargs.get("operation", 0)

        safe_tx["safeTxGas"] = safe_tx_kwargs.get("safeTxGas", 0)
        safe_tx["baseGas"] = safe_tx_kwargs.get("baseGas", 0)
        safe_tx["gasPrice"] = safe_tx_kwargs.get("gasPrice", 0)
        safe_tx["gasToken"] = safe_tx_kwargs.get(
            "gasToken", "0x0000000000000000000000000000000000000000"
        )
        safe_tx["refundReceiver"] = safe_tx_kwargs.get(
            "refundReceiver", "0x0000000000000000000000000000000000000000"
        )

        return self.safe_tx_def(**safe_tx)

    @property
    def local_signers(self) -> List[AccountAPI]:
        # NOTE: Signers are ordered, this is very important
        # TODO: Use config to skip any local signers
        return list(
            self.account_manager[address]
            for address in sorted(self.signers)
            if address in self.account_manager
        )

    def get_signatures(
        self, safe_tx: SafeTx, skip: Optional[AccountAPI] = None
    ) -> Iterator[MessageSignature]:
        for signer in self.local_signers:
            if skip and signer == skip:
                continue

            if not click.confirm(f"Should {signer} sign?"):
                continue

            if sig := signer.sign_message(safe_tx.signable_message):  # type: ignore[arg-type]
                yield sig

    def create_execute_transaction(
        self,
        safe_tx: SafeTx,
        signatures: List[MessageSignature],
        **txn_options,
    ) -> TransactionAPI:
        exec_args = list(safe_tx._body_["message"].values())[:-1]  # NOTE: Skip `nonce`
        encoded_signatures = b"".join(sig.encode_rsv() for sig in signatures)

        # Try to catch Gnosis Safe error codes before submitting
        # NOTE: executes a `ProviderAPI.prepare_transaction`, which may produce `ContractLogicError`
        try:
            return self.contract.execTransaction.as_transaction(
                *exec_args, encoded_signatures, **txn_options
            )

        except ContractLogicError as e:
            if e.message.startswith("GS"):
                raise SafeLogicError(e.message) from e

            else:
                raise e

    def sign_transaction(
        self,
        txn: TransactionAPI,
        submit_transaction: bool = True,
        submitter: Union[AddressType, str, None] = None,
        **signer_options,
    ) -> Optional[TransactionAPI]:
        safe_tx = self.create_safe_tx(txn, **signer_options)

        # Determine who is submitting the transaction (if enough signatures are gathered)
        if not submit_transaction:
            sender = None

        else:
            if not submitter:
                sender = self.local_signers[0]

            elif submitter in self.account_manager.aliases:
                sender = self.account_manager.load(submitter)

            elif (
                submitter_address := self.conversion_manager.convert(submitter, AddressType)
                in self.account_manager
            ):
                sender = self.account_manager[submitter_address]

            else:
                raise  # Can't find `submitter`!

        # Garner either M or M - 1 signatures, depending on if we are submitting
        # and whether the submitter is also a signer (both must be true to submit M - 1).
        if (
            sender  # NOTE: sender is None if submit_transaction is True
            and sender.address in self.signers
        ):
            signatures_required = self.confirmations_required - 1

        else:
            signatures_required = self.confirmations_required

        # TODO: Allow specifying an order via Config
        sigs = list(islice(self.get_signatures(safe_tx, skip=sender), signatures_required))

        if (
            sender  # NOTE: sender is None if submit_transaction is True
            # We have enough signatures to commit the transaction,
            # and a non-signer will submit it as their own transaction
            and len(sigs) >= signatures_required
        ):
            # We need to encode the submitter's address for Safe to decode
            if len(sigs) < self.confirmations_required:
                sigs.insert(
                    # TODO: Not sure if there's a better way to do this, might be buggy
                    self.local_signers.index(sender),
                    MessageSignature(  # type: ignore[call-arg]
                        v=1,
                        r=b"\x00" * 12 + to_bytes(hexstr=sender.address),
                        s=b"\x00" * 32,
                    ),
                )

            # Inherit gas args
            gas_args = {}
            # TODO: Set limit in a way to respects what Safe uses
            gas_args["gas_limit"] = (
                3 * txn.gas_limit // 2 if isinstance(txn.gas_limit, int) else txn.gas_limit
            )

            if txn.type == TransactionType.STATIC:
                gas_args["gas_price"] = txn.gas_price  # type: ignore[attr-defined]

            else:
                gas_args["max_fee"] = txn.max_fee
                gas_args["max_priority_fee"] = txn.max_priority_fee

            exec_transaction = self.create_execute_transaction(
                safe_tx,
                sigs,
                nonce=sender.nonce,  # TODO: Why do we need this?
                **gas_args,
            )
            return sender.sign_transaction(exec_transaction)

        elif submit_transaction:
            # NOTE: User wanted to submit transaction, but we can't, so don't publish to API
            raise NotEnoughSignatures(self.confirmations_required, len(sigs))

        elif sender:
            # Not enough signatures were gathered to submit, but signer didn't sign yet,
            # so might as well get one more from them before publishing confirmations to API.
            sigs.insert(
                # TODO: Not sure if there's a better way to do this, might be buggy
                self.local_signers.index(sender),
                sender.sign_message(safe_tx.signable_message),  # type: ignore[arg-type]
            )

        # NOTE: Not enough signatures were obtained to publish on-chain
        logger.info(
            f"Collected {len(sigs)}/{self.confirmations_required} signatures "
            f"for Safe {self.address}#{safe_tx.nonce}"  # TODO: put URI
        )
        # TODO: Submit safe_tx and sigs to Safe API
        return None
