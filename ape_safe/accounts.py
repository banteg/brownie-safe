import json
from itertools import islice
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Tuple, Type, Union

from ape.api import AccountAPI, AccountContainerAPI, ReceiptAPI, TransactionAPI
from ape.api.address import BaseAddress
from ape.contracts import ContractInstance
from ape.exceptions import ContractLogicError
from ape.logging import logger
from ape.types import AddressType, MessageSignature, SignableMessage
from ape.utils import cached_property
from ape_ethereum.transactions import TransactionType
from eip712.common import create_safe_tx_def
from eth_utils import to_bytes, to_int

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
    def signers(self) -> List[AddressType]:
        # NOTE: Signers are in order because of `Set`
        try:
            return self.client.safe_details.owners
        except Exception:
            return self.contract.getOwners()

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
        safe_tx["nonce"] = safe_tx_kwargs.get(
            "nonce", self.next_nonce
        )  # NOTE: Caution do NOT use self.nonce
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
        # TODO: Use config to skip any local signers
        return list(
            self.account_manager[address]
            for address in self.signers
            if address in self.account_manager
        )

    def get_signatures(
        self,
        safe_tx: SafeTx,
        signers: Iterable[AccountAPI],
    ) -> Iterator[Tuple[AddressType, MessageSignature]]:
        for signer in signers:
            if sig := signer.sign_message(safe_tx.signable_message):
                yield signer.address, sig

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

    def compute_prev_signer(self, signer: Union[str, AddressType, BaseAddress]) -> AddressType:
        """
        Sometimes it's handy to have "previous owner" for ownership change operations,
        this function makes it easy to calculate.
        """
        signer_address: AddressType = self.conversion_manager.convert(signer, AddressType)
        signers = self.contract.getOwners()  # NOTE: Use contract version to ensure correctness
        if signer_address not in signers:
            raise  # not a signer

        index = signers.index(signer_address)
        if index > 0:
            return signers[index - 1]

        # NOTE: SENTINEL_OWNERS is the "previous" address to index 0
        return AddressType("0x0000000000000000000000000000000000000001")  # type: ignore[arg-type]

    def prepare_transaction(self, txn: TransactionAPI) -> TransactionAPI:
        # NOTE: Need to override `AccountAPI` behavior for balance checks
        return self.provider.prepare_transaction(txn)

    def call(self, txn: TransactionAPI, **call_kwargs) -> ReceiptAPI:  # type: ignore[override]
        # NOTE: Override just to produce a more specific exception with better error message
        try:
            return super().call(txn, **call_kwargs)
        except ContractLogicError as e:
            if e.message.startswith("GS"):
                raise SafeLogicError(e.message) from e

            else:
                raise e

    def sign_transaction(
        self,
        txn: TransactionAPI,
        submit: bool = True,
        submitter: Union[AccountAPI, AddressType, str, None] = None,
        skip: Optional[List[Union[AccountAPI, AddressType, str]]] = None,
        **signer_options,
    ) -> Optional[TransactionAPI]:
        # TODO: Docstring (override AccountAPI)
        safe_tx = self.create_safe_tx(txn, **signer_options)

        # Determine who is submitting the transaction (if enough signatures are gathered)
        if not submit:
            if submitter:
                raise  # Cannot specify a submitter if not submitting

            sender = None

        else:
            if not submitter:
                sender = self.local_signers[0]

            elif isinstance(submitter, AccountAPI):
                sender = submitter

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
        available_signers = iter(self.local_signers)
        if sender and sender.address in self.signers:
            # Sender doesn't have to sign
            signatures_required = self.confirmations_required - 1
            available_signers = filter(lambda s: s != sender, available_signers)

        else:  # NOTE: sender is None if submit is False
            # Not submitting, or sender isn't a signer, so we need all confirmations
            signatures_required = self.confirmations_required

        # Allow bypassing any specified signers
        if skip:
            skip_addresses = [self.conversion_manager.convert(a, AddressType) for a in skip]

            def skip_signer(signer: AccountAPI):
                return signer.address not in skip_addresses

            available_signers = filter(skip_signer, available_signers)

        # TODO: Allow re-ordering via Config

        # Attempt to fetch just enough signatures to satisfy the amount we need
        # NOTE: It is okay to have less signatures, but it never should fetch more than needed
        sigs_by_signer = dict(
            islice(self.get_signatures(safe_tx, available_signers), signatures_required)
        )
        # Invariant: len(sigs_by_signer) <= signatures_required

        if (
            sender  # NOTE: sender is None if submit_transaction is False
            # We have enough signatures to commit the transaction,
            # and a non-signer will submit it as their own transaction
            and len(sigs_by_signer) == signatures_required
        ):
            # We need to encode the submitter's address for Safe to decode
            if len(sigs_by_signer) < self.confirmations_required:
                sigs_by_signer[sender.address] = MessageSignature(  # type: ignore[call-arg]
                    v=1,  # Approved hash (e.g. submitter is approved)
                    r=b"\x00" * 12 + to_bytes(hexstr=sender.address),
                    s=b"\x00" * 32,
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

            # NOTE: Must order signatures in ascending order of signer address (converted to int)
            def addr2int(a):
                return to_int(hexstr=a)

            sigs = [sigs_by_signer[signer] for signer in sorted(sigs_by_signer, key=addr2int)]

            exec_transaction = self.create_execute_transaction(
                safe_tx,
                sigs,
                nonce=sender.nonce,  # TODO: Why do we need this?
                **gas_args,
            )
            return sender.sign_transaction(exec_transaction)

        elif submit:
            # NOTE: User wanted to submit transaction, but we can't, so don't publish to API
            raise NotEnoughSignatures(self.confirmations_required, len(sigs_by_signer))

        elif sender and sender.address in self.signers:
            # Not enough signatures were gathered to submit, but signer didn't sign yet either,
            # so might as well get one more from them before publishing confirmations to API.
            if sig := sender.sign_message(safe_tx.signable_message):
                sigs_by_signer[sender.address] = sig

        # NOTE: Not enough signatures were obtained to publish on-chain
        logger.info(
            f"Collected {len(sigs_by_signer)}/{self.confirmations_required} signatures "
            f"for Safe {self.address}#{safe_tx.nonce}"  # TODO: put URI
        )
        # TODO: Submit safe_tx and sigs to Safe API
        return None
