import json
from itertools import islice
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Type, Union

from ape.api import AccountAPI, AccountContainerAPI, ReceiptAPI, TransactionAPI
from ape.api.address import BaseAddress
from ape.contracts import ContractInstance
from ape.logging import logger
from ape.types import AddressType, HexBytes, MessageSignature, SignableMessage
from ape.utils import cached_property
from ape_ethereum.transactions import TransactionType
from eip712.common import create_safe_tx_def
from eth_utils import keccak, to_bytes, to_int

from .client import SafeClient, SafeTx
from .exceptions import NoLocalSigners, NotASigner, NotEnoughSignatures, handle_safe_logic_error


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
        # NOTE: Is not ordered by signing order
        # TODO: Skip per user config
        # TODO: Order per user config
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

    @handle_safe_logic_error()
    def create_execute_transaction(
        self,
        safe_tx: SafeTx,
        signatures: Dict[AddressType, MessageSignature],
        **txn_options,
    ) -> TransactionAPI:
        exec_args = list(safe_tx._body_["message"].values())[:-1]  # NOTE: Skip `nonce`
        encoded_signatures = self._encode_signatures(signatures)

        # NOTE: executes a `ProviderAPI.prepare_transaction`, which may produce `ContractLogicError`
        return self.contract.execTransaction.as_transaction(
            *exec_args, encoded_signatures, **txn_options
        )

    def compute_prev_signer(self, signer: Union[str, AddressType, BaseAddress]) -> AddressType:
        """
        Sometimes it's handy to have "previous owner" for ownership change operations,
        this function makes it easy to calculate.
        """
        signer_address: AddressType = self.conversion_manager.convert(signer, AddressType)
        signers = self.contract.getOwners()  # NOTE: Use contract version to ensure correctness
        if signer_address not in signers:
            raise NotASigner(signer_address)

        index = signers.index(signer_address)
        if index > 0:
            return signers[index - 1]

        # NOTE: SENTINEL_OWNERS is the "previous" address to index 0
        return AddressType("0x0000000000000000000000000000000000000001")  # type: ignore[arg-type]

    def prepare_transaction(self, txn: TransactionAPI) -> TransactionAPI:
        # NOTE: Need to override `AccountAPI` behavior for balance checks
        return self.provider.prepare_transaction(txn)

    def _encode_signatures(self, signatures: Dict[AddressType, MessageSignature]) -> HexBytes:
        # NOTE: Must order signatures in ascending order of signer address (converted to int)
        def addr_to_int(a: AddressType) -> int:
            return to_int(hexstr=a)

        return HexBytes(
            b"".join(
                signatures[signer].encode_rsv() for signer in sorted(signatures, key=addr_to_int)
            )
        )

    def _safe_tx_exec_args(self, safe_tx: SafeTx) -> List:
        return list(safe_tx._body_["message"].values())

    def _preapproved_signature(
        self, signer: Union[AddressType, BaseAddress, str]
    ) -> MessageSignature:
        # Get the Safe-style "preapproval" signature type, which is a sentinel value used to denote
        # when a signer approved via some other method, such as `approveHash` or being `msg.sender`
        # TODO: Link documentation for this
        return MessageSignature(
            v=1,  # Approved hash (e.g. submitter is approved)
            r=b"\x00" * 12 + to_bytes(hexstr=self.conversion_manager.convert(signer, AddressType)),
            s=b"\x00" * 32,
        )

    @handle_safe_logic_error()
    def _impersonated_call(self, txn: TransactionAPI, **safe_tx_and_call_kwargs) -> ReceiptAPI:
        safe_tx = self.create_safe_tx(txn, **safe_tx_and_call_kwargs)
        safe_tx_exec_args = self._safe_tx_exec_args(safe_tx)
        signatures = {}

        # Bypass signature collection logic and attempt to submit by impersonation
        # NOTE: Only works for fork and local network providers that support `set_storage`
        safe_tx_hash = self.contract.getTransactionHash(*safe_tx_exec_args)
        for signer_address in self.signers[: self.confirmations_required]:
            # NOTE: `approvedHashes` is `address => safe_tx_hash => num_confs` @ slot 8
            # TODO: Use native ape slot indexing, once available
            address_bytes32 = to_bytes(hexstr=signer_address)
            address_bytes32 = b"\x00" * (32 - len(address_bytes32)) + address_bytes32
            key_hash = keccak(address_bytes32 + b"\x00" * 31 + to_bytes(8))
            slot = to_int(keccak(safe_tx_hash + key_hash))
            self.provider.set_storage(self.address, slot, to_bytes(1))

            signatures[signer_address] = self._preapproved_signature(signer_address)

        # NOTE: Could raise a `SafeContractError`
        safe_tx_and_call_kwargs["sender"] = safe_tx_and_call_kwargs.get(
            "submitter",
            # NOTE: Use whatever the last signer was if no `submitter`
            self.account_manager.test_accounts[signer_address],
        )
        return self.contract.execTransaction(
            *safe_tx_exec_args[:-1],  # NOTE: Skip nonce
            self._encode_signatures(signatures),
            **safe_tx_and_call_kwargs,
        )

    @handle_safe_logic_error()
    def call(  # type: ignore[override]
        self,
        txn: TransactionAPI,
        impersonate: bool = False,
        **call_kwargs,
    ) -> ReceiptAPI:
        if impersonate:
            return self._impersonated_call(txn, **call_kwargs)

        return super().call(txn, **call_kwargs)

    def _contract_approvals(self, safe_tx: SafeTx) -> Dict[AddressType, MessageSignature]:
        safe_tx_exec_args = self._safe_tx_exec_args(safe_tx)
        safe_tx_hash = self.contract.getTransactionHash(*safe_tx_exec_args)

        return {
            signer: self._preapproved_signature(signer)
            for signer in self.signers
            if self.contract.approvedHashes(signer, safe_tx_hash) > 0
        }

    def _all_approvals(self, safe_tx: SafeTx) -> Dict[AddressType, MessageSignature]:
        # TODO: Combine with approvals from SafeAPI
        return self._contract_approvals(safe_tx)

    def sign_transaction(
        self,
        txn: TransactionAPI,
        submit: bool = True,
        submitter: Union[AccountAPI, AddressType, str, None] = None,
        skip: Optional[List[Union[AccountAPI, AddressType, str]]] = None,
        signatures_required: Optional[int] = None,  # NOTE: Required if increasing threshold
        **signer_options,
    ) -> Optional[TransactionAPI]:
        # TODO: Docstring (override AccountAPI)
        safe_tx = self.create_safe_tx(txn, **signer_options)

        # Determine who is submitting the transaction (if enough signatures are gathered)
        if not submit and submitter:
            raise  # Cannot specify a submitter if not submitting

        elif submit and not submitter:
            if len(self.local_signers) == 0:
                raise NoLocalSigners()

            submitter = self.local_signers[0]
            logger.info(f"No submitter specified, so using: {submitter}")

        # NOTE: Works whether `submit` is set or not below here
        elif (
            submitter_address := self.conversion_manager.convert(submitter, AddressType)
            in self.account_manager
        ):
            submitter = self.account_manager[submitter_address]

        elif isinstance(submitter, str) and submitter in self.account_manager.aliases:
            submitter = self.account_manager.load(submitter)

        elif not isinstance(submitter, AccountAPI):
            raise  # Cannot handle `submitter=type(submitter)`

        # Invariant: `submitter` should be either `AccountAPI` or we are not submitting here
        assert isinstance(submitter, AccountAPI) or not submit

        # Garner either M or M - 1 signatures, depending on if we are submitting
        # and whether the submitter is also a signer (both must be true to submit M - 1).
        # NOTE: Will skip or reorder signers based on config
        available_signers = iter(self.local_signers)

        # If number of signatures required not specified, figure out how many are needed
        if not signatures_required:
            if submitter and submitter.address in self.signers:
                # Sender doesn't have to sign
                signatures_required = self.confirmations_required - 1
                # NOTE: Adjust signers to sign with by skipping submitter
                available_signers = filter(lambda s: s != submitter, available_signers)

            else:  # NOTE: `submitter` is `None` if `submit` is False
                # Not submitting, or submitter isn't a signer, so we need all confirmations
                signatures_required = self.confirmations_required

        # Allow bypassing any specified signers (above and beyond user config)
        if skip:
            skip_addresses = [self.conversion_manager.convert(a, AddressType) for a in skip]

            def skip_signer(signer: AccountAPI):
                return signer.address not in skip_addresses

            available_signers = filter(skip_signer, available_signers)

        # Check if transaction has existing tracked signatures
        sigs_by_signer = self._all_approvals(safe_tx)

        # Attempt to fetch just enough signatures to satisfy the amount we need
        # NOTE: It is okay to have less signatures, but it never should fetch more than needed
        sigs_by_signer.update(
            dict(
                islice(
                    self.get_signatures(safe_tx, available_signers),
                    signatures_required - len(sigs_by_signer),
                )
            )
        )

        if (
            submit  # NOTE: `submitter` should be set if `submit=True`
            # We have enough signatures to commit the transaction,
            # and a non-signer will submit it as their own transaction
            and len(sigs_by_signer) >= signatures_required
        ):
            # We need to encode the submitter's address for Safe to decode
            # NOTE: Should only be triggered if the `submitter` is also a signer
            if len(sigs_by_signer) < self.confirmations_required:
                sigs_by_signer[submitter.address] = self._preapproved_signature(submitter)

            # Inherit gas args from safe_tx, if set
            gas_args = {"gas_limit": txn.gas_limit}

            if txn.type == TransactionType.STATIC:
                gas_args["gas_price"] = txn.gas_price  # type: ignore[attr-defined]

            else:
                gas_args["max_fee"] = txn.max_fee
                gas_args["max_priority_fee"] = txn.max_priority_fee

            exec_transaction = self.create_execute_transaction(
                safe_tx,
                sigs_by_signer,
                **gas_args,
                nonce=submitter.nonce,  # NOTE: Required to correctly set nonce in encoded txn
            )
            return submitter.sign_transaction(exec_transaction, **signer_options)

        elif submit:
            # NOTE: User wanted to submit transaction, but we can't, so don't publish to API
            raise NotEnoughSignatures(signatures_required, len(sigs_by_signer))

        elif submitter and submitter.address in self.signers:
            # Not enough signatures were gathered to submit, but submitter also didn't sign yet,
            # so might as well get one more sig from them before publishing confirmations to API.
            if sig := submitter.sign_message(safe_tx.signable_message):
                sigs_by_signer[submitter.address] = sig

        # NOTE: Not enough signatures were obtained to publish on-chain
        logger.info(
            f"Collected {len(sigs_by_signer)}/{self.confirmations_required} signatures "
            f"for Safe {self.address}#{safe_tx.nonce}"  # TODO: put URI
        )
        # TODO: Submit safe_tx and sigs to Safe API
        return None
