from typing import List

from ape.api import ReceiptAPI, TransactionAPI
from ape.contracts.base import ContractInstance, ContractTransactionHandler
from ape.types import ContractType, HexBytes
from ape.utils import ManagerAccessMixin, cached_property
from eth_abi.packed import encode_packed

from .exceptions import UnsupportedChainError, ValueRequired

MULTISEND_CODE = HexBytes(
    "0x60806040526004361061001e5760003560e01c80638d80ff0a14610023575b600080fd5b6100dc6004803603602"
    "081101561003957600080fd5b810190808035906020019064010000000081111561005657600080fd5b8201836020"
    "8201111561006857600080fd5b8035906020019184600183028401116401000000008311171561008a57600080fd5"
    "b91908080601f01602080910402602001604051908101604052809392919081815260200183838082843760008184"
    "0152601f19601f8201169050808301925050505050505091929192905050506100de565b005b7f000000000000000"
    "000000000a238cbeb142c10ef7ad8442c6d1f9e89e07e776173ffffffffffffffffffffffffffffffffffffffff16"
    "3073ffffffffffffffffffffffffffffffffffffffff161415610183576040517f08c379a00000000000000000000"
    "000000000000000000000000000000000000081526004018080602001828103825260308152602001806102106030"
    "913960400191505060405180910390fd5b805160205b8181101561020a578083015160f81c6001820184015160601"
    "c6015830185015160358401860151605585018701600085600081146101cd57600181146101dd576101e8565b6000"
    "808585888a5af191506101e8565b6000808585895af491505b5060008114156101f757600080fd5b8260550187019"
    "650505050505050610188565b50505056fe4d756c746953656e642073686f756c64206f6e6c792062652063616c6c"
    "6564207669612064656c656761746563616c6ca26469706673582212205c784303626eec02b71940b551976170b50"
    "0a8a36cc5adcbeb2c19751a76d05464736f6c63430007060033"
)
DEFAULT_ADDRESS = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"
DEPLOYMENT_ADDRESS = {
    10: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    25: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    28: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    61: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    63: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    69: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    82: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    83: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    106: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    111: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    288: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    322: "0x6367360366E4c898488091ac315834B779d8f561",
    338: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    420: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    588: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    595: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    599: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    686: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    787: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    1001: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    1088: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    1294: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    7700: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    8217: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    10000: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    10001: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    42220: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    43114: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    54211: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    71401: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    71402: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    11155111: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    1666600000: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
    1666700000: "0x998739BFdAAdde7C933B942a68053933098f9EDa",
}
MULTISEND_CONTRACT_TYPE = {
    "contractName": "MultiSend",
    "abi": [
        {"inputs": [], "stateMutability": "nonpayable", "type": "constructor"},
        {
            "inputs": [{"internalType": "bytes", "name": "transactions", "type": "bytes"}],
            "name": "multiSend",
            "outputs": [],
            "stateMutability": "payable",
            "type": "function",
        },
    ],
}


class MultiSend(ManagerAccessMixin):
    """
    Create a sequence of calls to execute at once using ``eth_sendTransaction``
    via the MultiSend contract.

    Usage example::

        from ape_safe import multisend

        txn = multisend.Transaction()
        txn.add(contract.myMethod, *call_args)
        txn.add(contract.myMethod, *call_args)
        ...  # Add as many calls as desired to execute
        txn.add(contract.myMethod, *call_args)
        receipt = txn(sender=my_signer)  # Sends the multisend transaction
    """

    def __init__(self) -> None:
        """
        Initialize a new Multicall session object. By default, there are no calls to make.
        """
        self.calls: List[dict] = []

    @classmethod
    def inject(cls):
        """
        Create the multicall module contract on-chain, so we can use it.
        Must use a provider that supports ``debug_setCode``.

        Usage example::

            from ape_ethereum import multicall

            @pytest.fixture(scope="session")
            def use_multicall():
                # NOTE: use this fixture any test where you want to use a multicall
                multicall.BaseMulticall.deploy()
        """
        active_provider = cls.network_manager.active_provider
        assert active_provider, "Must be connected to an active network to deploy"

        active_provider.set_code(
            DEFAULT_ADDRESS,
            MULTISEND_CODE,
        )

    @cached_property
    def contract(self) -> ContractInstance:
        multisend_address = DEPLOYMENT_ADDRESS.get(self.provider.chain_id, DEFAULT_ADDRESS)

        # All versions have this ABI
        contract = self.chain_manager.contracts.instance_at(
            multisend_address,
            contract_type=ContractType.parse_obj(MULTISEND_CONTRACT_TYPE),
        )

        if contract.code != MULTISEND_CODE:
            raise UnsupportedChainError()

        return contract

    @property
    def handler(self) -> ContractTransactionHandler:
        return self.contract.multiSend

    def add(
        self,
        call,
        *args,
        delegatecall=False,
        value=0,
    ):
        """
        Adds a call to the Multicall session object.

        Raises:
            :class:`InvalidOption`: If one of the kwarg modifiers is not able to be used.

        Args:
            call: :class:`ContractMethodHandler` The method to call.
            *args: The arguments to invoke the method with.
            delegatecall: bool Whether the call should be processed using delegatecall.
            value: int The amount of ether to forward with the call.
        """
        self.calls.append(
            {
                "operation": int(delegatecall),
                "target": call.contract.address,
                "value": value or 0,
                "callData": call.encode_input(*args),
            }
        )

    def _validate_calls(self, **txn_kwargs) -> None:
        required_value = sum(call["value"] for call in self.calls)
        if required_value > 0:
            if "value" not in txn_kwargs:
                raise ValueRequired(required_value)

            value = self.conversion_manager.convert(txn_kwargs["value"], int)

            if required_value < value:
                raise ValueRequired(required_value)

        # NOTE: Won't fail if `value` is provided otherwise (won't do anything either)

    @property
    def encoded_calls(self):
        return [
            encode_packed(
                ["uint8", "address", "uint256", "uint256", "bytes"],
                [
                    call["operation"],
                    call["target"],
                    call["value"],
                    len(call["callData"]),
                    call["callData"],
                ],
            )
            for call in self.calls
        ]

    def __call__(self, **txn_kwargs) -> ReceiptAPI:
        """
        Execute the Multicall transaction. The transaction will broadcast again every time
        the ``Transaction`` object is called.

        Raises:
            :class:`UnsupportedChain`: If there is not an instance of Multicall3 deployed
              on the current chain at the expected address.

        Args:
            **txn_kwargs: the kwargs to pass through to the transaction handler.

        Returns:
            :class:`~ape.api.transactions.ReceiptAPI`
        """
        self._validate_calls(**txn_kwargs)
        return self.handler(b"".join(self.encoded_calls), **txn_kwargs)

    def as_transaction(self, **txn_kwargs) -> TransactionAPI:
        """
        Encode the Multicall transaction as a ``TransactionAPI`` object, but do not execute it.

        Returns:
            :class:`~ape.api.transactions.TransactionAPI`
        """
        self._validate_calls(**txn_kwargs)
        # NOTE: Will fail using `self.handler.as_transaction` because handler
        #       expects to be called only via delegatecall
        return self.network_manager.ecosystem.create_transaction(
            receiver=self.handler.contract.address,
            data=self.handler.encode_input(b"".join(self.encoded_calls)),
            **txn_kwargs,
        )
