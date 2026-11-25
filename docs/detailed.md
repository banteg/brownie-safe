# Detailed example

Wrap a small amount of ETH and transfer the resulting WETH in one Safe transaction. Start the [mainnet fork](install.md#configure-a-mainnet-fork) and use a deployed Safe with enough ETH for the example. The minimal WETH ABI lets Brownie load the contract without an explorer API key.

```python
from brownie import Contract
from brownie_safe import BrownieSafe

safe = BrownieSafe(input("Safe address or ENS name: ").strip())
recipient = input("WETH recipient address: ").strip()
amount = 10**15  # 0.001 ETH, in wei

weth_abi = [
    {
        "type": "function", "name": "deposit", "stateMutability": "payable",
        "inputs": [], "outputs": [],
    },
    {
        "type": "function", "name": "transfer", "stateMutability": "nonpayable",
        "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
]
weth = Contract.from_abi(
    "WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", weth_abi, owner=safe.account,
)
deposit = weth.deposit({"value": amount})
transfer = weth.transfer(recipient, amount)
receipts = [deposit, transfer]

safe_tx = safe.multisend_from_receipts(receipts, safe_nonce=safe.retrieve_nonce())
receipt = safe.preview(safe_tx, call_trace=True)
```

The original calls and the replay both run on the fork. In the replay, the Safe deposits ETH before sending WETH, so the transfer can use the WETH created by the first call.

## Propose the batch

With [hosted Safe access](install.md#set-up-hosted-safe-access) configured, build the batch again without an explicit nonce. Brownie Safe chooses the next nonce using the on-chain nonce and the pending queue. Set `include_pending=True` to replay pending transactions before previewing the new batch.

```python
safe_tx = safe.multisend_from_receipts(receipts)
safe.preview(safe_tx, include_pending=True)
```

After reviewing the preview, use a [configured signer](signing.md) to propose the batch to the hosted Safe Queue Service. This creates an off-chain proposal. `post_transaction` prompts for a local signer when the transaction has no signatures.

```python
safe.post_transaction(safe_tx)
```

## Confirm and execute

To submit an additional confirmation, select the queued transaction by its hash and sign with a different Safe owner account. Replace `second-owner` with that account’s Brownie alias.

```python
queued = next(tx for tx in safe.pending_transactions if tx.safe_tx_hash == safe_tx.safe_tx_hash)
signature = safe.sign_transaction(queued, "second-owner")
safe.post_signature(queued, signature)
```

Once the proposal has enough signatures, use [Safe Wallet](https://app.safe.global/) to execute it on mainnet. For a local simulation of queued proposals, call `safe.preview_pending()` on the fork.
