# Quickstart

[Install Brownie Safe and start a mainnet fork](install.md). Use the address or ENS name of a deployed Safe with enough ETH for two 0.001 ETH transfers and gas. Enter two recipient addresses for this example.

```python
from brownie_safe import BrownieSafe

safe = BrownieSafe(input("Safe address or ENS name: ").strip())
recipient_a = input("First recipient address: ").strip()
recipient_b = input("Second recipient address: ").strip()

first = safe.account.transfer(recipient_a, "0.001 ether")
second = safe.account.transfer(recipient_b, "0.001 ether")
receipts = [first, second]

safe_tx = safe.multisend_from_receipts(receipts, safe_nonce=safe.retrieve_nonce())
safe.preview(safe_tx)
```

The two transfers run locally as the impersonated Safe. `preview` resets the fork by default and replays the batched transaction through the Safe contract. Passing the on-chain nonce keeps this preview independent of the hosted queue.

If the Safe has a guard, the batch and the selected MultiSend deployment must satisfy the guard. Use the optional `multisend` argument to select a deployment already approved for that Safe.

See the [detailed example](detailed.md) to build a batch from contract calls, account for pending proposals, and submit a proposal.
