# Signing

Brownie Safe can sign with a local Brownie account, Frame, or a Trezor. On the hosted [Safe Queue Service](https://docs.safe.global/core-api/safe-queue-service-overview), an owner or a delegate can sign a proposal. Additional confirmations must come from Safe owners. The [Safe API key](install.md#set-up-hosted-safe-access) authenticates the HTTP requests. The transaction signature authorizes the proposal or confirmation.

## Local accounts

This is the default signing method when `post_transaction` needs a signature. Import a private key or encrypted keystore into Brownie. See [Brownie account management](https://eth-brownie.readthedocs.io/en/latest/account-management.html).

```bash
uv run --locked brownie accounts new ape
# Or import an existing keystore
uv run --locked brownie accounts import ape keystore.json
```

Pass the name of an imported account or a Brownie `LocalAccount` instance. Brownie prompts for the keystore password. Omit the signer argument to choose an account interactively.

```python
signature = safe.sign_transaction(safe_tx, "ape")
```

## Frame

Connect [Frame](https://frame.sh/), select the Safe signer, and approve the connection and signature prompts.

```python
signature = safe.sign_with_frame(safe_tx)
```

Brownie Safe reads the first account Frame exposes at `http://127.0.0.1:1248` and requests an `eth_signTypedData_v4` signature. Use a signer that supports this method.

## Trezor

Install the Trezor extra from the checkout:

```bash
uv sync --locked --extra trezor
```

Connect your Trezor and verify the signing request on the device.

```python
signature = safe.sign_with_trezor(safe_tx)
```

Brownie Safe uses EIP-712 signing for a Model T with firmware 2.4.3 or later. Its other signing path uses an `eth_sign` signature. Pass `force_eth_sign=True` to select that path explicitly, or `use_passphrase=True` to request a passphrase.

All three methods return the signature and add it to `safe_tx` if that signer is new. Use the signed transaction with `safe.post_transaction(safe_tx)` for a new proposal. For an existing proposal, submit the signature with `safe.post_signature(safe_tx, signature)`.
