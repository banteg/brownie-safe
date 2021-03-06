# Quick Start

Account plugin for the [Safe](https://safe.global//) Multisig wallet (previously known as Gnosis Safe).

## Dependencies

* [python3](https://www.python.org/downloads) version 3.8 or greater, python3-dev

## Installation

### via ``ape``

You can install using the [ape](https://github.com/ApeWorX/ape) built-in plugin manager:

```bash
$ ape plugins install safe
```

### via ``pip``

You can install the latest release via [`pip`](https://pypi.org/project/pip/):

```bash
$ pip install ape-safe
```

### via ``setuptools``

You can clone the repository and use [`setuptools`](https://github.com/pypa/setuptools) for the most up-to-date version:

```bash
$ git clone https://github.com/ApeWorX/ape-safe.git
$ cd ape-safe
$ python3 setup.py install
```

## Quick Usage

To use the plugin, first use the CLI extension to add a safe you created:

```bash
# Add the safe located at "my-safe.eth" ENS on the ethereum mainnet network
$ ape safe add --network ethereum:mainnet "my-safe.eth" my-safe
Safe Found
    network: ethereum:mainnet
    address: 0x1234....AbCd
    version: 1.3.0
    required_confirmations: 2
    signers:
    - 0x2345....BcDe
    - 0x3456....CdEf
    - 0x4567....DeFg

Add safe [y/N]: y
```

Once you've added the safe, you can use the multisig inside any of your ape scripts or the console:

```python
from ape_safe import multisend

safe = accounts.load("my-safe")

# Load some contracts (here using ape-tokens)
dai = tokens["DAI"]
vault = tokens["yvDAI"]
amount = dai.balanceOf(safe)  # How much we want to deposit

# Create a multisend transaction (a transaction that executes multiple calls)
txn = multisend.Transaction()
txn.add(dai.approve, vault, amount)
txn.add(vault.deposit, amount)

# Fetch signatures from any local signers, and broadcast if confirmations are met
# Otherwise, it will post the partially confirmed message to Safe Global's API
txn(sender=safe)
```

You can then use the CLI extension to view and sign for pending transactions:

```bash
$ ape safe pending --network ethereum:mainnet my-safe
Local Signer(s) detected!
Do you want to sign unconfirmed transactions [y/N]: y
...  # Sign with any local signers that have not confirmed yet
```

## Development

Please see the [contributing guide](CONTRIBUTING.md) to learn more how to contribute to this project.
Comments, questions, criticisms and pull requests are welcomed.

## Acknowledgements

This package was inspired by [the original ape-safe](https://github.com/banteg/ape-safe#readme) by [banteg](https://github.com/banteg).
For versions prior to v0.6.0, the original package should be referenced.
