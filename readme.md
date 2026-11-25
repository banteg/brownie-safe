# Brownie Safe: Gnosis Safe tx builder

[Read Documentation](https://safe.ape.tax/)

Brownie Safe allows you to iteratively build complex multi-step Gnosis Safe transactions and safely preview their side effects from the convenience of a locally forked mainnet environment.

*Previously known as Ape Safe*

## Installation

From a local checkout, install Brownie Safe and its locked dependencies with uv:

```bash
uv sync --locked
```

## Quickstart

[Configure a local Ethereum fork](https://safe.ape.tax/install.html#configure-a-mainnet-fork), then follow the [quickstart](https://safe.ape.tax/quickstart.html) to build and preview a Safe transaction. Hosted proposals and confirmations use the Safe Queue Service.

## Development

Run the Queue Service tests from the synced checkout:

```bash
uv run --locked pytest tests/test_queue_service.py
```

Use `uv build` to build the wheel and source distribution.

## Build the docs

From the repository root, use [uv](https://docs.astral.sh/uv/) to build the site:

```sh
uv run --no-project --python 3.12 --with-requirements docs-requirements.txt zensical build --clean --strict
```

Use `zensical serve` in place of `zensical build --clean --strict` to preview changes locally.
