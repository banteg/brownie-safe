# Installation

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and [Anvil](https://getfoundry.sh/anvil/). Brownie Safe supports Python 3.10 through 3.12. uv uses the lockfile to install Brownie and the Safe SDK together.

This documentation follows the repository. PyPI's 0.9.3 release predates the hosted Safe Queue Service migration, so use a checkout for the hosted workflows in these guides.

```bash
git clone https://github.com/banteg/brownie-safe.git
cd brownie-safe
uv sync --locked
```

## Configure a mainnet fork

Export `ETH_RPC_URL` to an Ethereum mainnet RPC URL that Anvil can fork from. Register the upstream network and the development fork once. Brownie uses the upstream network’s explorer settings on the fork.

```bash
uv run --locked brownie networks add Ethereum brownie-safe-mainnet \
  host='$ETH_RPC_URL' chainid=1 explorer=https://api.etherscan.io/v2/api
uv run --locked brownie networks add development brownie-safe-fork \
  cmd=anvil host=http://127.0.0.1 port=8546 fork=brownie-safe-mainnet chain_id=1 base_fee=0 steps_tracing=true
```

If you already registered the fork with an RPC URL, add the upstream network above and run `uv run --locked brownie networks modify brownie-safe-fork fork=brownie-safe-mainnet`.

The local RPC listens on port 8546 and uses a zero base fee for simulation. Opcode tracing enables Brownie call traces. The fork uses chain ID 1 so the Safe transaction hashes and hosted queue requests refer to Ethereum mainnet. See [Brownie network management](https://eth-brownie.readthedocs.io/en/latest/network-management.html) to use an existing fork configuration.

## Load verified contracts

Export `ETHERSCAN_TOKEN` with your Etherscan API key. From the checkout, run `mkdir -p contracts` so Brownie recognizes it as a project. Add this setting to `brownie-config.yaml`:

```yaml
autofetch_sources: true
```

Brownie can then fetch and cache the ABI when you call `safe.contract(address)` for a verified contract.

## Start the console

Run from the checkout:

```bash
uv run --locked brownie console --network brownie-safe-fork
```

## Set up hosted Safe access

Set `SAFE_AUTH_TOKEN` to your [Safe API key](https://docs.safe.global/core-api/how-to-use-api-keys) in the shell that launches Brownie when you want to read the hosted queue or submit proposals and confirmations. The [quickstart](quickstart.md) uses the on-chain nonce for a local preview, which can run without a Safe API key.
