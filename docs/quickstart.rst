Quickstart
================

Set ``SAFE_AUTH_TOKEN`` to your `Safe API key`_ to read the pending queue, propose transactions, and submit confirmations.

.. code-block:: bash

    pip install -U brownie-safe
    brownie console --network mainnet-fork


.. code-block:: python

    from brownie_safe import BrownieSafe
    safe = BrownieSafe('ychad.eth')

    dai = safe.contract('0x6B175474E89094C44Da98b954EedeAC495271d0F')
    vault = safe.contract('0x19D3364A399d251E894aC732651be8B0E4e85001')

    amount = dai.balanceOf(safe.account)
    dai.approve(vault, amount)
    vault.deposit(amount)

    safe_tx = safe.multisend_from_receipts()
    safe.preview(safe_tx)
    safe.post_transaction(safe_tx)

.. _Safe API key: https://docs.safe.global/core-api/how-to-use-api-keys
