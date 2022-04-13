Quickstart
================

.. code-block:: bash

    pip install -U ape-safe
    brownie console --network mainnet-fork


.. code-block:: python

    from ape_safe import ApeSafe
    safe = ApeSafe('ychad.eth')

    dai = safe.contract('0x6B175474E89094C44Da98b954EedeAC495271d0F')
    vault = safe.contract('0x19D3364A399d251E894aC732651be8B0E4e85001')

    amount = dai.balanceOf(safe.account)
    dai.approve(vault, amount)
    vault.deposit(amount)

    safe_tx = safe.multisend_from_receipts()
    safe.preview(safe_tx)
    safe.post_transaction(safe_tx)
