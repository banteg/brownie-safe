Detailed example
================

Let's try making a transaction that puts to work the idle DAI in our treasury.
We have our eyes on one of the Yearn's vaults where you need to supply a Curve LP token.

The vault token is a few hops away from DAI:

1. Deposit DAI into Curve Pool, receive Curve LP token.

2. Deposit Curve LP into Yearn Vault, receive Vault shares.

Now drop into Brownie's interactive console:

.. code-block:: bash

    $ brownie console --network mainnet-fork

Play around the same way you would do with a normal account:

.. code-block:: python

    >>> from ape_safe import ApeSafe
    
    # You can specify an ENS name here
    # Specify an EthereumClient if you don't run a local node
    >>> safe = ApeSafe('ychad.eth')
    
    # Unlocked account is available as `safe.account`
    >>> safe.account
    <Account '0xFEB4acf3df3cDEA7399794D0869ef76A6EfAff52'>

    # Instantiate contracts with `safe.contract`
    >>> dai = safe.contract('0x6B175474E89094C44Da98b954EedeAC495271d0F')
    >>> zap = safe.contract('0x094d12e5b541784701FD8d65F11fc0598FBC6332')
    >>> lp = safe.contract('0x4f3E8F405CF5aFC05D68142F3783bDfE13811522')
    >>> vault = safe.contract('0xFe39Ce91437C76178665D64d7a2694B0f6f17fE3')

    # Work our way towards having a vault balance
    >>> dai_amount = dai.balanceOf(safe.account)
    >>> dai.approve(zap, dai_amount)
    >>> amounts = [0, dai_amount, 0, 0]
    >>> mint_amount = zap.calc_token_amount(amounts, True)
    >>> zap.add_liquidity(amounts, mint_amount * 0.99)
    >>> lp.approve(vault, 2 ** 256 - 1)
    >>> vault.depositAll()
    >>> vault.balanceOf(safe.account)
    2609.5479641693646
    
    # Combine transaction history into a multisend transaction
    >>> safe_tx = safe.multisend_from_receipts()

    # Estimate the gas needed for a successful execution
    >>> safe.estimate_gas(safe_tx)
    1082109

    # Preview the side effects in mainnet fork,
    # including a detailed call trace, courtesy of Brownie
    >>> safe.preview(safe_tx, call_trace=True)

    # Sign a transaction
    >>> signed_tx = safe.sign_transaction(safe_tx)

    # Post it to the transaction service
    # Prompts for a signature if needed
    >>> safe.post_transaction(safe_tx)

    # You can also preview side effects of pending transactions
    >>> safe.preview_pending()
