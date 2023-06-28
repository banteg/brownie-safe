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

    >>> from brownie_safe import BrownieSafe
    
    # You can specify an ENS name here
    # Specify an EthereumClient if you don't run a local node
    >>> safe = BrownieSafe('ychad.eth')
    
    # Unlocked account is available as `safe.account`
    >>> safe.account
    <Account '0xFEB4acf3df3cDEA7399794D0869ef76A6EfAff52'>

    # Instantiate contracts with `safe.contract`
    >>> dai = safe.contract('0x6B175474E89094C44Da98b954EedeAC495271d0F')
    >>> zap = safe.contract('0x094d12e5b541784701FD8d65F11fc0598FBC6332')
    >>> lp = safe.contract('0x4f3E8F405CF5aFC05D68142F3783bDfE13811522')
    >>> vault = safe.contract('0xFe39Ce91437C76178665D64d7a2694B0f6f17fE3')

    # Work our way towards having a vault balance
    >>> dai_amount = dai.balanceOf(safe)
    >>> dai.approve(zap, dai_amount)
    >>> amounts = [0, dai_amount, 0, 0]
    >>> mint_amount = zap.calc_token_amount(amounts, True)
    >>> zap.add_liquidity(amounts, mint_amount * 0.99)
    >>> lp.approve(vault, 2 ** 256 - 1)
    >>> vault.depositAll()
    >>> vault.balanceOf(safe)
    2609.5479641693646

    # Combine transaction history into a multisend transaction
    >>> safe_tx = safe.multisend_from_receipts()

    # Estimate the gas needed for a successful execution
    >>> safe.estimate_gas(safe_tx)
    1082109

    # Preview the side effects in mainnet fork,
    # including a detailed call trace, courtesy of Brownie
    >>> safe.preview(safe_tx, call_trace=True)

    # Post it to the transaction service
    # Prompts for a signature if needed
    >>> safe.post_transaction(safe_tx)

    # Post an additional confirmation to the transaction service
    >>> signtature = safe.sign_transaction(safe_tx)
    >>> safe.post_signature(safe_tx, signature)

    # Retrieve pending transactions from the transaction service
    >>> safe.pending_transactions
    
    # Preview the side effects of all pending transactions
    >>> safe.preview_pending()

    # Execute the transactions with enough signatures
    >>> network.priority_fee('2 gwei')
    >>> signer = safe.get_signer('ape')
    >>>
    >>> for tx in safe.pending_transactions:
    >>>     receipt = safe.execute_transaction(safe_tx, signer)
    >>>     receipt.info()
