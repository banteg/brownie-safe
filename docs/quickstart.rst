Quickstart
==========

Since multisig signers are usually slow to fullfill their duties,
it's common to batch multiple actions and send them as one transaction.
Batching also serves a purpose of rudimentary zaps if you are not concerned
about the exactly matching in/out values and allow for some slippage.

Gnosis Safe has an excellent Transaction Builder app which allows scaffolding
complex interactions. This approach is usually faster and cheaper than deploying
a bespoke contract for every transaction. 

Ape Safe expands on this idea. It allows you to use multisig as a regular account and 
then convert the transaction history into one multisend transaction and make sure
it works before it hits the signers.

Let's try making a transaction which puts idle DAI in our treasury to work.
We have our eye on one of Yearn's vaults where you need to supply Curve LP token.

The vault token is a few hops away from DAI:

1. Deposit DAI into Curve Pool, receive Curve LP token.

2. Deposit Curve LP into Yearn Vault, receive Vault shares.

Now drop into Brownie's interactive console:

.. code-block:: bash

    $ brownie console --network mainnet-fork

Play around the same way you would do with a normal account:

.. code-block:: python

    >>> from ape_safe import ApeSafe
    
    # You can specify a ENS name here
    # Specify an EthereumClient if you don't run a local node
    >>> safe = ApeSafe('ychad.eth')
    
    # Unlocked account is available as `safe.account`
    >>> safe.account
    <Account '0xFEB4acf3df3cDEA7399794D0869ef76A6EfAff52'>

    # Contracts can be instantiated with `safe.contract`
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
    >>> lp.balanceOf(safe.account) / 1e18
    2660.3307701784192
    >>> lp.approve(vault, 2 ** 256 - 1)
    >>> vault.depositAll()
    >>> vault.balanceOf(safe.account)
    2609.5479641693646
    
    # Combine receipts from history into a multisend transaction
    >>> safe_tx = safe.multisend_from_receipts()

    # Estimate gas needed for a successful execution
    >>> safe.estimate_gas(safe_tx)
    1082109

    # Preview side effects in mainnet fork,
    # including a detailed call trace, courtesy of Brownie
    >>> safe.preview(safe_tx, call_trace=True)

    # Sign a transaction (optional)
    >>> signed_tx = safe.sign_transaction(safe_tx)

    # Post it to the transaction service
    >>> safe.post_transaction(safe_tx)
