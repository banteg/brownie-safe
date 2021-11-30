Signing
=======

Several options for signing transactions are available in Ape Safe, including support for hardware wallets.

Signatures are required, Gnosis `transaction service`_ will only accept a transaction with an owner signature or from `a delegate`_.

Local accounts
--------------

This is the default signing method when you send a transaction.

Import a private key or a keystore into Brownie to use it with Ape Safe.
Brownie accounts are encrypted at rest as .json keystores.
See also Brownie's `Account management`_ documentation.

.. code-block:: bash

    # Import a private key
    $ brownie accounts new ape
    Enter the private key you wish to add:

    # Import a .json keystore
    $ brownie accounts import ape keystore.json

Ape Safe will prompt you for an account (unless supplied as an argument) and Brownie will prompt you for a password.

.. code-block:: python

    >>> safe.sign_transaction(safe_tx)
    signer (ape, safe): ape
    Enter password for "ape":
    
    >>> safe.sign_transaction(safe_tx, 'ape')
    Enter password for "ape":

If you prefer to manage accounts outside Brownie, e.g. use a seed phrase, you can pass a ``LocalAccount`` instance:

.. code-block:: python

    >>> from eth_account import Account
    >>> key = Account.from_mnemonic('safe grape tape escape...')
    >>> safe.sign_transaction(safe_tx, key)

Frame
-----

If you wish to use a hardware wallet, your best option is Frame_. It supports Ledger, Trezor, and Lattice. You can also use with with keystore accounts, they are called Ring Signers in Frame.

To sign, select an account in Frame and do this:

.. code-block:: python

    >>> safe.sign_with_frame(safe_tx)


Frame exposes an RPC connection at ``http://127.0.0.1:1248`` and exposes the currently selected account as ``eth_accounts[0]``. Ape Safe sends the payload as ``eth_signTypedData_v4``, which must be supported by your signer device.

Trezor
------

Alternative method for Trezor models and firmware versions which don't support EIP-712 using ``eth_sign``:

.. code-block:: python

    >>> safe.sign_with_trezor(safe_tx)


.. _`transaction service`: https://safe-transaction.gnosis.io/
.. _`a delegate`: https://safe-transaction.gnosis.io/
.. _Account management: https://eth-brownie.readthedocs.io/en/latest/account-management.html
.. _Frame: https://frame.sh/
