Signing
=======

Several options for signing transactions are available in ApeSafe, including support for hardware wallets.

Local accounts
--------------

Import a private key or a keystore into Brownie to use it with ApeSafe. Brownie accounts are encrypted as .json keystore at rest. See `Account management`_ section of the Brownie docs for details.

.. code-block:: bash

    # Import a private key
    $ brownie accounts new ape
    Enter the private key you wish to add:

    # Import a .json keystore
    brownie accounts import ape keystore.json

Gnosis Safe API won't accept a transaction without signatures unless you are `a delegate`_. Local account is the default signing option when you send a transaction. ApeSafe will prompt you for an account and Brownie will prompt you for a password.

You can also explicitly sign a transaction with a specific account to skip the first prompt:

.. code-block:: python

    >>> safe.sign_transaction(safe_tx, 'ape')

If you prefer to manage accounts outside Brownie, e.g. use a seed phrase, you can pass a ``LocalAccount`` instance:

.. code-block:: python

    >>> from eth_account import Account
    >>> key = Account.from_mnemonic('safe grape tape escape...')
    >>> safe.sign_transaction(safe_tx, key)

Frame
-----

If you wish to use a hardware wallet, your best option is Frame_. It supports all Ledger, Trezor, and Grid+ models. You can also use with with keystore accounts called Ring Signers in Frame.

To sign a transaction using Frame, select an account in Frame and do this:

.. code-block:: python

    >>> safe.sign_with_frame(safe_tx)


Frame exposes an RPC connection at ``http://127.0.0.1:1248`` and exposes the currently selected account as ``eth_accounts[0]``. ApeSafe sends the payload as ``eth_signTypedData_v4``.


.. _Account management: https://eth-brownie.readthedocs.io/en/latest/account-management.html
.. _Frame: https://frame.sh/
.. _`a delegate`: https://safe-transaction.gnosis.io/
