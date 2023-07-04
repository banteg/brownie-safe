Changelog
=========

0.8.0
-----

- add anvil support
- speed up simulations by writing to storage instead of sending approveHash transactions
- dropped ganache support

0.7.2
-----

- rename the package to brownie-safe
- backport safe transaction service
- switch frame to the correct network
- update safe api endpoints

0.6.0
-----

- add support for boba, fantom, optimism
- preview including the pending txs

0.5.0
-----

- execute transaction with frame
- trezor eip-712 signing support

0.4.0
-----

- trezor signing support

0.3.0
-----

- hardware wallet support via frame
- submit signatures to transaction service
- retrieve pending transactions from transaction service
- execute signed transactions
- convert confirmations to signatures
- expanded documentation about signing

0.2.0
-----

- add support for safe contracts 1.3.0
- switch to multicall 1.3.0 call only
- support multiple networks
- autodetect transaction service from chain id
