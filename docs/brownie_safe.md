# API docs { #module-brownie_safe }

`BrownieSafe` creates a Safe instance for the contract version at the given address. The returned instance exposes the methods and properties documented under `BrownieSafeBase`. Pass `base` to use your own `BrownieSafeBase` subclass.

The default backend uses the hosted Safe Queue Service for proposals, confirmations, and pending transactions. `safe.transaction_service` is the separate client for indexed on-chain history. Supply `base_url` to use a custom Safe Transaction Service for queue operations, and pass `auth_token` explicitly if it requires authentication. For the hosted queue, `auth_token` takes precedence over `SAFE_AUTH_TOKEN` and its legacy alias `SAFE_TRANSACTION_SERVICE_API_KEY`.

::: brownie_safe.BrownieSafe

::: brownie_safe.BrownieSafeBase

::: brownie_safe.ApiError

::: brownie_safe.ExecutionFailure
