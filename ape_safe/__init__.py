from ape import plugins

from .accounts import AccountContainer, SafeAccount
from .multisend import MultiSend


@plugins.register(plugins.AccountPlugin)
def account_types():
    return AccountContainer, SafeAccount


__all__ = [
    "MultiSend",
    "SafeAccount",
]
