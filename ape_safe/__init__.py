from ape import plugins

from .accounts import AccountContainer, SafeAccount


@plugins.register(plugins.AccountPlugin)
def account_types():
    return AccountContainer, SafeAccount
