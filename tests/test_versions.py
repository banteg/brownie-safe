from safe_eth.safe import Safe

import brownie_safe as module


def test_every_safe_version_the_sdk_resolves_is_wrapped():
    # BrownieSafe() looks up its wrapper by the version of the class the SDK resolved.
    # 0.0.1 and 1.0.0 predate the versions Brownie Safe supports.
    unwrapped = set(Safe.available_versions()) - set(module.PATCHED_SAFE_VERSIONS)
    assert unwrapped == {'0.0.1', '1.0.0'}
