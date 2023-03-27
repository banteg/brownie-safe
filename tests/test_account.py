import pytest


def test_init(safe, OWNERS, THRESHOLD, safe_contract):
    assert safe.contract == safe_contract
    assert safe.confirmations_required == THRESHOLD
    assert safe.signers == list(o.address for o in OWNERS)
    assert safe.next_nonce == 0


def test_swap_owner(safe, accounts, OWNERS):
    old_owner = safe.signers[0]
    new_owner = accounts[len(OWNERS)]  # replace owner 1 with account N + 1
    assert new_owner.address not in safe.signers
    # NOTE: Since the signers are processed in order, we replace the last account

    prev_owner = safe.compute_prev_signer(old_owner)
    # TODO: Remove `gas_limit` by allowing forking to compute gas limit
    # TODO: Figure out why `sender=safe` uses impersonated accounts
    # receipt = safe.contract.swapOwner(prev_owner, old_owner, new_owner, sender=safe)
    txn = safe.contract.swapOwner.as_transaction(
        prev_owner, old_owner, new_owner, gas_limit=150_000
    )
    print(safe.contract.decode_input(txn.data))
    receipt = safe.call(txn, safeTxGas=145_000)

    assert not receipt.events.filter(safe.contract.ExecutionFailure)
    assert receipt.events.filter(safe.contract.ExecutionSuccess)
    assert receipt.events.filter(safe.contract.AddedOwner)[0].owner == new_owner
    assert receipt.events.filter(safe.contract.RemovedOwner)[0].owner == old_owner

    assert old_owner not in safe.signers
    assert new_owner.address in safe.signers


def test_add_owner(safe, accounts, OWNERS):
    new_owner = accounts[len(OWNERS)]  # replace owner 1 with account N + 1
    assert new_owner.address not in safe.signers

    # TODO: Remove `gas_limit` by allowing forking to compute gas limit
    # TODO: Figure out why `sender=safe` uses impersonated accounts
    # receipt = safe.contract.addOwnerWithThreshold(
    #     new_owner, safe.confirmations_required, sender=safe
    # )
    txn = safe.contract.addOwnerWithThreshold.as_transaction(
        new_owner, safe.confirmations_required, gas_limit=150_000
    )
    receipt = safe.call(txn, safeTxGas=145_000)

    assert not receipt.events.filter(safe.contract.ExecutionFailure)
    assert receipt.events.filter(safe.contract.ExecutionSuccess)
    assert receipt.events.filter(safe.contract.AddedOwner)[0].owner == new_owner

    assert new_owner.address in safe.signers


def test_remove_owner(safe, OWNERS):
    if len(OWNERS) == 1:
        pytest.skip("Can't remove the only owner")

    old_owner = safe.signers[0]

    prev_owner = safe.compute_prev_signer(old_owner)
    # TODO: Remove `gas_limit` by allowing forking to compute gas limit
    # TODO: Figure out why `sender=safe` uses impersonated accounts
    # receipt = safe.contract.removeOwner(
    #     prev_owner, old_owner, safe.confirmations_required, sender=safe
    # )
    txn = safe.contract.removeOwner.as_transaction(
        prev_owner, old_owner, safe.confirmations_required, gas_limit=150_000
    )
    receipt = safe.call(txn, safeTxGas=145_000)

    assert not receipt.events.filter(safe.contract.ExecutionFailure)
    assert receipt.events.filter(safe.contract.ExecutionSuccess)
    assert receipt.events.filter(safe.contract.RemovedOwner)[0].owner == old_owner

    assert old_owner not in safe.signers
