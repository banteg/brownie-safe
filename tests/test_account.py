def test_init(safe, OWNERS, THRESHOLD, safe_contract):
    assert safe.contract == safe_contract
    assert safe.confirmations_required == THRESHOLD
    assert (
        safe.signers == set(s.address for s in safe.local_signers) == set(o.address for o in OWNERS)
    )
    assert safe.next_nonce == 0


def test_swap_owner(safe, accounts, OWNERS):
    old_owner = list(safe.signers)[-1]
    new_owner = accounts[len(OWNERS)]  # replace owner N with account N + 1
    # NOTE: Since the signers are processed in order, we replace the last account

    prev_owner = safe.compute_prev_signer(old_owner)
    # TODO: Remove `gas_limit` by allowing forking to compute gas limit
    tx = safe.call(
        # TODO: Remove `gas_limit` by allowing forking to compute gas limit
        safe.contract.swapOwner.as_transaction(prev_owner, old_owner, new_owner, gas_limit=100_000)
    )

    assert tx.events[0].event_name == "RemovedOwner"
    assert tx.events[0].owner == old_owner

    assert tx.events[1].event_name == "AddedOwner"
    assert tx.events[1].owner == new_owner

    assert tx.events[2].event_name == "ExecutionSuccess"

    assert safe.signers == set(
        a.address for a in accounts[: len(OWNERS) - 1] + [accounts[len(OWNERS)]]
    )  # noqa: E203
