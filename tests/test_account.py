def test_init(safe, OWNERS, THRESHOLD, safe_contract):
    assert safe.contract == safe_contract
    assert safe.confirmations_required == THRESHOLD
    assert (
        safe.signers == set(s.address for s in safe.local_signers) == set(o.address for o in OWNERS)
    )
    assert safe.next_nonce == 0
