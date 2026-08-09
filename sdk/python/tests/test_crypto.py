from hacash_agent_pay import HacashKey


def test_deterministic_address():
    a = HacashKey.from_password("agent-sdk-test")
    b = HacashKey.from_password("agent-sdk-test")
    assert a.address == b.address
    assert len(a.address) > 20


def test_sign_verify():
    key = HacashKey.from_password("agent-sdk-sign")
    h = "ab" * 32
    sig = key.sign_hash_hex(h)
    assert len(sig) == 194
    assert HacashKey.verify_sign_hex(h, sig, key.address)


def test_signature_is_deterministic_and_low_s():
    key = HacashKey.from_password("agent-sdk-canonical-sign")
    h = "cd" * 32
    first = key.sign_hash_hex(h)
    second = key.sign_hash_hex(h)
    assert first == second

    s = int(first[-64:], 16)
    assert s <= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 // 2
