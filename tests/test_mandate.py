from warrant import caveats as cv
from warrant.mandate import Mandate, MandateError

KEY = b"issuer-root-key-for-tests"


def base():
    return Mandate.mint(KEY, "mnd_001", [cv.max_amount(5000), cv.currency("USD")])


def test_minted_mandate_verifies():
    assert base().verify_signature(KEY)


def test_wrong_root_key_does_not_verify():
    assert not base().verify_signature(b"some-other-key")


def test_attenuation_needs_no_key_and_still_verifies():
    narrowed = base().attenuate(cv.merchant("m_42"))
    assert narrowed.verify_signature(KEY)
    assert len(narrowed.caveats) == 3


def test_attenuation_does_not_mutate_the_original():
    m = base()
    m.attenuate(cv.merchant("m_42"))
    assert len(m.caveats) == 2


def test_a_caveat_cannot_be_removed():
    narrowed = base().attenuate(cv.merchant("m_42"))
    stripped = Mandate(narrowed.mandate_id, narrowed.caveats[:-1], narrowed.signature)
    assert not stripped.verify_signature(KEY)


def test_caveats_cannot_be_reordered():
    m = base()
    swapped = Mandate(m.mandate_id, (m.caveats[1], m.caveats[0]), m.signature)
    assert not swapped.verify_signature(KEY)


def test_a_caveat_cannot_be_edited():
    m = base()
    edited = Mandate(m.mandate_id, (cv.max_amount(999999), m.caveats[1]), m.signature)
    assert not edited.verify_signature(KEY)


def test_signature_cannot_be_spliced_from_another_mandate():
    a = Mandate.mint(KEY, "mnd_a", [cv.max_amount(100)])
    b = Mandate.mint(KEY, "mnd_b", [cv.max_amount(999999)])
    spliced = Mandate(a.mandate_id, a.caveats, b.signature)
    assert not spliced.verify_signature(KEY)


def test_mandate_id_is_covered_by_the_signature():
    m = base()
    renamed = Mandate("mnd_other", m.caveats, m.signature)
    assert not renamed.verify_signature(KEY)


def test_round_trips_through_serialisation():
    m = base().attenuate(cv.merchant("m_42"))
    again = Mandate.deserialize(m.serialize())
    assert again.verify_signature(KEY)
    assert again.caveats == m.caveats
    assert again.mandate_id == m.mandate_id


def test_malformed_blob_is_rejected():
    for blob in ("{}", "not json", '{"id":"x","caveats":[],"sig":"zz"}'):
        try:
            Mandate.deserialize(blob)
        except MandateError:
            continue
        raise AssertionError(f"should have rejected {blob!r}")


def test_attenuate_rejects_non_caveats():
    try:
        base().attenuate("merchant=m_42")
    except MandateError:
        return
    raise AssertionError("expected MandateError")


def test_caveat_encoding_is_unambiguous():
    # Without length prefixes these two would serialise identically and the
    # signature chain would not tell them apart.
    assert cv.Caveat("ab", "c").encode() != cv.Caveat("a", "bc").encode()


def test_chain_order_changes_the_signature():
    one = Mandate.mint(KEY, "m", [cv.max_amount(100), cv.merchant("x")])
    two = Mandate.mint(KEY, "m", [cv.merchant("x"), cv.max_amount(100)])
    assert one.signature != two.signature
