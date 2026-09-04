from warrant import caveats as cv
from warrant.caveats import Caveat, evaluate

NOW = 1_800_000_000


def ctx(**over):
    base = {
        "amount": 1000,
        "now": NOW,
        "merchant": "m_42",
        "category": "groceries",
        "currency": "USD",
        "nonce": "n1",
    }
    base.update(over)
    return base


def test_empty_caveat_list_permits_everything():
    ok, reasons = evaluate([], ctx())
    assert ok and reasons == []


def test_max_amount_allows_at_the_boundary():
    assert evaluate([cv.max_amount(1000)], ctx(amount=1000))[0]


def test_max_amount_rejects_above():
    ok, reasons = evaluate([cv.max_amount(999)], ctx(amount=1000))
    assert not ok and "per-transaction" in reasons[0]


def test_merchant_and_category_must_match():
    assert not evaluate([cv.merchant("other")], ctx())[0]
    assert not evaluate([cv.category("books")], ctx())[0]
    assert evaluate([cv.merchant("m_42"), cv.category("groceries")], ctx())[0]


def test_currency_is_case_insensitive():
    assert evaluate([cv.currency("usd")], ctx(currency="USD"))[0]
    assert evaluate([cv.currency("USD")], ctx(currency="usd"))[0]


def test_expiry():
    assert evaluate([cv.expires_at(NOW + 10)], ctx())[0]
    assert not evaluate([cv.expires_at(NOW - 1)], ctx())[0]


def test_nonce_binding():
    assert evaluate([cv.bind_nonce("n1")], ctx())[0]
    assert not evaluate([cv.bind_nonce("n1")], ctx(nonce="n2"))[0]


def test_total_amount_includes_the_current_request():
    # The last transaction must not be allowed to cross the cap.
    ok, _ = evaluate([cv.total_amount(1500)], ctx(amount=1000), {"spent_before": 600})
    assert not ok
    ok, _ = evaluate([cv.total_amount(1500)], ctx(amount=1000), {"spent_before": 500})
    assert ok


def test_total_amount_reports_the_tightest_cap():
    state = {"spent_before": 0}
    evaluate([cv.total_amount(5000), cv.total_amount(2000)], ctx(amount=10), state)
    assert state["total_cap"] == 2000


def test_unknown_caveat_fails_closed():
    # Ignoring caveats we do not understand would let an attacker neutralise a
    # restriction by renaming it.
    ok, reasons = evaluate([Caveat("spend_freely", "yes")], ctx())
    assert not ok and "unknown caveat" in reasons[0]


def test_all_failures_are_reported_not_just_the_first():
    ok, reasons = evaluate(
        [cv.max_amount(1), cv.merchant("other"), cv.expires_at(NOW - 1)], ctx()
    )
    assert not ok and len(reasons) == 3


def test_attenuation_can_only_narrow_in_practice():
    # Adding a second, looser cap does not widen anything, because both are
    # evaluated and the stricter one still has to hold.
    tight = [cv.max_amount(500)]
    loosened = tight + [cv.max_amount(100000)]
    assert not evaluate(loosened, ctx(amount=1000))[0]
