from warrant import caveats as cv
from warrant.ledger import CasLedger, NaiveLedger, run_to_completion
from warrant.mandate import Mandate
from warrant.schedule import explore, run_schedule
from warrant.verify import Verifier

KEY = b"issuer-root-key-for-tests"
NOW = 1_800_000_000


def req(amount, **over):
    base = {"amount": amount, "now": NOW, "merchant": "m_42",
            "category": "groceries", "currency": "USD", "nonce": "n1"}
    base.update(over)
    return base


def mandate(total=5000, per=5000):
    return Mandate.mint(KEY, "mnd_1", [cv.max_amount(per), cv.total_amount(total)])


def test_sequential_captures_accumulate():
    v = Verifier(KEY)
    m = mandate(total=1000)
    for expected in (True, True, False):
        d, r = v.capture(m, req(400))
        assert bool(d and r and r.accepted) is expected


def test_capture_is_blocked_when_authorisation_fails():
    v = Verifier(KEY)
    d, r = v.capture(mandate(per=100), req(500))
    assert not d.ok and r is None


def test_idempotency_key_prevents_a_double_charge():
    v = Verifier(KEY)
    m = mandate(total=1000)
    _, first = v.capture(m, req(400), idem_key="k1")
    _, second = v.capture(m, req(400), idem_key="k1")
    assert first.accepted and second.replayed
    assert v.ledger.account("mnd_1").spent == 400


def test_distinct_idempotency_keys_both_charge():
    v = Verifier(KEY)
    m = mandate(total=1000)
    v.capture(m, req(400), idem_key="k1")
    v.capture(m, req(400), idem_key="k2")
    assert v.ledger.account("mnd_1").spent == 800


def test_authorisation_failure_never_reaches_the_ledger():
    # A request that fails a caveat is rejected before the ledger is touched,
    # so there is no capture result and nothing is recorded against the
    # idempotency key. The ledger only ever sees requests that already passed.
    v = Verifier(KEY)
    m = mandate(total=300)
    d, r = v.capture(m, req(400), idem_key="k1")
    assert not d.ok and r is None
    assert v.ledger.account("mnd_1").spent == 0
    assert "k1" not in v.ledger.account("mnd_1").seen


def test_the_ledger_records_its_own_rejections_idempotently():
    # Rejections that happen inside the ledger, which is where a lost race
    # lands, are remembered so a retry does not get a second chance at the cap.
    for cls in (NaiveLedger, CasLedger):
        led = cls()
        first = run_to_completion(led.steps("m", 400, 300, "k1"))
        second = run_to_completion(led.steps("m", 400, 300, "k1"))
        assert not first.accepted, cls.__name__
        assert second.replayed and not second.accepted, cls.__name__


def _cap_invariant(cap):
    def check(results):
        total = sum(r.amount for r in results if r and r.accepted)
        if total > cap:
            return False, f"committed {total} against a cap of {cap}"
        return True, ""

    return check


def test_naive_ledger_breaks_its_cap_under_interleaving():
    # Two concurrent captures of 600 against a cap of 1000. Run one after the
    # other, exactly one succeeds. Interleaved, the naive read-check-write lets
    # both through.
    def factories():
        led = NaiveLedger()
        return [lambda: led.steps("m", 600, 1000) for _ in range(2)]

    found = False
    for order in ([0, 1, 0, 1, 0, 1], [0, 1, 1, 0, 0, 1]):
        results = run_schedule(factories(), order)
        total = sum(r.amount for r in results if r and r.accepted)
        if total > 1000:
            found = True
    assert found, "expected the naive ledger to overshoot on some interleaving"


def test_cas_ledger_holds_the_cap_across_every_interleaving():
    led = CasLedger()
    report = explore(
        [lambda: led.steps("m", 600, 1000) for _ in range(2)],
        steps_each=4,
        invariant=_cap_invariant(1000),
    )
    assert report["violations"] == 0
    assert report["schedules_checked"] > 0


def test_sequential_behaviour_is_identical_for_both_ledgers():
    for cls in (NaiveLedger, CasLedger):
        led = cls()
        a = run_to_completion(led.steps("m", 600, 1000))
        b = run_to_completion(led.steps("m", 600, 1000))
        assert a.accepted and not b.accepted, cls.__name__


def test_cas_retry_loop_terminates():
    led = CasLedger()
    r = run_to_completion(led.steps("m", 10, None))
    assert r.accepted
