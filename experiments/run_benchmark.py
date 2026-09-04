"""Main results.

    python experiments/run_benchmark.py
"""

import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

from warrant import caveats as cv
from warrant.ledger import CasLedger, NaiveLedger
from warrant.mandate import Mandate
from warrant.schedule import explore
from warrant.verify import Verifier

from attacks import ATTACKER_REQUEST, run_suite

KEY = b"issuer-root-key-0123456789abcdef"


def attack_suite(trials=500):
    verifier = Verifier(KEY)

    def authorise(mandate, request):
        return bool(verifier.authorise(mandate, request))

    return run_suite(Mandate.mint, authorise, KEY, trials=trials)


def concurrency(cap=1000, amount=600, n_ops=2):
    """Two concurrent captures that must not both succeed."""

    def invariant(results):
        total = sum(r.amount for r in results if r and r.accepted)
        if total > cap:
            return False, f"committed {total} against a cap of {cap}"
        return True, ""

    out = {}
    for cls, steps_each in ((NaiveLedger, 4), (CasLedger, 5)):
        led = cls()
        report = explore(
            [lambda: led.steps("m", amount, cap) for _ in range(n_ops)],
            steps_each=steps_each,
            invariant=invariant,
        )
        out[cls.name] = report
    return out


def concurrency_wider(cap=1000, amount=400, n_ops=3):
    """Three concurrent captures, sampled rather than exhaustive."""
    from warrant.schedule import sample

    def invariant(results):
        total = sum(r.amount for r in results if r and r.accepted)
        if total > cap:
            return False, f"committed {total} against a cap of {cap}"
        return True, ""

    out = {}
    for cls, steps_each in ((NaiveLedger, 4), (CasLedger, 5)):
        led = cls()
        out[cls.name] = sample(
            [lambda: led.steps("m", amount, cap) for _ in range(n_ops)],
            steps_each=steps_each,
            invariant=invariant,
            n=4000,
            seed=3,
        )
    return out


def idempotency_under_retry_storm(retries=200):
    """The same request arriving many times because the network ate the reply."""
    v = Verifier(KEY)
    m = Mandate.mint(KEY, "mnd_idem", [cv.max_amount(5000), cv.total_amount(5000)])
    request = {"amount": 400, "now": ATTACKER_REQUEST["now"], "merchant": "m_42",
               "category": "groceries", "currency": "USD", "nonce": "n1"}
    charged = 0
    for _ in range(retries):
        _, r = v.capture(m, request, idem_key="retry-key")
        if r and r.accepted and not r.replayed:
            charged += 1
    return {
        "requests": retries,
        "times_charged": charged,
        "ledger_total": v.ledger.account("mnd_idem").spent,
        "expected_total": 400,
    }


def verification_cost(depths=(0, 2, 4, 8, 16, 32, 64), iters=4000):
    out = {}
    for d in depths:
        caveats = [cv.max_amount(10000 + i) for i in range(d)]
        m = Mandate.mint(KEY, "mnd_cost", caveats)
        t0 = time.perf_counter()
        for _ in range(iters):
            m.verify_signature(KEY)
        elapsed = time.perf_counter() - t0
        out[d] = {"us_per_verify": round(elapsed / iters * 1e6, 3)}
    return out


def main():
    results = {}

    print("=" * 76)
    print("1. Attack suite against the chained construction")
    print("=" * 76)
    suite = attack_suite()
    results["attack_suite"] = suite
    print(f"{'attack':<30}{'attempted':>12}{'accepted':>10}{'rate':>9}")
    print("-" * 61)
    for name, v in suite["per_attack"].items():
        print(f"{name:<30}{v['attempted']:>12}{v['accepted']:>10}{v['rate']:>9.4f}")
    print("-" * 61)
    print(f"{'TOTAL':<30}{suite['total_attempted']:>12}{suite['total_accepted']:>10}"
          f"{suite['overall_rate']:>9.5f}")

    print()
    print("=" * 76)
    print("2. Two concurrent captures of 600 against a cumulative cap of 1000")
    print("=" * 76)
    conc = concurrency()
    results["concurrency_2"] = conc
    print(f"{'ledger':<10}{'schedules':>12}{'exhaustive':>13}{'cap violations':>17}")
    print("-" * 52)
    for name, r in conc.items():
        print(f"{name:<10}{r['schedules_checked']:>12}{str(r['exhaustive']):>13}"
              f"{r['violations']:>17}")
    naive = conc["naive"]
    if naive["first_violation"]:
        print(f"  naive counterexample: {naive['first_violation']['why']}")
        print(f"  schedule: {naive['first_violation']['order']}")

    print()
    print("=" * 76)
    print("3. Three concurrent captures of 400 against a cap of 1000 (sampled)")
    print("=" * 76)
    wide = concurrency_wider()
    results["concurrency_3"] = wide
    print(f"{'ledger':<10}{'schedules':>12}{'cap violations':>17}{'violation rate':>17}")
    print("-" * 56)
    for name, r in wide.items():
        rate = r["violations"] / r["schedules_checked"]
        print(f"{name:<10}{r['schedules_checked']:>12}{r['violations']:>17}{rate:>17.4f}")

    print()
    print("=" * 76)
    print("4. Idempotency under a retry storm")
    print("=" * 76)
    idem = idempotency_under_retry_storm()
    results["idempotency"] = idem
    print(f"  {idem['requests']} identical requests charged the account "
          f"{idem['times_charged']} time(s)")
    print(f"  ledger total {idem['ledger_total']}, expected {idem['expected_total']}")

    print()
    print("=" * 76)
    print("5. Verification cost by caveat-chain depth")
    print("=" * 76)
    cost = verification_cost()
    results["verification_cost"] = cost
    print(f"{'caveats':>10}{'us/verify':>14}")
    print("-" * 24)
    for d, v in cost.items():
        print(f"{d:>10}{v['us_per_verify']:>14}")

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "results.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\nwrote experiments/results.json")


if __name__ == "__main__":
    main()
