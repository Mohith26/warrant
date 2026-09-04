"""Negative controls.

The chained construction and the compare-and-swap ledger both look like extra
work compared to the obvious thing. Both obvious things are implemented here
and run through the same tests.

    python experiments/controls.py
"""

import hashlib
import hmac
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

from warrant import caveats as cv
from warrant.caveats import evaluate
from warrant.mandate import Mandate
from warrant.verify import Verifier

from attacks import ATTACKER_REQUEST, run_suite

KEY = b"issuer-root-key-0123456789abcdef"


def sign_once(key, mandate_id, caveats):
    """The obvious alternative: one signature over the whole caveat list.

    This is what you write if you have not thought about delegation. It is
    unforgeable in the ordinary sense, so it passes the tests people usually
    write for it. What it cannot do is let a holder attenuate without the root
    key, and, much worse, it has no way to tell that a caveat has been removed
    if the signature is recomputed over whatever list is presented.

    Modelled here the way it actually gets built in practice: the signature
    covers the mandate id and the caveats that existed at issue time, and the
    verifier checks the presented list against it.
    """
    caveats = tuple(caveats)
    payload = mandate_id.encode("utf-8") + b"".join(c.encode() for c in caveats)
    sig = hmac.new(key, payload, hashlib.sha256).digest()
    return Mandate(mandate_id, caveats, sig)


def _sign_once_verify(mandate, key):
    payload = mandate.mandate_id.encode("utf-8") + b"".join(
        c.encode() for c in mandate.caveats
    )
    return hmac.compare_digest(
        mandate.signature, hmac.new(key, payload, hashlib.sha256).digest()
    )


def control_sign_once():
    """Run the identical attack suite against both constructions.

    Worth stating plainly because I got this wrong at first: signing the caveat
    list once is NOT weaker against tampering. The verifier recomputes over
    whatever list is presented, so dropping, editing or reordering a caveat
    breaks the signature just as it does with chaining. Both score zero.

    The chained construction is not buying forgery resistance. It is buying
    delegation, which controls 2 and 2b measure.
    """

    verifier = Verifier(KEY)

    def chained_authorise(mandate, request):
        return bool(verifier.authorise(mandate, request))

    def sign_once_authorise(mandate, request):
        if not _sign_once_verify(mandate, KEY):
            return False
        ok, _ = evaluate(mandate.caveats, request, {"spent_before": 0})
        return ok

    return {
        "chained": run_suite(Mandate.mint, chained_authorise, KEY, trials=400, seed=11),
        "sign_once": run_suite(sign_once, sign_once_authorise, KEY, trials=400, seed=11),
    }


def _appendable_verify(mandate, key):
    """Sign-once, patched to allow delegation the obvious way.

    Signing once cannot attenuate, so the natural fix is to let a holder append
    extra caveats and have the verifier accept any mandate whose leading
    caveats still match the issuer's signature. Extra caveats only ever add
    restrictions, so this feels safe.

    It is not. The verifier has no way to know how many caveats were appended,
    so it accepts the shortest matching prefix, and a recipient can simply drop
    everything an intermediate agent added.
    """
    for k in range(len(mandate.caveats), -1, -1):
        payload = mandate.mandate_id.encode("utf-8") + b"".join(
            c.encode() for c in mandate.caveats[:k]
        )
        if hmac.compare_digest(
            mandate.signature, hmac.new(key, payload, hashlib.sha256).digest()
        ):
            return True
    return False


def control_subdelegation(trials=400):
    """The attack that actually separates the two constructions.

    An issuer grants a broad mandate to a travel agent. The agent narrows it to
    a single merchant and 25 dollars before handing it to a sub-agent. The
    sub-agent then tries to undo the narrowing and spend the full original
    authority somewhere else.
    """
    issuer_caveats = [cv.currency("USD"), cv.expires_at(ATTACKER_REQUEST["now"] + 3600)]
    delegated = [cv.max_amount(2500), cv.merchant("m_42")]

    request = dict(ATTACKER_REQUEST)  # 250000 at attacker_merchant
    out = {}

    chained_broken = 0
    for _ in range(trials):
        m = Mandate.mint(KEY, "mnd_travel", issuer_caveats)
        for c in delegated:
            m = m.attenuate(c)
        stripped = Mandate(m.mandate_id, tuple(issuer_caveats), m.signature)
        if stripped.verify_signature(KEY):
            ok, _ = evaluate(stripped.caveats, request, {"spent_before": 0})
            chained_broken += ok
    out["chained"] = {"attempts": trials, "succeeded": chained_broken}

    appendable_broken = 0
    for _ in range(trials):
        base = sign_once(KEY, "mnd_travel", issuer_caveats)
        handed_on = Mandate(
            base.mandate_id, base.caveats + tuple(delegated), base.signature
        )
        stripped = Mandate(base.mandate_id, tuple(issuer_caveats), handed_on.signature)
        if _appendable_verify(stripped, KEY):
            ok, _ = evaluate(stripped.caveats, request, {"spent_before": 0})
            appendable_broken += ok
    out["sign_once_appendable"] = {"attempts": trials, "succeeded": appendable_broken}

    for v in out.values():
        v["rate"] = round(v["succeeded"] / v["attempts"], 4)
    return out


def control_attenuation_without_the_root_key():
    """Can a holder narrow a mandate without talking to the issuer?

    This is the property the whole construction exists for, and the sign-once
    scheme simply cannot do it, which is worth stating as a measurement rather
    than an opinion.
    """
    chained = Mandate.mint(KEY, "mnd_x", [cv.max_amount(5000)])
    narrowed = chained.attenuate(cv.merchant("m_42"))

    once = sign_once(KEY, "mnd_x", [cv.max_amount(5000)])
    once_narrowed = Mandate(
        once.mandate_id, once.caveats + (cv.merchant("m_42"),), once.signature
    )

    return {
        "chained_holder_can_attenuate": bool(narrowed.verify_signature(KEY)),
        "sign_once_holder_can_attenuate": bool(_sign_once_verify(once_narrowed, KEY)),
    }


def control_no_idempotency_key(retries=200):
    """Retry the same payment with no idempotency key at all."""
    v = Verifier(KEY)
    m = Mandate.mint(KEY, "mnd_noidem", [cv.max_amount(5000), cv.total_amount(10 ** 9)])
    request = {"amount": 400, "now": ATTACKER_REQUEST["now"], "merchant": "m_42",
               "category": "groceries", "currency": "USD", "nonce": "n1"}
    for _ in range(retries):
        v.capture(m, request)  # no idem_key
    return {
        "requests": retries,
        "ledger_total": v.ledger.account("mnd_noidem").spent,
        "expected_total": 400,
        "overcharge_factor": v.ledger.account("mnd_noidem").spent // 400,
    }


def control_unknown_caveat_fails_open():
    """Ignore caveats the verifier does not recognise, instead of rejecting.

    A tempting compatibility choice, and it hands an attacker a way to
    neutralise any restriction by renaming it.
    """
    request = dict(ATTACKER_REQUEST)
    hostile = [cv.Caveat("max_amount_v2", "100")]

    fail_closed, _ = evaluate(hostile, request, {"spent_before": 0})

    def fail_open(caveats, ctx):
        from warrant.caveats import _HANDLERS

        for c in caveats:
            handler = _HANDLERS.get(c.kind)
            if handler is None:
                continue  # the bug
            ok, _why = handler(c.value, ctx, {"spent_before": 0})
            if not ok:
                return False
        return True

    return {
        "fail_closed_authorises": bool(fail_closed),
        "fail_open_authorises": bool(fail_open(hostile, request)),
    }


def main():
    results = {}

    print("=" * 76)
    print("Control 1: sign the caveat list once instead of chaining")
    print("=" * 76)
    c1 = control_sign_once()
    results["sign_once"] = c1
    print(f"{'attack':<30}{'chained':>12}{'sign-once':>12}")
    print("-" * 54)
    for name in c1["chained"]["per_attack"]:
        a = c1["chained"]["per_attack"][name]["rate"]
        b = c1["sign_once"]["per_attack"][name]["rate"]
        print(f"{name:<30}{a:>12.4f}{b:>12.4f}")
    print("-" * 54)
    print(f"{'OVERALL':<30}{c1['chained']['overall_rate']:>12.5f}"
          f"{c1['sign_once']['overall_rate']:>12.5f}")

    print()
    print("=" * 76)
    print("Control 2: can a holder attenuate without the issuer's key?")
    print("=" * 76)
    c2 = control_attenuation_without_the_root_key()
    results["attenuation"] = c2
    print(f"  chained    : {c2['chained_holder_can_attenuate']}")
    print(f"  sign-once  : {c2['sign_once_holder_can_attenuate']}")

    print()
    print("=" * 76)
    print("Control 2b: sub-agent strips the restriction an intermediate added")
    print("=" * 76)
    c2b = control_subdelegation()
    results["subdelegation"] = c2b
    print(f"{'construction':<24}{'attempts':>10}{'stripped':>11}{'rate':>9}")
    print("-" * 54)
    for name, v in c2b.items():
        print(f"{name:<24}{v['attempts']:>10}{v['succeeded']:>11}{v['rate']:>9.4f}")

    print()
    print("=" * 76)
    print("Control 3: retry storm with no idempotency key")
    print("=" * 76)
    c3 = control_no_idempotency_key()
    results["no_idempotency"] = c3
    print(f"  {c3['requests']} retries of a single 400 payment settled "
          f"{c3['ledger_total']} total")
    print(f"  expected {c3['expected_total']}, overcharged by "
          f"{c3['overcharge_factor']}x")

    print()
    print("=" * 76)
    print("Control 4: ignore unrecognised caveats instead of rejecting")
    print("=" * 76)
    c4 = control_unknown_caveat_fails_open()
    results["unknown_caveat"] = c4
    print(f"  fail closed authorises the hostile request: {c4['fail_closed_authorises']}")
    print(f"  fail open   authorises the hostile request: {c4['fail_open_authorises']}")

    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "controls.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\nwrote experiments/controls.json")


if __name__ == "__main__":
    main()
