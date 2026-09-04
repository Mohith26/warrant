"""The attack suite, shared by the benchmark and the controls.

Each attack takes a mandate an agent legitimately holds and tries to turn it
into one that authorises more than it should. They are written against an
abstract pair of (build, verify) functions so the same attacks can be pointed
at the real chained construction and at the sign-once control, and the results
compared directly.
"""

import random

from warrant import caveats as cv
from warrant.mandate import Mandate

NOW = 1_800_000_000


def honest_mandate(build, key, rng):
    """What the agent is actually given: a tightly scoped authority."""
    return build(
        key,
        "mnd_%04d" % rng.randrange(10000),
        [
            cv.max_amount(2500),
            cv.currency("USD"),
            cv.merchant("m_42"),
            cv.category("groceries"),
            cv.expires_at(NOW + 3600),
        ],
    )


def _rebuild(m, caveats, signature=None):
    return Mandate(m.mandate_id, tuple(caveats), signature or m.signature)


def drop_a_caveat(m, key, rng):
    """Remove one restriction and keep the signature."""
    if len(m.caveats) < 2:
        return None
    i = rng.randrange(len(m.caveats))
    return _rebuild(m, m.caveats[:i] + m.caveats[i + 1:])


def drop_the_last_caveat(m, key, rng):
    """Specifically the most recently added one, which is the easiest target."""
    if len(m.caveats) < 2:
        return None
    return _rebuild(m, m.caveats[:-1])


def raise_the_limit(m, key, rng):
    """Edit the amount cap in place."""
    caveats = list(m.caveats)
    for i, c in enumerate(caveats):
        if c.kind == "max_amount":
            caveats[i] = cv.max_amount(int(c.value) * 100)
            return _rebuild(m, caveats)
    return None


def reorder(m, key, rng):
    if len(m.caveats) < 2:
        return None
    caveats = list(m.caveats)
    rng.shuffle(caveats)
    if tuple(caveats) == m.caveats:
        return None
    return _rebuild(m, caveats)


def swap_merchant(m, key, rng):
    caveats = list(m.caveats)
    for i, c in enumerate(caveats):
        if c.kind == "merchant":
            caveats[i] = cv.merchant("attacker_merchant")
            return _rebuild(m, caveats)
    return None


def extend_expiry(m, key, rng):
    caveats = list(m.caveats)
    for i, c in enumerate(caveats):
        if c.kind == "expires_at":
            caveats[i] = cv.expires_at(int(c.value) + 86400 * 365)
            return _rebuild(m, caveats)
    return None


def splice_signature(m, key, rng):
    """Take the signature from a different mandate minted by the same issuer."""
    other = honest_mandate(Mandate.mint, key, rng)
    return _rebuild(m, m.caveats, other.signature)


def rename_mandate(m, key, rng):
    return Mandate("mnd_attacker", m.caveats, m.signature)


def forge_with_guessed_key(m, key, rng):
    """Mint a fresh permissive mandate under a key the attacker guessed wrong."""
    guess = bytes(rng.randrange(256) for _ in range(len(key)))
    return Mandate.mint(guess, m.mandate_id, [cv.max_amount(10 ** 9)])


def append_permissive_caveat(m, key, rng):
    """Legitimately attenuate, but with something that tries to widen scope.

    This one is expected to be *accepted* by the signature check, because
    anyone may add a caveat. It must still be rejected at authorisation,
    because adding a looser cap alongside a tighter one does not remove the
    tighter one, and because unknown caveat kinds fail closed.
    """
    return m.attenuate(cv.Caveat("ignore_limits", "true"))


def truncate_to_nothing(m, key, rng):
    return _rebuild(m, ())


ATTACKS = [
    drop_a_caveat,
    drop_the_last_caveat,
    raise_the_limit,
    reorder,
    swap_merchant,
    extend_expiry,
    splice_signature,
    rename_mandate,
    forge_with_guessed_key,
    append_permissive_caveat,
    truncate_to_nothing,
]

# The request the attacker actually wants to push through: far over the cap, at
# the wrong merchant, in the wrong category.
ATTACKER_REQUEST = {
    "amount": 250000,
    "now": NOW,
    "merchant": "attacker_merchant",
    "category": "electronics",
    "currency": "USD",
    "nonce": "n1",
}


def run_suite(build, authorise, key, trials=500, seed=0):
    """Point the whole suite at one construction and count what gets through.

    build(key, mandate_id, caveats) -> mandate
    authorise(mandate, request) -> bool, whether money would move
    """
    rng = random.Random(seed)
    per_attack = {}
    for attack in ATTACKS:
        attempted = 0
        accepted = 0
        for _ in range(trials):
            m = honest_mandate(build, key, rng)
            forged = attack(m, key, rng)
            if forged is None:
                continue
            attempted += 1
            if authorise(forged, ATTACKER_REQUEST):
                accepted += 1
        per_attack[attack.__name__] = {
            "attempted": attempted,
            "accepted": accepted,
            "rate": round(accepted / attempted, 4) if attempted else 0.0,
        }
    total_attempted = sum(v["attempted"] for v in per_attack.values())
    total_accepted = sum(v["accepted"] for v in per_attack.values())
    return {
        "per_attack": per_attack,
        "total_attempted": total_attempted,
        "total_accepted": total_accepted,
        "overall_rate": round(total_accepted / total_attempted, 5) if total_attempted else 0.0,
    }
