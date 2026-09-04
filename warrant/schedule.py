"""Deterministic interleaving explorer.

Testing a race with real threads gives you a test that fails once a week on CI
and cannot be reproduced. Instead, each concurrent operation is written as a
generator that yields at the points where it could be preempted, and this
module drives several of them forward one step at a time, enumerating the
orderings.

That makes the concurrency bug in NaiveLedger a deterministic, reproducible
failure with a printable schedule attached, and it makes the absence of one in
CasLedger an exhaustive statement over the schedule space rather than a hopeful
one.

The number of interleavings of k operations with n steps each grows like
(kn)! / (n!)^k, so `explore` enumerates exhaustively while that is small and
`sample` takes random schedules when it is not. Both report how many schedules
they actually covered so a claim of "no violations" can be read honestly.
"""

import itertools
import random


def _advance(gen):
    """Step a generator once. Returns (finished, value)."""
    try:
        next(gen)
        return False, None
    except StopIteration as stop:
        return True, stop.value


def run_schedule(factories, order):
    """Run operations under one specific interleaving.

    factories is a list of zero-argument callables each returning a fresh
    generator. order is a sequence of operation indices saying who runs next.
    Indices for finished operations are skipped, and anything left unfinished
    at the end is drained in index order.
    """
    gens = [f() for f in factories]
    results = [None] * len(gens)
    done = [False] * len(gens)

    for idx in order:
        if done[idx]:
            continue
        finished, value = _advance(gens[idx])
        if finished:
            done[idx] = True
            results[idx] = value

    for i, gen in enumerate(gens):
        while not done[i]:
            finished, value = _advance(gen)
            if finished:
                done[i] = True
                results[i] = value
    return results


def all_orders(n_ops, steps_each):
    """Every distinct interleaving of n_ops operations with steps_each steps."""
    slots = []
    for i in range(n_ops):
        slots.extend([i] * steps_each)
    return set(itertools.permutations(slots))


def explore(factories, steps_each, invariant, max_schedules=20000):
    """Enumerate interleavings and report any that break the invariant.

    invariant is called with the list of results and must return
    (ok, description).
    """
    orders = all_orders(len(factories), steps_each)
    exhaustive = len(orders) <= max_schedules
    if not exhaustive:
        orders = list(orders)[:max_schedules]

    violations = []
    checked = 0
    for order in orders:
        results = run_schedule(factories, order)
        checked += 1
        ok, why = invariant(results)
        if not ok:
            violations.append({"order": list(order), "why": why})
    return {
        "schedules_checked": checked,
        "exhaustive": exhaustive,
        "violations": len(violations),
        "first_violation": violations[0] if violations else None,
    }


def sample(factories, steps_each, invariant, n=5000, seed=0):
    """Random interleavings, for when the exhaustive space is too large."""
    rng = random.Random(seed)
    slots = []
    for i in range(len(factories)):
        slots.extend([i] * steps_each)

    violations = []
    for _ in range(n):
        order = slots[:]
        rng.shuffle(order)
        results = run_schedule(factories, order)
        ok, why = invariant(results)
        if not ok:
            violations.append({"order": order, "why": why})
    return {
        "schedules_checked": n,
        "exhaustive": False,
        "violations": len(violations),
        "first_violation": violations[0] if violations else None,
    }
