# Warrant

Attenuable payment mandates for delegated and agent-initiated spend.

The problem is delegation. A user wants to let an agent buy something for them,
but only up to $25, only at one merchant, only today. The agent may then hand a
further-narrowed version to a sub-agent. Nobody except the issuer should be
able to widen anything, and the issuer should not have to be online while it
happens.

This is a mandate format for that, plus a spend ledger that holds a cumulative
cap under concurrent use, plus the test harness that shows both actually work.
Standard library only.

## The mandate

A mandate is a macaroon (Birgisson et al., NDSS 2014). Start with an HMAC over
the mandate id keyed by a secret only the issuer holds, then re-key with the
current signature for each restriction added:

```
sig_0 = HMAC(root_key, mandate_id)
sig_n = HMAC(sig_{n-1}, caveat_n)
```

Anyone holding the mandate can add a caveat, because the current signature is
the key for the next step. Going backwards means inverting HMAC, so no holder
can remove a caveat, reorder the chain, or splice caveats in from a different
mandate.

Caveats supported: per-transaction cap, cumulative cap, merchant, category,
currency, expiry, and binding to a single request nonce.

Against a suite of 11 tampering attacks, 5,493 attempts:

| attack | attempts | accepted |
|---|---|---|
| drop a caveat | 500 | 0 |
| drop the last caveat | 500 | 0 |
| raise the amount cap | 500 | 0 |
| reorder the chain | 493 | 0 |
| swap the merchant | 500 | 0 |
| extend the expiry | 500 | 0 |
| splice a signature from another mandate | 500 | 0 |
| rename the mandate | 500 | 0 |
| forge under a guessed key | 500 | 0 |
| append a permissive caveat | 500 | 0 |
| truncate to no caveats | 500 | 0 |
| **total** | **5,493** | **0** |

## What I got wrong about why this works

My first version of the writeup claimed the chain is harder to forge than the
obvious alternative, which is signing the whole caveat list once at issue time.
That is not true, and the control says so: the sign-once scheme scores **0.0000
on every one of those 11 attacks too**. The verifier recomputes over whatever
list is presented, so dropping or editing a caveat breaks the signature there
exactly as it does here.

Chaining does not buy forgery resistance. It buys **delegation**, and the
difference only shows up once there is more than one hop:

| | can a holder narrow it without the issuer's key? |
|---|---|
| chained | yes |
| sign-once | no |

Which matters, because the natural way to bolt delegation onto a sign-once
scheme is to let holders append extra caveats and have the verifier accept any
mandate whose leading caveats still match the issuer's signature. Extra caveats
only add restrictions, so it feels safe.

It is not safe. The verifier cannot tell how many caveats were appended, so it
accepts the shortest prefix that matches, and a recipient can drop everything
an intermediate agent added. An issuer grants a broad mandate to a travel
agent; the agent narrows it to one merchant and $25 before handing it to a
sub-agent; the sub-agent strips the narrowing:

| construction | attempts | restriction stripped |
|---|---|---|
| chained | 400 | **0** |
| sign-once with appendable extras | 400 | **400 (100%)** |

That is the actual argument for the chain, and it took building the wrong thing
first to state it correctly.

## The cumulative cap

A cumulative cap is only as good as the thing counting the spend. The natural
implementation reads the running total, checks it against the cap, and writes
the new total. Between the read and the write another request can do the same,
and both pass a check neither would have passed sequentially. Two agents
holding copies of the same mandate is the normal case, not an exotic one.

Rather than test this with threads, which produces a test that fails once a
week on CI and cannot be reproduced, each capture is a generator that yields at
the points where it could be preempted, and `schedule.py` enumerates the
interleavings. Two concurrent captures of 600 against a cap of 1000:

| ledger | schedules | exhaustive | cap violations |
|---|---|---|---|
| read-check-write | 70 | yes | **1** |
| compare-and-swap | 252 | yes | **0** |

The counterexample comes with its schedule attached: `[0, 1, 1, 0, 1, 0, 0, 1]`
commits 1200 against a cap of 1000.

One violation in seventy is the whole point. A stress test would run this ten
thousand times and quite plausibly never hit it; exhaustive enumeration finds
it every time, deterministically, and prints the interleaving that did it. With
three concurrent captures the space is too large to enumerate, so it falls back
to 4,000 sampled schedules: 2 violations for read-check-write, 0 for
compare-and-swap.

## Idempotency

A retried request carrying an idempotency key it has already seen returns the
original outcome instead of charging again. 200 identical requests for 400
units:

| | times charged | ledger total |
|---|---|---|
| with idempotency key | 1 | 400 |
| without | 200 | **80,000** |

## Verification cost

Linear in chain depth, about 1.86 us per caveat on top of a 1.8 us floor:

| caveats | us/verify |
|---|---|
| 0 | 1.80 |
| 4 | 9.23 |
| 16 | 31.30 |
| 64 | 120.20 |

## Other controls

**Unrecognised caveats must fail closed.** If a verifier skips caveats it does
not understand, an attacker neutralises any restriction by renaming it.
Measured: a hostile request carrying `max_amount_v2=100` is rejected when
unknown kinds fail closed and **authorised** when they fail open.

**Caveat encoding has to be unambiguous.** Caveats are length-prefixed before
hashing, because otherwise `Caveat("ab", "c")` and `Caveat("a", "bc")`
serialise identically and the chain cannot distinguish them. There is a test
for exactly that.

## Running it

```
python run_tests.py                     # 44 tests, no dependencies
python experiments/run_benchmark.py     # attack suite, concurrency, costs
python experiments/controls.py          # the negative controls above
```

Everything is seeded and reproduces exactly.

## Layout

```
warrant/
  caveats.py    caveat types, canonical encoding, fail-closed evaluation
  mandate.py    the HMAC chain: mint, attenuate, verify, serialise
  ledger.py     read-check-write and compare-and-swap, plus idempotency
  schedule.py   deterministic interleaving explorer
  verify.py     authorise and capture against a real request
tests/          44 tests
experiments/    attack suite, benchmark, negative controls
```

## Context

Agent-initiated payments are an open area right now: Google's AP2, the Agentic
Commerce Protocol from Stripe and OpenAI, and x402 all have to answer the same
questions this is about. How does a merchant know an agent really has the
user's authority, how is that authority narrowed as it is passed along, and
what stops it being replayed. Macaroons are a 2014 answer to a 2026 problem and
they hold up well.

## References

- Birgisson, Politz, Erlingsson, Taly, Vrable, Lentczner (2014), *Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud*
- Google, *Agent Payments Protocol (AP2)*
- Stripe and OpenAI, *Agentic Commerce Protocol*
