"""Caveats: the restrictions carried by a payment mandate.

A caveat is a predicate over a payment request. A mandate is valid for a
request only if every caveat on it holds. Caveats can only ever be added, never
removed, so attaching one always narrows what the mandate can do.

Two properties are deliberate:

  Caveats serialise canonically. The signature chain in mandate.py is computed
  over these bytes, so any ambiguity in the encoding is a forgery surface. A
  caveat with the same meaning must always produce the same bytes.

  An unrecognised caveat fails closed. If a verifier does not understand a
  caveat it must reject, not ignore. Failing open here means an attacker can
  neutralise a restriction by naming it something the verifier has never heard
  of, which is the classic way this kind of token gets broken.
"""

from dataclasses import dataclass


class CaveatError(ValueError):
    pass


@dataclass(frozen=True)
class Caveat:
    kind: str
    value: str

    def encode(self):
        """Canonical bytes. Length-prefixed so kind and value cannot be confused.

        Without the length prefix, Caveat("ab", "c") and Caveat("a", "bc")
        would serialise to the same bytes and the signature chain would not
        distinguish them.
        """
        k = self.kind.encode("utf-8")
        v = self.value.encode("utf-8")
        return b"%d:%s|%d:%s" % (len(k), k, len(v), v)

    def __str__(self):
        return f"{self.kind}={self.value}"


def max_amount(cents):
    """Per-transaction ceiling."""
    return Caveat("max_amount", str(int(cents)))


def total_amount(cents):
    """Cumulative ceiling across every use of this mandate."""
    return Caveat("total_amount", str(int(cents)))


def merchant(merchant_id):
    return Caveat("merchant", str(merchant_id))


def category(name):
    return Caveat("category", str(name))


def currency(code):
    return Caveat("currency", str(code).upper())


def expires_at(epoch_seconds):
    return Caveat("expires_at", str(int(epoch_seconds)))


def bind_nonce(nonce):
    """Ties the mandate to one specific request nonce.

    This is what stops a captured mandate from being replayed against a
    different request. It is a caveat rather than a verifier-side rule so that
    an agent can narrow a long-lived mandate down to a single transaction
    itself, without talking to the issuer.
    """
    return Caveat("bind_nonce", str(nonce))


# Every caveat kind the verifier understands. Anything else is rejected.
_HANDLERS = {}


def _handler(kind):
    def register(fn):
        _HANDLERS[kind] = fn
        return fn

    return register


@_handler("max_amount")
def _check_max_amount(value, ctx, state):
    return ctx["amount"] <= int(value), f"amount {ctx['amount']} over per-transaction cap {value}"


@_handler("total_amount")
def _check_total_amount(value, ctx, state):
    cap = int(value)
    # The running total has to include this request, otherwise the last
    # transaction is always allowed to cross the cap.
    projected = state.get("spent_before", 0) + ctx["amount"]
    # Record the tightest cumulative cap seen, so the ledger knows what to
    # enforce when it commits.
    prior = state.get("total_cap")
    state["total_cap"] = cap if prior is None else min(prior, cap)
    return projected <= cap, f"cumulative {projected} over cap {cap}"


@_handler("merchant")
def _check_merchant(value, ctx, state):
    return ctx.get("merchant") == value, f"merchant {ctx.get('merchant')!r} not {value!r}"


@_handler("category")
def _check_category(value, ctx, state):
    return ctx.get("category") == value, f"category {ctx.get('category')!r} not {value!r}"


@_handler("currency")
def _check_currency(value, ctx, state):
    got = str(ctx.get("currency", "")).upper()
    return got == value, f"currency {got!r} not {value!r}"


@_handler("expires_at")
def _check_expires_at(value, ctx, state):
    return ctx["now"] <= int(value), f"expired at {value}, now {ctx['now']}"


@_handler("bind_nonce")
def _check_bind_nonce(value, ctx, state):
    return ctx.get("nonce") == value, f"nonce {ctx.get('nonce')!r} not bound value {value!r}"


def evaluate(caveats, ctx, state=None):
    """Check every caveat against a request context.

    Returns (ok, reasons). All caveats are evaluated rather than short
    circuiting, so a rejection reports everything that was wrong instead of
    only the first thing, which matters when an agent is trying to work out
    what it is allowed to do.
    """
    state = {} if state is None else state
    reasons = []
    for c in caveats:
        handler = _HANDLERS.get(c.kind)
        if handler is None:
            # Fail closed on anything we do not recognise.
            reasons.append(f"unknown caveat kind {c.kind!r}")
            continue
        ok, why = handler(c.value, ctx, state)
        if not ok:
            reasons.append(why)
    return (not reasons), reasons
