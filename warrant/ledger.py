"""The spend ledger, and why the obvious implementation is wrong.

A cumulative spend cap is only as good as the thing counting the spend. The
natural implementation reads the running total, checks it against the cap, and
writes the new total. Between the read and the write another request can do the
same thing, and both pass a check that neither would have passed if they had
run one after the other. Two agents holding copies of the same mandate is not
an unusual situation; it is the normal one.

Two implementations here, deliberately:

    NaiveLedger  read, check, write. Correct on its own, broken under
                 concurrency, and used as the negative control.
    CasLedger    the same thing behind a compare-and-swap on a version counter,
                 retrying when it loses the race.

schedule.py drives both through every interleaving of a set of concurrent
captures and checks the cap invariant, so the difference is measured rather
than asserted.

Idempotency is separate from both. A retried request carrying an idempotency
key it has already seen returns the original outcome instead of charging again,
which is the behaviour every payments API needs and the reason a network
timeout is survivable.
"""

from dataclasses import dataclass, field


class LedgerConflict(Exception):
    """Raised by CasLedger when a compare-and-swap loses its race."""


@dataclass
class Account:
    spent: int = 0
    version: int = 0
    # idempotency key -> (accepted, amount)
    seen: dict = field(default_factory=dict)


@dataclass
class CaptureResult:
    accepted: bool
    reason: str = ""
    replayed: bool = False
    amount: int = 0


class NaiveLedger:
    """Read, check, write. The control."""

    name = "naive"

    def __init__(self):
        self.accounts = {}

    def account(self, mandate_id):
        return self.accounts.setdefault(mandate_id, Account())

    def steps(self, mandate_id, amount, cap, idem_key=None):
        """Yields at each point where another request could interleave.

        Written as a generator so schedule.py can drive several of these
        forward one step at a time and explore the orderings, without needing
        real threads.
        """
        acct = self.account(mandate_id)

        if idem_key is not None and idem_key in acct.seen:
            accepted, amt = acct.seen[idem_key]
            return CaptureResult(accepted, "replayed", replayed=True, amount=amt)
        yield  # after the idempotency lookup

        spent = acct.spent
        yield  # after the read, before the check

        if cap is not None and spent + amount > cap:
            if idem_key is not None:
                acct.seen[idem_key] = (False, 0)
            return CaptureResult(False, f"cumulative {spent + amount} over cap {cap}")
        yield  # after the check, before the write

        acct.spent = spent + amount
        if idem_key is not None:
            acct.seen[idem_key] = (True, amount)
        return CaptureResult(True, amount=amount)


class CasLedger:
    """Compare-and-swap on a version counter, with a bounded retry loop."""

    name = "cas"
    MAX_RETRIES = 32

    def __init__(self):
        self.accounts = {}

    def account(self, mandate_id):
        return self.accounts.setdefault(mandate_id, Account())

    def steps(self, mandate_id, amount, cap, idem_key=None):
        acct = self.account(mandate_id)

        if idem_key is not None and idem_key in acct.seen:
            accepted, amt = acct.seen[idem_key]
            return CaptureResult(accepted, "replayed", replayed=True, amount=amt)
        yield

        for _ in range(self.MAX_RETRIES):
            spent = acct.spent
            version = acct.version
            yield  # the window another request can slip through

            if cap is not None and spent + amount > cap:
                if idem_key is not None:
                    acct.seen[idem_key] = (False, 0)
                return CaptureResult(False, f"cumulative {spent + amount} over cap {cap}")
            yield

            # The swap itself is the only thing that has to be atomic, and it
            # is one comparison and two assignments with no yield between them.
            if acct.version == version:
                acct.spent = spent + amount
                acct.version = version + 1
                if idem_key is not None:
                    acct.seen[idem_key] = (True, amount)
                return CaptureResult(True, amount=amount)
            # Lost the race. Re-read and try again.

        return CaptureResult(False, "too many retries")


def run_to_completion(gen):
    """Drive one capture generator with no interleaving at all."""
    try:
        while True:
            next(gen)
    except StopIteration as stop:
        return stop.value
