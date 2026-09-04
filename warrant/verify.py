"""Putting it together: verify a mandate against an actual payment request.

Three things have to hold before money moves.

  1. the signature chain recomputes from the issuer's root key
  2. every caveat holds against this request
  3. the cumulative spend, including this request, is inside the tightest
     cumulative cap on the chain

The third is the one that cannot be done from the token alone, because it
depends on what has already been spent. That is why authorise() reads the
ledger before evaluating caveats and why capture() commits through the ledger's
compare-and-swap rather than trusting the check it just did.
"""

from dataclasses import dataclass

from .caveats import evaluate
from .ledger import CasLedger, run_to_completion
from .mandate import Mandate


@dataclass
class Decision:
    ok: bool
    reasons: tuple = ()
    total_cap: int | None = None

    def __bool__(self):
        return self.ok


class Verifier:
    def __init__(self, root_key, ledger=None):
        self.root_key = root_key
        self.ledger = ledger if ledger is not None else CasLedger()

    def authorise(self, mandate, request):
        """Check a request without moving money.

        request needs amount and now, and optionally merchant, category,
        currency and nonce.
        """
        if not isinstance(mandate, Mandate):
            return Decision(False, ("not a mandate",))
        if not mandate.verify_signature(self.root_key):
            # Deliberately terse. Telling a caller which caveat broke the chain
            # would help them search for one that does not.
            return Decision(False, ("signature does not verify",))

        acct = self.ledger.account(mandate.mandate_id)
        state = {"spent_before": acct.spent}
        ok, reasons = evaluate(mandate.caveats, request, state)
        return Decision(ok, tuple(reasons), state.get("total_cap"))

    def capture(self, mandate, request, idem_key=None):
        """Authorise and, if it passes, commit the spend.

        Returns (decision, capture_result). The cap is re-enforced inside the
        ledger commit, so a request that passed authorisation but lost a race
        still cannot push the total over.
        """
        decision = self.authorise(mandate, request)
        if not decision.ok:
            return decision, None

        result = run_to_completion(
            self.ledger.steps(
                mandate.mandate_id, request["amount"], decision.total_cap, idem_key
            )
        )
        return decision, result

    def capture_steps(self, mandate, request, idem_key=None):
        """The capture path as a generator, for the interleaving explorer."""
        decision = self.authorise(mandate, request)
        if not decision.ok:
            return None
        yield
        return (yield from self.ledger.steps(
            mandate.mandate_id, request["amount"], decision.total_cap, idem_key
        ))
