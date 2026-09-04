"""Payment mandates, built the way macaroons are built.

The problem this solves is delegation. A user wants to let an agent spend on
their behalf, but only up to $50, only at one merchant, only today. The agent
may then want to hand a further-narrowed version to a sub-agent. Nobody except
the issuer should be able to widen anything, and the issuer should not have to
be online for any of it.

The construction is Google's macaroon (Birgisson et al., NDSS 2014). Start with
a signature over the mandate id keyed by a secret only the issuer holds:

    sig_0 = HMAC(root_key, mandate_id)

and for each caveat, re-key with the current signature:

    sig_n = HMAC(sig_{n-1}, caveat_n)

The consequence is the whole point. Anyone holding the mandate can add a caveat
and compute the new signature, because the current signature is the key for the
next step. But going backwards means inverting HMAC, so no holder can remove a
caveat, reorder the chain, or splice caveats in from a different mandate. The
issuer verifies by recomputing the chain from the root key.

experiments/controls.py implements the obvious alternative, signing the caveat
list once at issue time, and measures how many of the same attacks it lets
through.
"""

import hashlib
import hmac
import json

from .caveats import Caveat

HASH = hashlib.sha256


class MandateError(ValueError):
    pass


def _chain(root_key, mandate_id, caveats):
    sig = hmac.new(root_key, mandate_id.encode("utf-8"), HASH).digest()
    for c in caveats:
        sig = hmac.new(sig, c.encode(), HASH).digest()
    return sig


class Mandate:
    """A delegated authority to spend, narrowed by an append-only caveat chain."""

    def __init__(self, mandate_id, caveats, signature):
        self.mandate_id = mandate_id
        self.caveats = tuple(caveats)
        self.signature = signature

    @classmethod
    def mint(cls, root_key, mandate_id, caveats=()):
        caveats = tuple(caveats)
        return cls(mandate_id, caveats, _chain(root_key, mandate_id, caveats))

    def attenuate(self, caveat):
        """Add a restriction. Needs no key, and cannot be undone.

        Returns a new mandate; the original is untouched, so an agent can hand
        out several differently narrowed copies of the same authority.
        """
        if not isinstance(caveat, Caveat):
            raise MandateError("can only attenuate with a Caveat")
        return Mandate(
            self.mandate_id,
            self.caveats + (caveat,),
            hmac.new(self.signature, caveat.encode(), HASH).digest(),
        )

    def verify_signature(self, root_key):
        """Recompute the chain from the root key.

        compare_digest rather than == so the check does not leak where the
        first differing byte is.
        """
        return hmac.compare_digest(
            self.signature, _chain(root_key, self.mandate_id, self.caveats)
        )

    def serialize(self):
        return json.dumps(
            {
                "id": self.mandate_id,
                "caveats": [[c.kind, c.value] for c in self.caveats],
                "sig": self.signature.hex(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def deserialize(cls, blob):
        try:
            raw = json.loads(blob)
            return cls(
                raw["id"],
                tuple(Caveat(k, v) for k, v in raw["caveats"]),
                bytes.fromhex(raw["sig"]),
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise MandateError(f"malformed mandate: {exc}") from exc

    def __repr__(self):
        inner = ", ".join(str(c) for c in self.caveats)
        return f"Mandate({self.mandate_id}, [{inner}])"
