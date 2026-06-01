"""Lstar fork — attestation aggregation."""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.lstar.aggregation_select import select_greedily
from lean_spec.spec.forks.lstar.containers import (
    SignedAggregatedAttestation,
    SingleMessageAggregate,
)

from ._contract import LstarSpecContract, LstarStore


class AggregationMixin(LstarSpecContract):
    """Attestation aggregation for the lstar fork."""

    def aggregate(self, store: LstarStore) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """Turn raw validator votes into compact aggregated attestations.

        Validators cast individual signatures over gossip. Before those
        votes can influence fork choice or be included in a block, they
        must be combined into compact cryptographic proofs.

        The store holds three pools of attestation evidence:

        - **Gossip signatures**: individual validator votes arriving in real-time.
        - **New payloads**: aggregated proofs from the current round, not yet
          committed to the chain.
        - **Known payloads**: previously accepted proofs, reusable as building
          blocks for deeper aggregation.

        For each unique piece of attestation data the algorithm proceeds in three phases:

        1. **Select** — greedily pick existing proofs that maximize
           validator coverage (new before known).
        2. **Fill** — collect raw gossip signatures for any validators
           not yet covered.
        3. **Aggregate** — delegate to the XMSS subspec to produce a
           single cryptographic proof.

        After aggregation the store is updated:

        - Consumed gossip signatures are removed.
        - Newly produced proofs are recorded for future reuse.
        """
        validators = store.states[store.head].validators
        gossip_signatures = store.attestation_signatures
        new = store.latest_new_aggregated_payloads
        known = store.latest_known_aggregated_payloads

        new_aggregates: list[SignedAggregatedAttestation] = []

        # Only attestation data with a new payload or a raw gossip signature
        # can trigger aggregation. Known payloads alone cannot — they exist
        # only to help extend coverage when combined with fresh evidence.
        for data in new.keys() | gossip_signatures.keys():
            # Phase 1: Select
            #
            # Start with the cheapest option: reuse proofs that already
            # cover many validators.
            #
            # Child proofs are aggregated signatures from prior rounds.
            # Selecting them first keeps the final proof tree shallow
            # and avoids redundant cryptographic work.
            #
            # New payloads go first because they represent uncommitted
            # work — known payloads fill remaining gaps.

            child_proofs, covered = select_greedily(new.get(data), known.get(data))

            # Phase 2: Fill
            #
            # For every validator not yet covered by a child proof,
            # include its individual gossip signature.
            #
            # Sorting by validator index guarantees deterministic proof
            # construction regardless of network arrival order.
            raw_entries = [
                (
                    e.validator_index,
                    validators[e.validator_index].get_attestation_public_key(),
                    e.signature,
                )
                for e in sorted(gossip_signatures.get(data, set()), key=lambda e: e.validator_index)
                if e.validator_index not in covered
            ]

            # The aggregation layer enforces a minimum: either at least one
            # raw signature, or at least two child proofs to merge.
            #
            # A lone child proof is already a valid proof — nothing to do.
            if not raw_entries and len(child_proofs) < 2:
                continue

            # Phase 3: Aggregate
            #
            # Build the recursive proof tree.
            #
            # Each child proof needs its participants' public keys so
            # the XMSS prover can verify inner proofs while constructing
            # the outer one.
            children = [
                (
                    child,
                    [
                        validators[validator_index].get_attestation_public_key()
                        for validator_index in child.participants.to_validator_indices()
                    ],
                )
                for child in child_proofs
            ]

            # Hand everything to the XMSS subspec.
            # Each fresh entry already carries its validator index alongside its key and signature.
            # Out comes a single proof covering all selected validators.
            proof = SingleMessageAggregate.aggregate(
                children=children,
                raw_xmss=raw_entries,
                message=hash_tree_root(data),
                slot=data.slot,
            )
            new_aggregates.append(SignedAggregatedAttestation(data=data, proof=proof))

        # ── Store bookkeeping ────────────────────────────────────────
        #
        # Record freshly produced proofs so future rounds can reuse them.
        # Remove gossip signatures that were consumed by this aggregation.
        store.latest_new_aggregated_payloads = {}
        for signed_attestation in new_aggregates:
            store.latest_new_aggregated_payloads.setdefault(signed_attestation.data, set()).add(
                signed_attestation.proof
            )

        for data in store.latest_new_aggregated_payloads:
            store.attestation_signatures.pop(data, None)
        return store, new_aggregates
