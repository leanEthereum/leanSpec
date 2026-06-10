"""Lstar fork — attestation aggregation."""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks.lstar._base import LstarSpecBase, LstarStore
from lean_spec.spec.forks.lstar.containers import (
    SignedAggregatedAttestation,
    SingleMessageAggregate,
    ValidatorIndex,
)


def select_proofs_for_coverage(
    priority_pool: set[SingleMessageAggregate] | None,
    fallback_pool: set[SingleMessageAggregate] | None = None,
) -> tuple[list[SingleMessageAggregate], set[ValidatorIndex]]:
    """
    Greedily pick proofs covering as many distinct validators as possible.

    The priority pool is consulted before the fallback pool.

    Args:
        priority_pool: Proofs consulted first; None or empty is skipped.
        fallback_pool: Proofs consulted after the priority pool is exhausted.

    Returns:
        The chosen proofs and the union of validator indices they cover.
    """
    # Picks accumulate across both pools, sharing one running coverage set.
    selected_proofs: list[SingleMessageAggregate] = []
    covered_validators: set[ValidatorIndex] = set()

    # Priority pool first, so its proofs win before the fallback is touched.
    for proof_pool in (priority_pool, fallback_pool):
        if not proof_pool:
            continue

        # Materialize each proof's validator set once, up front.
        # Otherwise every comparison below would reparse the bitfield.
        validators_covered_by = {
            proof: set(proof.participants.to_validator_indices()) for proof in proof_pool
        }

        # Greedy set-cover: repeatedly take the proof adding the most new validators.
        candidate_proofs = set(proof_pool)
        while candidate_proofs:
            # Pick the proof adding the most still-uncovered validators.
            #
            # The key is a tuple, compared left to right:
            #
            #   - len(new coverage)  most new validators wins.
            #   - encoded bytes      ties go to the largest canonical encoding.
            #
            # Without the second key, ties fall to set iteration order.
            # That order is randomized per process, so different runs could pick differently.
            # The encoding makes every tie resolve to one stable winner.
            #
            # Example, with covered_validators = {0, 1} and two candidates left:
            #
            #   A covers {1, 2, 3}  ->  newly_covered = {2, 3}  ->  key = (2, bytes_A)
            #   B covers {2}        ->  newly_covered = {2}     ->  key = (1, bytes_B)
            #
            #   max picks A, since 2 > 1.
            best_proof = max(
                candidate_proofs,
                key=lambda proof: (
                    len(validators_covered_by[proof] - covered_validators),
                    proof.encode_bytes(),
                ),
            )

            # Best adds the most, so if it adds nothing, nothing does: stop at full coverage.
            # Greedy only affects how many proofs, never which validators end up covered.
            newly_covered = validators_covered_by[best_proof] - covered_validators
            if not newly_covered:
                break

            # Record this proof as chosen.
            selected_proofs.append(best_proof)
            # Grow the running coverage so later picks are scored against it.
            covered_validators |= newly_covered
            # Drop it from contention so it is not weighed again.
            candidate_proofs.discard(best_proof)

    return selected_proofs, covered_validators


class AggregationMixin(LstarSpecBase):
    """Attestation aggregation for the lstar fork."""

    def aggregate(self, store: LstarStore) -> tuple[LstarStore, list[SignedAggregatedAttestation]]:
        """
        Combine raw validator votes into compact aggregated attestations.

        A validator signs its vote and gossips it as a raw signature.
        It must become a compact proof before it can sway fork choice or enter a block.

        Three pools of evidence feed each round:

        - Gossip signatures: individual votes arriving in real time.
        - New payloads: proofs aggregated this round, not yet on chain.
        - Known payloads: previously accepted proofs, reused as building blocks.

        Each unique attestation data is processed in select, fill, and aggregate phases.
        """
        # The validator registry from the head state, indexed by validator index.
        # Aggregation looks up each contributor's public key through it.
        validators = store.states[store.head].validators

        new_aggregates = []

        # Process only data with fresh evidence: a new payload or a raw gossip signature.
        #
        # Known payloads cannot start a round alone, since re-aggregating them adds nothing.
        # They serve only as fallback building blocks once fresh evidence exists.
        # Iterate in insertion order, in order to have a deterministic pool order.
        for attestation_data in {
            **store.latest_new_aggregated_payloads,
            **store.attestation_signatures,
        }:
            # Phase 1: Select.
            #
            # Reuse existing proofs first to keep the proof tree shallow.
            # New payloads outrank known ones, so uncommitted work is reused first.
            child_proofs, covered_validators = select_proofs_for_coverage(
                store.latest_new_aggregated_payloads.get(attestation_data),
                store.latest_known_aggregated_payloads.get(attestation_data),
            )

            # Phase 2: Fill.
            #
            # Child proofs already cover some validators.
            # Each remaining validator still needs its individual raw vote.
            # Collect the triple the prover consumes: index, public key, signature.
            # Sorting by validator index keeps the result independent of arrival order.
            #
            # Example, with covered_validators = {0, 2} and gossip votes from {0, 1, 3}:
            #
            #   v = 0  ->  already covered, skipped
            #   v = 1  ->  (1, key_1, signature_1)
            #   v = 3  ->  (3, key_3, signature_3)
            #
            #   raw_signatures = [(1, key_1, signature_1), (3, key_3, signature_3)]
            raw_signatures = [
                (
                    signature_entry.validator_index,
                    PublicKey.decode_bytes(
                        validators[signature_entry.validator_index].attestation_public_key
                    ),
                    signature_entry.signature,
                )
                for signature_entry in sorted(
                    store.attestation_signatures.get(attestation_data, set()),
                    key=lambda entry: entry.validator_index,
                )
                if signature_entry.validator_index not in covered_validators
            ]

            # Aggregation needs fresh material: one raw signature, or two child proofs to merge.
            # A lone child proof is already valid, so there is nothing to do.
            if not raw_signatures and len(child_proofs) < 2:
                continue

            # Phase 3: Aggregate.
            #
            # Each child proof is re-verified while the outer proof is built.
            # Verifying one needs the public keys of the validators it covers.
            # So pair every child proof with those keys, resolved by index.
            #
            # Example, for a child proof covering validators {2, 5}:
            #
            #   participants  ->  [2, 5]
            #   public keys   ->  [key_2, key_5]   (resolved by index in the registry)
            #   paired as     ->  (child_proof, [key_2, key_5])
            children_with_keys = [
                (
                    child_proof,
                    [
                        PublicKey.decode_bytes(validators[validator_index].attestation_public_key)
                        for validator_index in child_proof.participants.to_validator_indices()
                    ],
                )
                for child_proof in child_proofs
            ]

            # One proof covering every selected validator comes back.
            proof = SingleMessageAggregate.aggregate(
                children=children_with_keys,
                raw_xmss=raw_signatures,
                message=hash_tree_root(attestation_data),
                slot=attestation_data.slot,
            )
            new_aggregates.append(SignedAggregatedAttestation(data=attestation_data, proof=proof))

        # Replace the new-payload pool with this round's proofs, keyed by attestation data.
        # Future rounds reuse these as building blocks.
        new_aggregated_payloads = {
            signed_attestation.data: {signed_attestation.proof}
            for signed_attestation in new_aggregates
        }

        # Those proofs absorbed their gossip signatures, so drop the raw copies.
        remaining_attestation_signatures = {
            attestation_data: signatures
            for attestation_data, signatures in store.attestation_signatures.items()
            if attestation_data not in new_aggregated_payloads
        }

        return store.model_copy(
            update={
                "latest_new_aggregated_payloads": new_aggregated_payloads,
                "attestation_signatures": remaining_attestation_signatures,
            }
        ), new_aggregates
