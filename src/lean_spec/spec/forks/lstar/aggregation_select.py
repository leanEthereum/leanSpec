"""Greedy proof selection for lstar block production."""

from lean_spec.spec.forks.lstar.containers import SingleMessageAggregate, ValidatorIndex


def select_greedily(
    *proof_sets: set[SingleMessageAggregate] | None,
) -> tuple[list[SingleMessageAggregate], set[ValidatorIndex]]:
    """
    Greedy set-cover over single-message aggregate proofs maximizing validator coverage.

    Iterates the proof sets in order, repeatedly picking the proof with the
    most uncovered validators until no further coverage is possible.
    Earlier proof sets are prioritized so gossip-fresh proofs win over
    already-known ones.

    The validator-index sets are materialized once per proof, not inside the
    inner max key, so the loop runs in O(P * V) instead of O(P^2 * V).

    Args:
        *proof_sets: One or more sets of single-message aggregate proofs, ordered by priority.
            None entries are skipped.

    Returns:
        The chosen proofs and the union of validator indices they cover.
    """
    selected: list[SingleMessageAggregate] = []
    covered: set[ValidatorIndex] = set()

    for proofs in proof_sets:
        if not proofs:
            continue

        # Materialize each proof's validator index set once.
        # The greedy loop below would otherwise recompute it on every comparison.
        coverage_of: dict[SingleMessageAggregate, set[ValidatorIndex]] = {
            p: set(p.participants.to_validator_indices()) for p in proofs
        }
        remaining = list(proofs)

        while remaining:
            best = max(remaining, key=lambda p: len(coverage_of[p] - covered))
            new_coverage = coverage_of[best] - covered
            if not new_coverage:
                break
            selected.append(best)
            covered |= new_coverage
            remaining.remove(best)

    return selected, covered
