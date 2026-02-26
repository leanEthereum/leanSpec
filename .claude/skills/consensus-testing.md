---
name: consensus-testing
description: "Specialized patterns for testing consensus and fork choice code with multiple validators. Use when writing tests in tests/consensus/, or when testing functions involving validators, attestations, justification, or finalization."
---

# Consensus & Fork Choice Testing Patterns

Testing consensus logic requires understanding how validators interact. Single-validator tests miss critical dynamics.

## Multi-Validator Test Design

**Minimum validator counts by scenario:**
- Basic consensus: 4 validators (allows 1 byzantine, maintains 2/3 honest)
- Justification threshold: 8+ validators (clean 2/3 math)

**Always vary the validator set composition:**
- All validators honest and online
- Supermajority honest (exactly 2/3 + 1)
- At justification threshold (exactly 2/3)
- Below threshold (2/3 - 1, should fail to justify)
- Mixed online/offline validators

## Validator Relationship Scenarios

Test how validators interact, not just individual behavior:

**Attestation patterns:**
- All validators attest to same head (happy path)
- Validators split between two competing heads
- Staggered attestations across slots
- Late attestations arriving after new blocks
- Missing attestations from subset of validators

**Proposer/attester dynamics:**
- Proposer includes own attestation
- Proposer excludes valid attestations (censorship)
- Attestations reference proposer's parent (not proposer's block)
- Multiple blocks proposed for same slot (equivocation)

**Committee behavior:**
- Full committee participation
- Partial committee (threshold edge cases)
- Empty committee attestations
- Cross-committee attestation conflicts

## Fork Choice Scenarios

Fork choice tests must exercise competing chain heads:

**Branch competition:**
```
         +-- B2a <- B3a (3 attestations)
genesis <- B1 -+
         +-- B2b <- B3b (4 attestations)  <- winner
```
- Test that head follows attestation weight
- Verify re-org when new attestations shift weight
- Check tie-breaking rules when weights equal

**Critical scenarios to cover:**
1. **Weight transitions**: Head changes as attestations arrive
2. **Deep re-orgs**: New branch overtakes after multiple slots
3. **Equivocation handling**: Same validator attests to conflicting heads
4. **Checkpoint boundaries**: Behavior at epoch transitions
5. **Finalization effects**: Finalized blocks cannot be re-orged

## Justification & Finalization

The 2/3 supermajority threshold is critical:

**Justification tests:**
- Exactly 2/3 participation -> should justify
- One less than 2/3 -> should NOT justify
- Validators with different effective balances (weighted voting)
- Justification with gaps (skip epochs)

**Finalization tests:**
- Two consecutive justified epochs -> finalization
- Justified but not finalized (gap in justification)
- Finalization with varying participation rates
- Cannot finalize without prior justification

## Timing & Ordering

Consensus is sensitive to when events occur:

**Test event orderings:**
- Attestation before vs after block arrival
- Multiple attestations in same slot vs spread across slots
- Block arrives late (after attestation deadline)
- Out-of-order block delivery (child before parent)

**Slot boundary behavior:**
- Actions at slot start vs slot end
- Crossing epoch boundaries
- Genesis slot special cases

## Spec Filler Patterns for Fork Choice

```python
def test_competing_branches(fork_choice_test: ForkChoiceTestFiller) -> None:
    """Fork choice selects branch with higher attestation weight."""
    fork_choice_test(
        anchor_state=genesis_state,
        anchor_block=genesis_block,
        steps=[
            # Build competing branches
            OnBlock(block=block_2a),
            OnBlock(block=block_2b),
            # Add attestations favoring branch b
            OnAttestation(attestation=att_for_2b_validator_0),
            OnAttestation(attestation=att_for_2b_validator_1),
            OnAttestation(attestation=att_for_2a_validator_2),
            # Verify head follows weight
            Checks(head=block_2b.hash_tree_root()),
        ],
    )
```

## State Transition with Multiple Validators

```python
def test_justification_threshold(state_transition_test: StateTransitionTestFiller) -> None:
    """State justifies checkpoint when 2/3 validators attest."""
    # Create state with 8 validators
    state = create_state_with_validators(count=8)

    # Block with attestations from exactly 6/8 validators (75% > 2/3)
    block = create_block_with_attestations(
        state=state,
        attesting_validators=[0, 1, 2, 3, 4, 5],  # 6 of 8
    )

    state_transition_test(
        pre=state,
        blocks=[block],
        post=StateExpectation(
            current_justified_checkpoint=expected_checkpoint,
        ),
    )
```

## Common Pitfalls

Avoid these testing mistakes:

1. **Single validator tests** - Miss consensus dynamics entirely
2. **Always-honest scenarios** - Never test byzantine behavior
3. **Ignoring weights** - Validators may have different balances
4. **Fixed ordering** - Real networks have non-deterministic message arrival
5. **Skipping threshold edges** - The 2/3 boundary is where bugs hide
6. **Testing implementation** - Test spec behavior, not internal state
