---
title: leanSpec → Lean4 Proof Propositions Catalog
last_updated: 2026-05-01
tags:
  - lean4
  - formal-verification
  - propositions
  - safety
  - consensus
---

# leanSpec → Lean4 Proof Propositions Catalog

## Context

`leanSpec` is the Python specification of the Lean Ethereum consensus.
To guarantee that any client implementation derived from this specification is safe,
spec-level **propositions** must be extracted and discharged as theorems in Lean4.

- **Goal**: design a verifiably safe client specification.
- **Strategy**: start from concrete, function-local propositions (input/output equalities, range bounds, round-trips) and progress upward to system-wide invariants.
- **Role of this document**: a prioritized catalog of propositions to formalize in Lean4.
    - Each entry pairs natural language, a semi-formal `∀/⇒` statement, and a Lean4 skeleton.
    - Tier 1/2/3 ranks implementation difficulty.
    - Coverage spans 4 areas: consensus core, SSZ and primitive types, validator duties, networking and sync.

> A Japanese sibling lives at [`lean4-proof-propositions.md`](lean4-proof-propositions.md).
> This English catalog is **not** a translation: where exploration uncovered exact constants
> or line ranges, the propositions here state them literally.

## Approach

### Abstraction levels

- **L1 (concrete)**: closed-form computational equalities. Example: `process_slots(s, n).slot = s.slot + n`.
- **L2 (medium)**: relations between functions, invariant preservation. Example: `latest_justified.slot` is monotone across `process_block`.
- **L3 (abstract)**: system-wide properties. Example: the fork-choice graph is acyclic; finalization is irreversible.

This document targets **L1 with selected L2**. L3 propositions are listed in Tier 3 and will be expanded in a follow-up phase once the lower tiers are stable.

### Tier semantics

- **Tier 1 (low)**: 1–2 days per proof. No prerequisites. Builds the foundation.
- **Tier 2 (medium)**: ~1 week per proof. Depends on Tier 1 lemmas. Encodes core safety.
- **Tier 3 (high)**: high abstraction, or requires a cryptographic assumption stated as `axiom`.

### Notation

- Semi-formal lines use `∀ … . …` and `⇒`.
- Lean4 skeletons end with `:= by sorry`. Proofs are deferred.
- Source references use `path/file.py:lo-hi` against the working tree at commit `c66da82` and later.
- Lean4 types live in a hypothetical `LeanSpec` namespace (`LeanSpec.SSZ.Uint64`, `LeanSpec.Forks.Lstar.State`, etc.).

```lean
-- Skeleton template
theorem foo (s : State) : P s := by sorry
```

## Tier 1 — Pure computation, range, round-trip, bounds

### T1-A. SSZ and primitive type laws

#### T1-A.1. Boolean encode/decode round-trip

- Source: `src/lean_spec/types/boolean.py:87-103`
- Natural language: encoding then decoding any boolean recovers the original; only `0x00` and `0x01` are accepted on decode.
- Semi-formal: `∀ b : Boolean. decode (encode b) = some b ∧ encode b ∈ {0x00, 0x01}` and `∀ x ≥ 0x02. decode (singleton x) = none`.
- Lean4:

```lean
theorem boolean_roundtrip (b : Boolean) :
    Boolean.decode (Boolean.encode b) = some b := by sorry

theorem boolean_encode_singleton (b : Boolean) :
    Boolean.encode b = #[0] ∨ Boolean.encode b = #[1] := by sorry

theorem boolean_decode_rejects (x : UInt8) (hx : 2 ≤ x) :
    Boolean.decode #[x] = none := by sorry
```

#### T1-A.2. Uint64 range invariant

- Source: `src/lean_spec/types/uint.py:22-38`
- Natural language: every `Uint64` value is in `[0, 2^64)`; the constructor rejects out-of-range integers.
- Semi-formal: `∀ v : Uint64. 0 ≤ v.toNat < 2^64`.
- Lean4:

```lean
theorem uint64_range (v : Uint64) :
    v.toNat < 2 ^ 64 := by sorry
```

#### T1-A.3. Uint64 little-endian round-trip

- Source: `src/lean_spec/types/uint.py:84-126`
- Natural language: 8-byte little-endian encode then decode is identity; output is exactly 8 bytes.
- Semi-formal: `∀ v : Uint64. decode (encode v) = some v ∧ |encode v| = 8`.
- Lean4:

```lean
theorem uint64_roundtrip (v : Uint64) :
    Uint64.decode (Uint64.encode v) = some v := by sorry

theorem uint64_encode_length (v : Uint64) :
    (Uint64.encode v).size = 8 := by sorry
```

#### T1-A.4. UintN byte length is `BITS / 8`

- Source: `src/lean_spec/types/uint.py:84-91`
- Natural language: for every supported width `N ∈ {8, 16, 32, 64, 256}`, encoded length equals `N / 8`.
- Semi-formal: `∀ N ∈ {8,16,32,64,256}. ∀ v : UintN. |encode v| = N / 8`.
- Lean4:

```lean
theorem uintN_encode_length (N : Nat) (hN : N ∈ ({8,16,32,64,256} : Set Nat))
    (v : UintN N) :
    (UintN.encode v).size = N / 8 := by sorry
```

#### T1-A.5. Bytes32 fixed length

- Source: `src/lean_spec/types/byte_arrays.py:59-98`
- Natural language: every `Bytes32` value has exactly 32 bytes; `Bytes32.zero` is the all-zero buffer.
- Semi-formal: `∀ bs : Bytes32. bs.size = 32` and `Bytes32.zero = ByteArray.replicate 32 0`.
- Lean4:

```lean
theorem bytes32_length (bs : Bytes32) : bs.toByteArray.size = 32 := by sorry

theorem bytes32_zero_def :
    Bytes32.zero.toByteArray = ByteArray.mk (Array.mkArray 32 0) := by sorry
```

#### T1-A.6. ByteList limit

- Source: `src/lean_spec/types/byte_arrays.py:262-338`
- Natural language: a `ByteList[LIMIT]` always carries between `0` and `LIMIT` bytes inclusive.
- Semi-formal: `∀ LIMIT. ∀ b : ByteList LIMIT. b.data.size ≤ LIMIT`.
- Lean4:

```lean
theorem bytelist_size_le (LIMIT : Nat) (b : ByteList LIMIT) :
    b.data.size ≤ LIMIT := by sorry
```

#### T1-A.7. SSZVector length invariant

- Source: `src/lean_spec/types/collections.py:153-158`
- Natural language: every fixed-length vector holds exactly `LENGTH` elements.
- Semi-formal: `∀ T LENGTH. ∀ v : SSZVector T LENGTH. v.data.length = LENGTH`.
- Lean4:

```lean
theorem sszvector_length {T : Type} {LENGTH : Nat}
    (v : SSZVector T LENGTH) :
    v.data.length = LENGTH := by sorry
```

#### T1-A.8. SSZList limit

- Source: `src/lean_spec/types/collections.py:321-323, 352`
- Natural language: every `SSZList[T, LIMIT]` has at most `LIMIT` elements; lists are never fixed-size.
- Semi-formal: `∀ T LIMIT. ∀ l : SSZList T LIMIT. l.data.length ≤ LIMIT ∧ ¬ SSZList.isFixedSize`.
- Lean4:

```lean
theorem sszlist_size_le {T : Type} {LIMIT : Nat}
    (l : SSZList T LIMIT) :
    l.data.length ≤ LIMIT := by sorry

theorem sszlist_not_fixed_size {T : Type} {LIMIT : Nat} :
    ¬ SSZList.isFixedSize T LIMIT := by sorry
```

#### T1-A.9. Bitvector packing

- Source: `src/lean_spec/types/bitfields.py:61-129`
- Natural language: a `Bitvector[N]` serializes to `⌈N / 8⌉` bytes using little-endian bit packing; encode/decode round-trips.
- Semi-formal: `∀ N. ∀ bv : Bitvector N. |encode bv| = (N + 7) / 8 ∧ decode (encode bv) = some bv`.
- Lean4:

```lean
theorem bitvector_encode_length (N : Nat) (bv : Bitvector N) :
    (Bitvector.encode bv).size = (N + 7) / 8 := by sorry

theorem bitvector_roundtrip (N : Nat) (bv : Bitvector N) :
    Bitvector.decode (Bitvector.encode bv) = some bv := by sorry
```

#### T1-A.10. Bitlist delimiter

- Source: `src/lean_spec/types/bitfields.py:166-284`
- Natural language: a bitlist is encoded with a delimiter bit `1` placed exactly at position `num_bits`; decoding finds the highest set bit and recovers the original sequence.
- Semi-formal: `∀ LIMIT. ∀ bl : Bitlist LIMIT. let e = encode bl in highestSetBit e = bl.length ∧ decode e = some bl`.
- Lean4:

```lean
theorem bitlist_delimiter_position (LIMIT : Nat) (bl : Bitlist LIMIT) :
    Bitlist.highestSetBit (Bitlist.encode bl) = bl.length := by sorry

theorem bitlist_roundtrip (LIMIT : Nat) (bl : Bitlist LIMIT) :
    Bitlist.decode (Bitlist.encode bl) = some bl := by sorry
```

#### T1-A.11. Container size composition

- Source: `src/lean_spec/types/container.py:63-99`
- Natural language: a container is fixed-size iff every field is fixed-size, and in that case its byte length is the sum of field byte lengths.
- Semi-formal:
  - `isFixed C ⇔ ∀ f ∈ fields C. isFixed (typeOf f)`
  - `isFixed C ⇒ byteLength C = Σ f ∈ fields C, byteLength (typeOf f)`
- Lean4:

```lean
theorem container_fixed_iff (C : Container) :
    Container.isFixedSize C ↔ ∀ f ∈ C.fields, FieldType.isFixedSize f := by sorry

theorem container_byte_length_sum (C : Container)
    (h : Container.isFixedSize C) :
    Container.byteLength C =
      (C.fields.map FieldType.byteLength).foldl (· + ·) 0 := by sorry
```

#### T1-A.12. `get_power_of_two_ceil` minimality

- Source: `src/lean_spec/subspecs/ssz/utils.py:10-14`
- Natural language: for any positive `x`, `ceilPow2 x` is the smallest power of two greater than or equal to `x`.
- Semi-formal: `∀ x > 0. x ≤ ceilPow2 x ∧ ∃ k. ceilPow2 x = 2^k ∧ (k = 0 ∨ 2^(k-1) < x)`.
- Lean4:

```lean
theorem ceil_pow2_minimal (x : Nat) (h : 0 < x) :
    x ≤ SSZ.ceilPow2 x ∧
    ∃ k, SSZ.ceilPow2 x = 2 ^ k ∧
      (k = 0 ∨ 2 ^ (k - 1) < x) := by sorry
```

#### T1-A.13. `merkleize` single-chunk identity

- Source: `src/lean_spec/subspecs/ssz/merkleization.py:81-83`
- Natural language: merkleizing a list with exactly one 32-byte chunk returns that chunk.
- Semi-formal: `∀ c : Bytes32. merkleize [c] = c`.
- Lean4:

```lean
theorem merkleize_singleton (c : Bytes32) :
    SSZ.merkleize [c] = c := by sorry
```

#### T1-A.14. `mix_in_length` distinguishes lengths

- Source: `src/lean_spec/subspecs/ssz/merkleization.py:148-153`
- Natural language: under SHA-256 collision resistance, mixing in distinct lengths yields distinct mixed roots.
- Semi-formal: `∀ root len₁ len₂. len₁ ≠ len₂ ⇒ mix_in_length root len₁ ≠ mix_in_length root len₂` (modulo the SHA-256 collision-resistance axiom).
- Lean4:

```lean
theorem mix_in_length_injective_on_length
    (root : Bytes32) (l1 l2 : Nat) (h : l1 ≠ l2) :
    SSZ.mixInLength root l1 ≠ SSZ.mixInLength root l2 := by sorry
```

### T1-B. Slot and Checkpoint algebra

#### T1-B.1. Checkpoint ordering by slot

- Source: `src/lean_spec/forks/lstar/containers/checkpoint.py:14-29`
- Natural language: checkpoint `<` is purely slot-based; the root never participates in the ordering.
- Semi-formal: `∀ c₁ c₂ : Checkpoint. c₁ < c₂ ↔ c₁.slot < c₂.slot`.
- Lean4:

```lean
theorem checkpoint_lt_iff_slot_lt (c1 c2 : Checkpoint) :
    c1 < c2 ↔ c1.slot < c2.slot := by sorry
```

#### T1-B.2. `is_justifiable_after` 3-condition disjunction

- Source: `src/lean_spec/forks/lstar/containers/slot.py:30-76`
- Natural language: with `δ = target − finalized`, the slot is justifiable iff `δ ≤ 5`, or `δ` is a perfect square, or `δ` is a pronic number `k(k+1)`.
- Semi-formal: `∀ f t. f ≤ t ⇒ (isJustifiableAfter f t ↔ let δ = t-f in δ ≤ 5 ∨ ∃ k. δ = k*k ∨ ∃ k. δ = k*(k+1))`.
- Lean4:

```lean
theorem justifiable_iff
    (finalized target : Slot) (h : finalized ≤ target) :
    Slot.isJustifiableAfter finalized target ↔
      let δ := target.toNat - finalized.toNat
      δ ≤ 5 ∨ (∃ k, δ = k * k) ∨ (∃ k, δ = k * (k + 1)) := by sorry
```

#### T1-B.3. `justified_index_after` formula

- Source: `src/lean_spec/forks/lstar/containers/slot.py:17-28`
- Natural language: returns `none` exactly when the slot has reached finalized; otherwise the index is `slot − finalized − 1`.
- Semi-formal: `∀ slot fin. justifiedIndexAfter slot fin = if slot ≤ fin then none else some (slot - fin - 1)`.
- Lean4:

```lean
theorem justified_index_after_def (slot fin : Slot) :
    Slot.justifiedIndexAfter slot fin =
      (if slot.toNat ≤ fin.toNat then none
       else some (slot.toNat - fin.toNat - 1)) := by sorry
```

#### T1-B.4. Round-robin proposer selection

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:182-323` (header check `228-231`)
- Natural language: with `n > 0` validators, the proposer for slot `s` is `s mod n`.
- Semi-formal: `∀ s n. n > 0 ⇒ proposerIndex s n = s mod n`.
- Lean4:

```lean
theorem proposer_index_round_robin (s : Slot) (n : Nat) (h : 0 < n) :
    ValidatorIndex.proposerFor s n = ValidatorIndex.mk (s.toNat % n) := by sorry
```

### T1-C. Validator-side bounds

#### T1-C.1. Dual-key separation

- Source: `src/lean_spec/subspecs/validator/service.py:402, 441` (fields `proposal_secret_key`, `attestation_secret_key`)
- Natural language: every validator's proposal key is distinct from its attestation key.
- Semi-formal: `∀ vid : ValidatorIndex. proposalKey vid ≠ attestationKey vid`.
- Lean4:

```lean
theorem dual_key_distinct (reg : KeyRegistry) (vid : ValidatorIndex) :
    reg.proposalKey vid ≠ reg.attestationKey vid := by sorry
```

#### T1-C.2. Bounded `_attested_slots` window

- Source: `src/lean_spec/subspecs/validator/service.py:194-209`
- Natural language: after pruning, the local "already attested" set holds at most 5 slots.
- Semi-formal: `∀ svc current. (svc.pruneAttestedSlots current).attestedSlots.size ≤ 5`.
- Lean4:

```lean
theorem attested_slots_bounded (svc : ValidatorService) (current : Slot) :
    (svc.pruneAttestedSlots current).attestedSlots.size ≤ 5 := by sorry
```

### T1-D. Networking boundary values

#### T1-D.1. `BlocksByRange` count bound

- Source: `src/lean_spec/subspecs/networking/reqresp/handler.py:283-287`
- Natural language: a successful response has at most `min(req.count, 1024)` blocks (`MAX_REQUEST_BLOCKS = 1024`).
- Semi-formal: `∀ req resp. handleBlocksByRange req = ok resp ⇒ resp.length ≤ min req.count 1024`.
- Lean4:

```lean
theorem blocks_by_range_count_bounded
    (req : BlocksByRangeRequest) (resp : List Block)
    (h : Networking.handleBlocksByRange req = .ok resp) :
    resp.length ≤ Nat.min req.count.toNat 1024 := by sorry
```

#### T1-D.2. Sliding-window start

- Source: `src/lean_spec/subspecs/networking/reqresp/handler.py:296-303`
- Natural language: requests must satisfy `req.start_slot ≥ current_slot − 3600` (`MIN_SLOTS_FOR_BLOCK_REQUESTS = 3600`).
- Semi-formal: `∀ req current. handleBlocksByRange req current = ok _ ⇒ req.startSlot + 3600 ≥ current ∨ current < 3600`.
- Lean4:

```lean
theorem blocks_by_range_sliding_window
    (req : BlocksByRangeRequest) (current : Slot) (resp : List Block)
    (h : Networking.handleBlocksByRange req current = .ok resp) :
    req.startSlot.toNat + 3600 ≥ current.toNat ∨ current.toNat < 3600 := by sorry
```

#### T1-D.3. Codec payload upper bound

- Source: `src/lean_spec/subspecs/networking/reqresp/codec.py:121-122`
- Natural language: `encode_request` accepts only payloads up to 10 MiB (`MAX_PAYLOAD_SIZE = 10 * 1024 * 1024`).
- Semi-formal: `∀ d. encodeRequest d = ok _ ⇒ d.size ≤ 10485760`.
- Lean4:

```lean
def MAX_PAYLOAD_SIZE : Nat := 10 * 1024 * 1024

theorem codec_payload_bound (d : ByteArray) (out : ByteArray)
    (h : Codec.encodeRequest d = .ok out) :
    d.size ≤ MAX_PAYLOAD_SIZE := by sorry
```

#### T1-D.4. Codec round-trip

- Source: `src/lean_spec/subspecs/networking/reqresp/codec.py:95-193`
- Natural language: encoding then decoding is identity for any payload of legal size.
- Semi-formal: `∀ d. d.size ≤ 10485760 ⇒ decodeRequest (encodeRequest d) = some d`.
- Lean4:

```lean
theorem codec_roundtrip (d : ByteArray) (h : d.size ≤ MAX_PAYLOAD_SIZE) :
    Codec.decodeRequest (Codec.encodeRequest d).get! = some d := by sorry
```

## Tier 2 — Core invariants and well-formedness

### T2-A. State transition

#### T2-A.1. `process_slots` advances slot to target

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:113-180`
- Natural language: when `process_slots` succeeds, the resulting state's slot equals the target.
- Semi-formal: `∀ s target. s.slot < target ⇒ (processSlots s target).slot = target`.
- Lean4:

```lean
theorem process_slots_advances (s : State) (target : Slot)
    (h : s.slot < target) :
    (State.processSlots s target).slot = target := by sorry
```

#### T2-A.2. `process_block_header` slot alignment

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:182-323`
- Natural language: a successful header processing yields a state whose `latest_block_header.slot` equals the block slot, with `state_root` reset to zero pending body processing.
- Semi-formal: `processBlockHeader s b = ok s' ⇒ s'.latestBlockHeader.slot = b.slot ∧ s'.latestBlockHeader.stateRoot = Bytes32.zero`.
- Lean4:

```lean
theorem process_block_header_slot
    (s : State) (b : Block) (s' : State)
    (h : State.processBlockHeader s b = .ok s') :
    s'.latestBlockHeader.slot = b.slot ∧
    s'.latestBlockHeader.stateRoot = Bytes32.zero := by sorry
```

#### T2-A.3. Historical-hashes gap formula

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:271-278`
- Natural language: after `process_block_header`, the historical hashes are extended by the parent root followed by zero-fill for the empty slots between parent and current block.
- Semi-formal: with `gap = b.slot − parent.slot − 1`, `s'.historicalHashes = s.historicalHashes ++ [parent.root] ++ [ZERO]^gap`.
- Lean4:

```lean
theorem historical_hashes_gap
    (s : State) (b : Block) (s' : State)
    (h : State.processBlockHeader s b = .ok s') :
    let gap := b.slot.toNat - s.latestBlockHeader.slot.toNat - 1
    s'.historicalHashes = s.historicalHashes ++
      [s.latestBlockHeader.root] ++ List.replicate gap Bytes32.zero := by sorry
```

#### T2-A.4. Justified slot monotonicity

- Source: `src/lean_spec/forks/lstar/containers/state/state.py` (process_attestations)
- Natural language: every state transition preserves or advances `latest_justified.slot`.
- Semi-formal: `transition s b = ok s' ⇒ s.latestJustified.slot ≤ s'.latestJustified.slot`.
- Lean4:

```lean
theorem justified_slot_monotone (s s' : State) (b : Block)
    (h : State.transition s b = .ok s') :
    s.latestJustified.slot ≤ s'.latestJustified.slot := by sorry
```

#### T2-A.5. Finalized slot monotonicity

- Source: same region.
- Natural language: every state transition preserves or advances `latest_finalized.slot`.
- Semi-formal: `transition s b = ok s' ⇒ s.latestFinalized.slot ≤ s'.latestFinalized.slot`.
- Lean4:

```lean
theorem finalized_slot_monotone (s s' : State) (b : Block)
    (h : State.transition s b = .ok s') :
    s.latestFinalized.slot ≤ s'.latestFinalized.slot := by sorry
```

#### T2-A.6. Justified ≥ finalized invariant

- Source: derived; relies on T2-A.4 and T2-A.5.
- Natural language: in any reachable state, the latest justified slot is at least the latest finalized slot.
- Semi-formal: `∀ s. Reachable s ⇒ s.latestJustified.slot ≥ s.latestFinalized.slot`.
- Lean4:

```lean
theorem justified_ge_finalized (s : State) (h : Reachable s) :
    s.latestFinalized.slot ≤ s.latestJustified.slot := by sorry
```

#### T2-A.7. Supermajority threshold

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:513`
- Natural language: a candidate becomes justified exactly when at least two-thirds of validators voted (using the integer formula `3·voted ≥ 2·total`).
- Semi-formal: `justifies voted total ↔ 3 * voted ≥ 2 * total`.
- Lean4:

```lean
theorem justifies_iff_supermajority (voted total : Nat) :
    State.justifies voted total ↔ 3 * voted ≥ 2 * total := by sorry
```

#### T2-A.8. State-root verification

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:592-628`
- Natural language: a successful `state_transition` guarantees the post-state's hash tree root matches the block's declared `state_root`.
- Semi-formal: `transition s b = ok s' ⇒ hashTreeRoot s' = b.stateRoot`.
- Lean4:

```lean
theorem state_transition_state_root
    (s s' : State) (b : Block)
    (h : State.transition s b = .ok s') :
    SSZ.hashTreeRoot s' = b.stateRoot := by sorry
```

### T2-B. Forkchoice

#### T2-B.1. Attestation temporal order

- Source: `src/lean_spec/forks/lstar/store.py:277-331` (`validate_attestation`)
- Natural language: validated attestations satisfy `source.slot ≤ target.slot ≤ head.slot`.
- Semi-formal: `validateAttestation st att = ok ⇒ att.source.slot ≤ att.target.slot ≤ att.head.slot`.
- Lean4:

```lean
theorem attestation_temporal_order
    (st : Store) (att : Attestation)
    (h : Store.validateAttestation st att = .ok) :
    att.data.source.slot ≤ att.data.target.slot ∧
    att.data.target.slot ≤ att.data.head.slot := by sorry
```

#### T2-B.2. Head descends from latest_justified

- Source: `src/lean_spec/forks/lstar/store.py:639-729`
- Natural language: the result of `compute_head` is reachable from `latest_justified.root` via parent-edges.
- Semi-formal: `computeHead st = h ⇒ isAncestorOrEqual st st.latestJustified.root h`.
- Lean4:

```lean
theorem head_descends_from_justified
    (st : Store) (h : Bytes32)
    (hh : Store.computeHead st = h) :
    Store.isAncestorOrEqual st st.latestJustified.root h := by sorry
```

#### T2-B.3. LMD-GHOST tie-break determinism

- Source: `src/lean_spec/forks/lstar/store.py:725-727`
- Natural language: at each level, ties on weight are broken by lexicographically smallest hash; `compute_head` is therefore a pure function.
- Semi-formal: `∀ st. computeHead st` is a function; `∀ st children. tieBreak children = argmin (lex-order) (argmax weight children)`.
- Lean4:

```lean
theorem compute_head_pure (st : Store) :
    Store.computeHead st = Store.computeHead st := rfl

theorem lmd_ghost_tiebreak
    (st : Store) (children : List Bytes32) (h : children ≠ []) :
    Store.lmdGhostPick st children =
      Store.lexMin (Store.argmaxByWeight st children) := by sorry
```

#### T2-B.4. `update_safe_target` two-thirds floor

- Source: `src/lean_spec/forks/lstar/store.py:806-873`
- Natural language: the chosen safe target accumulates at least `⌈2N/3⌉` votes among the `N` validators.
- Semi-formal: `updateSafeTarget st = ok st' ⇒ st'.safeTarget.votes ≥ ⌈2 * st.numValidators / 3⌉`.
- Lean4:

```lean
theorem safe_target_two_thirds
    (st st' : Store) (h : Store.updateSafeTarget st = .ok st') :
    st'.safeTarget.votes ≥ (2 * st.numValidators + 2) / 3 := by sorry
```

### T2-C. Storage integrity

#### T2-C.1. Parent existence

- Source: `src/lean_spec/subspecs/storage/database.py`
- Natural language: every block stored in the database is either genesis or has its parent already stored.
- Semi-formal: `∀ b ∈ db.blocks. b.parentRoot = Bytes32.zero ∨ db.blocks.contains b.parentRoot`.
- Lean4:

```lean
theorem parent_exists_or_genesis (db : Database) (b : Block)
    (hin : b ∈ db.blocks.values) :
    b.parentRoot = Bytes32.zero ∨ db.blocks.contains b.parentRoot := by sorry
```

#### T2-C.2. State get-after-put

- Source: `src/lean_spec/subspecs/storage/database.py`
- Natural language: reading a state by block root after writing returns the value that was written.
- Semi-formal: `∀ db root s. (db.putState s root).getState root = some s`.
- Lean4:

```lean
theorem state_get_after_put (db : Database) (root : Bytes32) (s : State) :
    (db.putState s root).getState root = some s := by sorry
```

### T2-D. Sync FSM

#### T2-D.1. Valid transitions

- Source: `src/lean_spec/subspecs/sync/service.py:172-…`
- Natural language: only the four edges `IDLE → SYNCING`, `SYNCING → SYNCED`, `SYNCED → SYNCING`, and `_ → IDLE` are permitted.
- Semi-formal: see the inductive relation below.
- Lean4:

```lean
inductive SyncState | idle | syncing | synced
deriving DecidableEq

inductive SyncState.canTransitionTo : SyncState → SyncState → Prop
  | idle_to_syncing    : SyncState.canTransitionTo .idle .syncing
  | syncing_to_synced  : SyncState.canTransitionTo .syncing .synced
  | synced_to_syncing  : SyncState.canTransitionTo .synced .syncing
  | any_to_idle (s)    : SyncState.canTransitionTo s .idle

theorem sync_transition_sound
    (s s' : SyncState)
    (h : SyncService.transition s = some s') :
    SyncState.canTransitionTo s s' := by sorry
```

#### T2-D.2. Gossip acceptance gate

- Source: `src/lean_spec/subspecs/sync/service.py`
- Natural language: gossip blocks are accepted immediately iff the service is in `SYNCING` or `SYNCED`; in `IDLE` they are queued.
- Semi-formal: `acceptsGossip st ↔ st = SYNCING ∨ st = SYNCED`.
- Lean4:

```lean
theorem accepts_gossip_iff (st : SyncState) :
    SyncService.acceptsGossip st ↔ st = .syncing ∨ st = .synced := by sorry
```

### T2-E. Validator slashing avoidance

#### T2-E.1. No double vote

- Source: `src/lean_spec/subspecs/validator/service.py:194-202`
- Natural language: the local guard prevents producing a second attestation for the same slot.
- Semi-formal: `slot ∈ svc.attestedSlots ⇒ produceAttestation svc slot = none`.
- Lean4:

```lean
theorem no_double_vote
    (svc : ValidatorService) (slot : Slot)
    (hin : slot ∈ svc.attestedSlots) :
    ValidatorService.produceAttestation svc slot = none := by sorry
```

#### T2-E.2. XMSS prepared interval advances

- Source: `src/lean_spec/subspecs/xmss/interface.py:490-543`
- Natural language: `advance_preparation` shifts the prepared window by `√LIFETIME` slots; once the window has reached the activation boundary it acts as the identity.
- Semi-formal: with `Δ = floor (sqrt LIFETIME)`,
  `getPreparedInterval (advancePreparation sk) = shiftBy Δ (getPreparedInterval sk)`
  unless the right edge has crossed `activationEnd`, in which case `advancePreparation sk = sk`.
- Lean4:

```lean
theorem xmss_advance_window
    (sk : XMSS.SecretKey) :
    let Δ := Nat.sqrt XMSS.LIFETIME
    let cur := XMSS.getPreparedInterval sk
    let nxt := XMSS.getPreparedInterval (XMSS.advancePreparation sk)
    nxt.start = cur.start + Δ ∨ XMSS.advancePreparation sk = sk := by sorry
```

#### T2-E.3. Gossipsub mesh size bound

- Source: `src/lean_spec/subspecs/networking/gossipsub/mesh.py` (and `parameters.py`)
- Natural language: after a heartbeat, every subscribed topic's mesh contains between `D_low = 6` and `D_high = 12` peers (target `D = 8`).
- Semi-formal: `∀ st topic. afterHeartbeat st ⇒ topic ∈ st.subscriptions ⇒ 6 ≤ |st.mesh[topic]| ∧ |st.mesh[topic]| ≤ 12`.
- Lean4:

```lean
theorem mesh_size_bounded_after_heartbeat
    (st : MeshState) (topic : TopicId)
    (hb : MeshState.afterHeartbeat st)
    (sub : topic ∈ st.subscriptions) :
    6 ≤ st.meshPeers topic ∧ st.meshPeers topic ≤ 12 := by sorry
```

## Tier 3 — Global safety and cryptographic foundations

### T3-A. Forkchoice global properties

#### T3-A.1. Forkchoice graph is acyclic

- Source: `src/lean_spec/forks/lstar/store.py` (block graph induced by `parentRoot`).
- Natural language: the parent-of relation never closes a loop.
- Semi-formal: `∀ st b. b ∈ st.blocks ⇒ ¬ isProperAncestor st b.root b.root`.
- Lean4:

```lean
theorem fork_choice_acyclic
    (st : Store) (hwf : Store.WellFormed st)
    (b : Block) (hb : b ∈ st.blocks.values) :
    ¬ Store.isProperAncestor st b.root b.root := by sorry
```

#### T3-A.2. Finalization irreversibility

- Source: derived from T2-A.5 plus the closure `↝*`.
- Natural language: across any sequence of state transitions, finalized slot never decreases.
- Semi-formal: `∀ s s'. s ↝* s' ⇒ s.latestFinalized.slot ≤ s'.latestFinalized.slot`.
- Lean4:

```lean
theorem finalization_irreversible
    (s s' : State) (h : ReachableFrom s s') :
    s.latestFinalized.slot ≤ s'.latestFinalized.slot := by sorry
```

#### T3-A.3. Block-production loop terminates

- Source: `src/lean_spec/forks/lstar/store.py:1236-1344` (`produce_block_with_signatures`).
- Natural language: the fixed-point loop over justification updates terminates because each iteration strictly increases `latestJustified.slot` or reaches a fixed point.
- Semi-formal: there is a measure `μ : LoopState → ℕ` with `μ st' < μ st` until the loop returns.
- Lean4:

```lean
theorem produce_block_loop_terminates
    (init : LoopState) :
    ∃ n, Store.produceBlockLoopIter init n = .done := by sorry
```

### T3-B. Determinism and hashing

#### T3-B.1. `state_transition` is a pure function

- Source: `src/lean_spec/forks/lstar/containers/state/state.py:592-628`
- Natural language: `state_transition` has no side effects in the spec model; equal inputs give equal outputs.
- Semi-formal: `∀ s b. State.transition s b = State.transition s b`.
- Lean4:

```lean
theorem state_transition_pure (s : State) (b : Block) :
    State.transition s b = State.transition s b := rfl
```

#### T3-B.2. `hash_tree_root` is deterministic; collision resistance as axiom

- Source: `src/lean_spec/subspecs/ssz/hash.py:34-159`
- Natural language: `hash_tree_root` is a total function; injectivity is taken as a cryptographic axiom rooted in SHA-256 collision resistance.
- Semi-formal: `∀ x. htr x = htr x` (provable); `axiom htr_injective : ∀ x y. htr x = htr y → x = y`.
- Lean4:

```lean
theorem htr_deterministic {α} [SSZType α] (x : α) :
    SSZ.hashTreeRoot x = SSZ.hashTreeRoot x := rfl

axiom HashTreeRoot.collisionResistance :
    ∀ {α} [SSZType α] (x y : α),
      SSZ.hashTreeRoot x = SSZ.hashTreeRoot y → x = y
```

### T3-C. KoalaBear field axioms

#### T3-C.1. `Fp` is a commutative ring

- Source: `src/lean_spec/subspecs/koalabear/field.py` (`P = 2^31 − 2^24 + 1`).
- Natural language: addition and multiplication in `Fp` satisfy the commutative ring axioms.
- Semi-formal: associativity, commutativity, distributivity, additive identity, multiplicative identity, additive inverse.
- Lean4:

```lean
instance : CommRing Fp where
  add_assoc := by sorry
  zero_add := by sorry
  add_zero := by sorry
  add_comm := by sorry
  add_left_neg := by sorry
  mul_assoc := by sorry
  one_mul := by sorry
  mul_one := by sorry
  left_distrib := by sorry
  right_distrib := by sorry
  mul_comm := by sorry
```

#### T3-C.2. Multiplicative inverse via Fermat

- Source: `src/lean_spec/subspecs/koalabear/field.py:98-103`
- Natural language: every nonzero `Fp` element raised to `P − 2` is its inverse.
- Semi-formal: `∀ a : Fp. a ≠ 0 ⇒ a * a^(P-2) = 1`.
- Lean4:

```lean
theorem fp_inverse_via_fermat (a : Fp) (h : a ≠ 0) :
    a * a ^ (Fp.P - 2) = 1 := by sorry
```

### T3-D. XMSS round-trip

#### T3-D.1. Sign / verify round-trip on prepared slots

- Source: `src/lean_spec/subspecs/xmss/interface.py:224-446`
- Natural language: with a freshly generated key pair and a slot in the prepared window, signing and then verifying returns `true`.
- Semi-formal: `∀ pk sk slot msg. (pk, sk) = keyGen activation count ∧ slot ∈ getPreparedInterval sk ⇒ verify pk slot msg (sign sk slot msg) = true`.
- Lean4:

```lean
theorem xmss_sign_verify
    (pk : XMSS.PublicKey) (sk : XMSS.SecretKey)
    (slot : Slot) (msg : Bytes32)
    (act : Slot) (count : Uint64)
    (hkg : XMSS.keyGen act count = (pk, sk))
    (hslot : slot ∈ XMSS.getPreparedInterval sk) :
    XMSS.verify pk slot msg (XMSS.sign sk slot msg) = true := by sorry
```

## Roadmap (concrete → abstract)

| Phase | Focus | Example propositions |
|-------|-------|---------------------|
| 1 | Pure computation (Tier 1) | T1-A.1, T1-A.3, T1-B.2 |
| 2 | Function pre/post-conditions (Tier 1–2) | T1-D.1, T2-A.1, T2-A.2 |
| 3 | State-transition monotonicity (Tier 2) | T2-A.4, T2-A.5, T2-A.6 |
| 4 | System invariants (Tier 2–3) | T2-C.1, T2-D.1, T2-E.3 |
| 5 | Global safety (Tier 3) | T3-A.1, T3-A.2 |
| 6 | Cryptographic composition (Tier 3) | T3-B.2, T3-D.1 |

Move to a phase only after the prior phase's proofs are merged.

## Proposed Lean4 file layout

```text
proofs/lean4/
  LeanSpec/
    Prelude.lean                        -- shared types (Slot, Checkpoint, Bytes32, …)
    SSZ/
      Boolean.lean                      -- T1-A.1
      Uint.lean                         -- T1-A.2..4
      Bytes.lean                        -- T1-A.5..6
      Collections.lean                  -- T1-A.7..8
      Bitfields.lean                    -- T1-A.9..10
      Container.lean                    -- T1-A.11
      Utils.lean                        -- T1-A.12
      Merkleization.lean                -- T1-A.13..14, T3-B.2
    Forks/Lstar/
      Slot.lean                         -- T1-B.2..3
      Checkpoint.lean                   -- T1-B.1
      Proposer.lean                     -- T1-B.4
      State.lean                        -- T2-A.*, T3-B.1
      Store.lean                        -- T2-B.*, T3-A.*
    Validator/
      DualKey.lean                      -- T1-C.1
      Slashing.lean                     -- T1-C.2, T2-E.1, T2-E.2
    Networking/
      ReqResp.lean                      -- T1-D.*
      Gossipsub.lean                    -- T2-E.3
    Sync/
      FSM.lean                          -- T2-D.*
    Storage/
      Database.lean                     -- T2-C.*
    Crypto/
      KoalaBear.lean                    -- T3-C.*
      XMSS.lean                         -- T3-D.1
  lakefile.lean                         -- Lake build manifest
  lean-toolchain                        -- pinned Lean4 release
```

Each Lean file starts as a stub with `sorry`; Tier 1 is discharged first.

## Cross-reference: source → propositions

| Python source | Propositions |
|---------------|--------------|
| `types/boolean.py` | T1-A.1 |
| `types/uint.py` | T1-A.2..4 |
| `types/byte_arrays.py` | T1-A.5..6 |
| `types/collections.py` | T1-A.7..8 |
| `types/bitfields.py` | T1-A.9..10 |
| `types/container.py` | T1-A.11 |
| `subspecs/ssz/utils.py` | T1-A.12 |
| `subspecs/ssz/merkleization.py` | T1-A.13..14 |
| `subspecs/ssz/hash.py` | T3-B.2 |
| `forks/lstar/containers/checkpoint.py` | T1-B.1 |
| `forks/lstar/containers/slot.py` | T1-B.2..3 |
| `forks/lstar/containers/state/state.py` | T1-B.4, T2-A.1..8, T3-B.1 |
| `forks/lstar/store.py` | T2-B.1..4, T3-A.1..3 |
| `subspecs/validator/service.py` | T1-C.1..2, T2-E.1 |
| `subspecs/xmss/interface.py` | T2-E.2, T3-D.1 |
| `subspecs/networking/reqresp/handler.py` | T1-D.1..2 |
| `subspecs/networking/reqresp/codec.py` | T1-D.3..4 |
| `subspecs/networking/gossipsub/mesh.py` | T2-E.3 |
| `subspecs/sync/service.py` | T2-D.1..2 |
| `subspecs/storage/database.py` | T2-C.1..2 |
| `subspecs/koalabear/field.py` | T3-C.1..2 |

## Open questions

- **Mathlib dependency**: T3-C (field axioms) is much smaller with Mathlib's `CommRing` / `ZMod` instances. Adopt Mathlib or roll our own minimal algebra layer?
- **Spec ↔ Lean4 correspondence**: Should Lean4 types mirror Python 1:1, or be reformulated for proof ergonomics (e.g., quotient types, refinement types)?
- **Test fixture reuse**: Can the JSON fixtures under `tests/consensus/` be lifted into Lean4 as executable specifications, useful for differential testing?
- **Axiom boundary**: Where exactly do we stop proving and add `axiom` (SHA-256 collision resistance, XMSS forgery resistance, Poseidon properties)?
- **L3 expansion**: Tier 3 currently lists 8 propositions. As the Tier 1/2 base solidifies, additional system-level properties (e.g., consensus liveness under partial synchrony) will be added in a follow-up document.
