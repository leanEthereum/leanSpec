---
title: leanSpec → Lean4 定理証明 命題リスト
last_updated: 2026-05-01
tags:
  - lean4
  - formal-verification
  - propositions
  - safety
  - consensus
---

# leanSpec → Lean4 定理証明 命題リスト

## Context

leanSpec は Lean Ethereum コンセンサスの Python 仕様。
クライアント実装の安全性を担保するため、仕様レベルで成立すべき**命題**を抽出し、Lean4 でこれを定理証明する。

- **目的**: 安全なクライアント仕様の設計
- **方針**: 具体的なケース (関数単位の入出力命題) から始め、徐々に抽象度を上げる
- **本文書の役割**: Lean4 化する命題の優先順位付きカタログ
    - 各命題に「自然言語 + 半形式 (∀/⇒) + Lean4 skeleton」を併記
    - Tier 1/2/3 で実装難易度を区分
    - 対象は 4 領域: Consensus core / SSZ・基本型 / Validator duties / Networking・Sync

## アプローチ

### 命題の抽象度レベル

- **L1 (具体)**: 計算結果の等式。例: `process_slots(s, n).slot = s.slot + n`
- **L2 (中)**: 関数間の関係・不変量保存。例: `process_block` 後 `latest_justified.slot` 単調増加
- **L3 (抽象)**: 系全体の性質。例: fork choice は acyclic、finalization は irreversible

本ドキュメントは **L1 を中心に L2 を一部含む**。L3 は次フェーズで段階的に追加。

### Tier の意味

- **Tier 1 (低難度)**: 1〜2 日で Lean4 化可能。前提なし。最初の足場。
- **Tier 2 (中難度)**: 1 週間規模。Tier 1 の lemma に依存。コア安全性。
- **Tier 3 (高難度)**: 抽象度高、または暗号学的仮定 (collision resistance) を `axiom` として置く必要あり。

### Lean4 skeleton 表記

```lean
-- 命題の Lean4 stub。証明本体は `sorry` で保留。
theorem foo (s : State) : P s := by sorry
```

実コードでは `Std`, `Mathlib` または独自 `LeanSpec.Prelude` への依存になる想定。
SSZ・State・Block 等の型は別ファイル (`LeanSpec.Containers.*`) で別途定義。

## Tier 1: 最初に Lean4 化する命題 (低難度)

### T1-A. SSZ・基本型の round-trip と範囲制約

#### T1-A.1: Boolean encode/decode round-trip

- 出典: `src/lean_spec/types/boolean.py:87-103`
- 自然言語: 任意の真偽値 `b` について、エンコード後にデコードすると元に戻る。
- 半形式: `∀ b : Boolean. decode(encode(b)) = b`
- Lean4:

```lean
theorem boolean_roundtrip (b : Boolean) :
    Boolean.decode (Boolean.encode b) = some b := by sorry
```

#### T1-A.2: Uint64 範囲制約

- 出典: `src/lean_spec/types/uint.py:22-38`
- 自然言語: Uint64 の値は常に `[0, 2^64)` の範囲にある。
- 半形式: `∀ v : Uint64. 0 ≤ v.toNat ∧ v.toNat < 2^64`
- Lean4:

```lean
theorem uint64_range (v : Uint64) :
    v.toNat < 2 ^ 64 := by sorry
```

#### T1-A.3: Uint64 round-trip (8 byte LE)

- 出典: `uint.py:84-126`
- 半形式: `∀ v : Uint64. decode(encode(v)) = some v ∧ |encode(v)| = 8`
- Lean4:

```lean
theorem uint64_roundtrip (v : Uint64) :
    Uint64.decode (Uint64.encode v) = some v := by sorry

theorem uint64_encode_length (v : Uint64) :
    (Uint64.encode v).length = 8 := by sorry
```

#### T1-A.4: Bytes32 固定長

- 出典: `src/lean_spec/types/byte_arrays.py:59-76`
- 半形式: `∀ bs : Bytes32. |bs| = 32 ∧ decode(encode(bs)) = some bs`
- Lean4:

```lean
theorem bytes32_length (bs : Bytes32) : bs.size = 32 := by sorry
```

#### T1-A.5: SSZVector 長さ不変量

- 出典: `src/lean_spec/types/collections.py:137-158`
- 半形式: `∀ T n (v : SSZVector T n). v.data.length = n`
- Lean4:

```lean
theorem sszvector_length {T : Type} {n : Nat} (v : SSZVector T n) :
    v.data.length = n := by sorry
```

#### T1-A.6: get_power_of_two_ceil

- 出典: `src/lean_spec/subspecs/ssz/utils.py:10-14`
- 半形式: `∀ x > 0. let p = ceilPow2 x in p ≥ x ∧ ∃ k. p = 2^k ∧ (k = 0 ∨ 2^(k-1) < x)`
- Lean4:

```lean
theorem ceil_pow2_minimal (x : Nat) (h : 0 < x) :
    x ≤ ceilPow2 x ∧ ∃ k, ceilPow2 x = 2 ^ k ∧
      (k = 0 ∨ 2 ^ (k - 1) < x) := by sorry
```

### T1-B. Slot/Checkpoint の代数的性質

#### T1-B.1: Checkpoint の全順序 (slot ベース)

- 出典: `src/lean_spec/forks/lstar/containers/checkpoint.py`
- 半形式: `∀ c1 c2. c1 < c2 ⇔ c1.slot < c2.slot` (root は tie-break 用ではない)
- Lean4:

```lean
theorem checkpoint_lt_iff_slot_lt (c1 c2 : Checkpoint) :
    c1 < c2 ↔ c1.slot < c2.slot := by sorry
```

#### T1-B.2: is_justifiable_after の 3 条件 disjunction

- 出典: `src/lean_spec/forks/lstar/containers/slot.py`
- 自然言語: target slot が finalized から `δ ≤ 5`、`δ = k²`、`δ = k(k+1)` のいずれかなら justifiable。
- 半形式: `∀ f t. is_justifiable_after f t ⇔ (let δ = t-f in δ ≤ 5 ∨ ∃k. δ = k*k ∨ ∃k. δ = k*(k+1))`
- Lean4:

```lean
theorem justifiable_iff
    (finalized target : Slot) (h : finalized ≤ target) :
    Slot.isJustifiableAfter finalized target ↔
      let δ := target.toNat - finalized.toNat
      δ ≤ 5 ∨ (∃ k, δ = k * k) ∨ (∃ k, δ = k * (k + 1)) := by sorry
```

#### T1-B.3: Round-robin proposer

- 出典: `process_block_header` (`state.py:182-323`)
- 半形式: `∀ slot n. n > 0 ⇒ proposer_index slot n = slot mod n`
- Lean4:

```lean
theorem proposer_index_round_robin (slot : Slot) (n : Nat) (h : 0 < n) :
    ValidatorIndex.proposerFor slot n = ValidatorIndex.mk (slot.toNat % n) := by sorry
```

### T1-C. Validator duties の単純不変量

#### T1-C.1: Dual-key 分離

- 出典: `src/lean_spec/subspecs/validator/service.py:15-29, 376-452`
- 半形式: `∀ vid. proposalKey(vid) ≠ attestationKey(vid)`
- Lean4:

```lean
theorem dual_key_distinct (vid : ValidatorIndex) (reg : KeyRegistry) :
    reg.proposalKey vid ≠ reg.attestationKey vid := by sorry
```

#### T1-C.2: 1 スロット 1 提案者

- 出典: `validator/service.py:223-308`
- 半形式: `∀ slot n. (n > 0 ⇒ ∃! vid < n. isProposer vid slot n)`
- Lean4:

```lean
theorem unique_proposer (slot : Slot) (n : Nat) (h : 0 < n) :
    ∃! vid : Fin n, ValidatorIndex.isProposerFor vid slot := by sorry
```

### T1-D. Networking 境界値

#### T1-D.1: BlocksByRange 応答長上限

- 出典: `src/lean_spec/subspecs/networking/reqresp/handler.py:283-287`
- 半形式: `∀ req resp. handle req = ok resp ⇒ resp.length ≤ min(req.count, MAX_REQUEST_BLOCKS)`
- Lean4:

```lean
theorem blocks_by_range_bounded
    (req : BlocksByRangeRequest) (resp : List Block)
    (h : Handler.handle req = .ok resp) :
    resp.length ≤ min req.count MAX_REQUEST_BLOCKS := by sorry
```

#### T1-D.2: ペイロードサイズ上限

- 出典: `reqresp/codec.py:121-122`
- 半形式: `∀ payload. decode payload = ok _ ⇒ payload.length ≤ MAX_PAYLOAD_SIZE`
- Lean4:

```lean
theorem payload_size_bound (payload : ByteArray) (msg : Message)
    (h : Codec.decode payload = .ok msg) :
    payload.size ≤ MAX_PAYLOAD_SIZE := by sorry
```

## Tier 2: コア不変量 (中難度)

### T2-A. State Transition の単調性

#### T2-A.1: process_slots は slot を target に進める

- 出典: `src/lean_spec/forks/lstar/containers/state/state.py:113-180`
- 半形式: `∀ s target. s.slot ≤ target ⇒ (process_slots s target).slot = target`
- Lean4:

```lean
theorem process_slots_advances (s : State) (target : Slot)
    (h : s.slot ≤ target) :
    (State.processSlots s target).slot = target := by sorry
```

#### T2-A.2: process_block_header は block.slot に揃える

- 出典: `state.py:182-323`
- 半形式: `process_block_header s b = ok s' ⇒ s'.latest_block_header.slot = b.slot`
- Lean4:

```lean
theorem process_block_header_slot
    (s : State) (b : Block) (s' : State)
    (h : State.processBlockHeader s b = .ok s') :
    s'.latestBlockHeader.slot = b.slot := by sorry
```

#### T2-A.3: Checkpoint slot の単調性

- 出典: `state.py` (process 全般)
- 半形式: `∀ s s'. s' = stateTransition s _ ⇒ s'.latest_justified.slot ≥ s.latest_justified.slot ∧ s'.latest_finalized.slot ≥ s.latest_finalized.slot`
- Lean4:

```lean
theorem checkpoint_monotone
    (s s' : State) (b : Block)
    (h : State.transition s b = .ok s') :
    s.latestJustified.slot ≤ s'.latestJustified.slot ∧
    s.latestFinalized.slot ≤ s'.latestFinalized.slot := by sorry
```

#### T2-A.4: justified.slot ≥ finalized.slot 保存

- 半形式: `∀ s. s.latest_justified.slot ≥ s.latest_finalized.slot` が任意の reachable state で成立
- Lean4:

```lean
theorem justified_ge_finalized (s : State) (hreach : Reachable s) :
    s.latestJustified.slot ≥ s.latestFinalized.slot := by sorry
```

### T2-B. Fork choice の決定性と topology

#### T2-B.1: head 選択の決定性 (純関数性)

- 出典: `src/lean_spec/forks/lstar/store.py:639-762`
- 半形式: 同じ store 状態に対し `compute_head` は常に同じ結果を返す。
- Lean4:

```lean
theorem compute_head_deterministic (st : Store) :
    Store.computeHead st = Store.computeHead st := by rfl
-- 実質的には: 純関数として well-formed であることを証明する別 lemma に展開
```

#### T2-B.2: head は latest_justified の子孫

- 半形式: `∀ st. Store.computeHead st = h ⇒ isAncestorOrEqual st h st.latestJustified.root`
- Lean4:

```lean
theorem head_descends_from_justified (st : Store) (h : Bytes32)
    (hh : Store.computeHead st = h) :
    Store.isAncestorOrEqual st st.latestJustified.root h := by sorry
```

#### T2-B.3: Attestation source ≤ target ≤ head

- 出典: `store.py:277-331` (validate_attestation)
- 半形式: `∀ att. validate att = ok ⇒ att.source.slot ≤ att.target.slot ∧ att.target.slot ≤ att.head.slot`
- Lean4:

```lean
theorem attestation_topology
    (st : Store) (att : Attestation)
    (h : Store.validateAttestation st att = .ok) :
    att.data.source.slot ≤ att.data.target.slot ∧
    att.data.target.slot ≤ att.data.head.slot := by sorry
```

### T2-C. Storage 整合性

#### T2-C.1: Block の親存在 (genesis 以外)

- 出典: `src/lean_spec/subspecs/storage/database.py:22-36`
- 半形式: `∀ b ∈ store.blocks. b.parent_root = ZERO_HASH ∨ b.parent_root ∈ store.blocks`
- Lean4:

```lean
theorem parent_exists_or_genesis
    (st : Store) (b : Block)
    (hin : b ∈ st.blocks.values) :
    b.parentRoot = ByteArray.zeroes 32 ∨
    st.blocks.contains b.parentRoot := by sorry
```

#### T2-C.2: バッチ書き込みの原子性

- 出典: `database.py:288-296`
- 半形式: `∀ writes. batch_write writes = ok ⇒ all_persisted writes ∨ none_persisted writes`
- Lean4 (高水準モデル化):

```lean
theorem batch_atomic
    (db db' : Database) (ws : List Write) :
    Database.batchWrite db ws = .ok db' →
    (∀ w ∈ ws, db'.contains w) ∨ db' = db := by sorry
```

### T2-D. Sync 状態機械

#### T2-D.1: 状態遷移の妥当性

- 出典: `src/lean_spec/subspecs/sync/service.py:25-34, 767-786`
- 半形式: `validTransitions = {(IDLE, SYNCING), (SYNCING, SYNCED), (SYNCED, SYNCING), (_, IDLE)}`
- Lean4:

```lean
inductive SyncState | idle | syncing | synced
inductive SyncState.canTransitionTo : SyncState → SyncState → Prop
  | idle_to_syncing : canTransitionTo .idle .syncing
  | syncing_to_synced : canTransitionTo .syncing .synced
  | synced_to_syncing : canTransitionTo .synced .syncing
  | any_to_idle (s) : canTransitionTo s .idle

theorem transition_sound (s s' : SyncState)
    (h : SyncService.transition s = some s') :
    s.canTransitionTo s' := by sorry
```

#### T2-D.2: Gossip 受付条件

- 出典: `sync/service.py:477-487`
- 半形式: `∀ st. acceptsGossip st ⇔ st ∈ {syncing, synced}`
- Lean4:

```lean
theorem accepts_gossip_iff (st : SyncState) :
    SyncService.acceptsGossip st ↔ st = .syncing ∨ st = .synced := by sorry
```

### T2-E. Validator slashing 防止

#### T2-E.1: 二重投票防止 (1 スロットあたり 1 attestation)

- 出典: `validator/service.py:187-209`
- 半形式: `∀ vid slot. attested vid slot ⇒ ¬ produceAttestation vid slot` (ローカル状態で gate)
- Lean4:

```lean
theorem no_double_vote
    (svc svc' : ValidatorService) (vid : ValidatorIndex) (slot : Slot)
    (hin : slot ∈ svc.attestedSlots vid)
    (h : ValidatorService.produceAttestation svc vid slot = .ok svc') :
    False := by sorry
```

#### T2-E.2: XMSS 準備状態の単調性

- 出典: `validator/service.py:454-496`
- 半形式: `∀ sk. let sk' = advance_preparation sk in sk'.preparedEnd > sk.preparedEnd`
- Lean4:

```lean
theorem xmss_advance_monotone (sk : XMSSSecretKey) :
    sk.preparedEnd < (XMSS.advancePreparation sk).preparedEnd := by sorry
```

## Tier 3: 抽象的・安全性 critical (高難度)

### T3-A. Fork choice の global property

#### T3-A.1: Fork choice tree は acyclic

- 半形式: `∀ st. parentRoot 関係は store.blocks 上の DAG (循環なし)`
- Lean4:

```lean
theorem fork_choice_acyclic (st : Store) (hwf : Store.WellFormed st) :
    ∀ b ∈ st.blocks.values, ¬ Store.isProperAncestor st b.root b.root := by sorry
```

#### T3-A.2: Finalization の irreversibility

- 半形式: `∀ s s'. s' = transition s _ ⇒ ¬(s'.latest_finalized.slot < s.latest_finalized.slot)`
- Lean4:

```lean
theorem finalization_irreversible
    (s s' : State) (b : Block)
    (h : State.transition s b = .ok s') :
    s.latestFinalized.slot ≤ s'.latestFinalized.slot := by sorry
```

#### T3-A.3: Fixed-point block building loop の停止性

- 出典: `store.py:1236-1344` (produce_block_with_signatures)
- 半形式: 各反復で `latest_justified.slot` が単調増加または不動 ⇒ 有限ステップで停止
- Lean4: WellFoundedRecursion で表現。難度高。

### T3-B. State transition の決定性

#### T3-B.1: stateTransition は純関数

- 半形式: `∀ s b. transition s b = transition s b` (副作用なし)
- Lean4: 関数定義から自動的に決定的。`@[simp]` 補題として書く。

#### T3-B.2: hash_tree_root の決定性

- 出典: `src/lean_spec/subspecs/ssz/hash.py:34-160`
- 半形式: 純関数性。collision resistance は `axiom`。
- Lean4:

```lean
axiom HashTreeRoot.collisionResistance :
    ∀ x y, hashTreeRoot x = hashTreeRoot y → x = y
-- 注: 厳密な定理ではなく、暗号学的仮定として使う
```

### T3-C. KoalaBear 体公理

#### T3-C.1: Fp は可換環

- 出典: `src/lean_spec/subspecs/koalabear/field.py`
- 半形式: 加法・乗法の結合・可換・分配・単位元・逆元
- Lean4 (Mathlib `CommRing` instance):

```lean
instance : CommRing Fp := { /- 各 op の証明を書く -/ }
```

#### T3-C.2: Fermat の小定理から乗法逆元

- 半形式: `∀ a ≠ 0. a^(P-2) * a = 1 (mod P)`
- 注: Mathlib の `ZMod.pow_card_sub_two_eq_inv` を活用可能。

### T3-D. XMSS sign-verify round-trip

#### T3-D.1: 正しく key_gen された鍵では sign → verify が成功

- 出典: `src/lean_spec/subspecs/xmss/interface.py:224-400`
- 半形式: `∀ pk sk. (pk, sk) = key_gen ⇒ verify pk slot msg (sign sk slot msg) = true` (slot ∈ prepared)
- Lean4:

```lean
theorem xmss_sign_verify
    (pk : XMSSPublicKey) (sk : XMSSSecretKey)
    (slot : Slot) (msg : Bytes32)
    (hkg : XMSS.keyGenSpec pk sk)
    (hslot : slot ∈ sk.preparedRange) :
    XMSS.verify pk slot msg (XMSS.sign sk slot msg) = true := by sorry
```

## 抽象度ロードマップ (具体 → 抽象)

| Phase | 焦点 | 命題例 |
|---|---|---|
| 1 | 純粋計算 (Tier 1) | round-trip, 範囲制約, 境界値 |
| 2 | 関数の事前/事後条件 (Tier 1〜2) | process_slots, validate_attestation |
| 3 | 状態遷移の単調性 (Tier 2) | checkpoint slot 単調, justified ≥ finalized |
| 4 | システム不変量 (Tier 2〜3) | sync FSM, parent existence |
| 5 | グローバル安全性 (Tier 3) | acyclicity, finalization irreversibility |
| 6 | 暗号学的合成 (Tier 3) | XMSS round-trip, hash 仮定 |

各フェーズで命題と Lean4 stub を確定し、次フェーズに進む。

## 想定する Lean4 ファイル構成

実装フェーズで作成する想定の Lean4 ファイル群:

```text
proofs/lean4/
  LeanSpec/
    Prelude.lean                        -- 共通型 (Slot, Checkpoint, ByteArray32 etc)
    SSZ/
      Boolean.lean                      -- T1-A.1
      Uint.lean                         -- T1-A.2, T1-A.3
      Bytes.lean                        -- T1-A.4
      Vector.lean                       -- T1-A.5
      Utils.lean                        -- T1-A.6
    Forks/Lstar/
      Slot.lean                         -- T1-B.2
      Checkpoint.lean                   -- T1-B.1
      ProposerIndex.lean                -- T1-B.3, T1-C.2
      State.lean                        -- T2-A.1〜4
      Store.lean                        -- T2-B.1〜3, T3-A.1〜3
    Validator/
      DualKey.lean                      -- T1-C.1
      Slashing.lean                     -- T2-E.1〜2
    Networking/
      ReqResp.lean                      -- T1-D.1〜2
    Sync/
      FSM.lean                          -- T2-D.1〜2
    Storage/
      Database.lean                     -- T2-C.1〜2
  lakefile.lean                         -- Lake (Lean4 build)
  lean-toolchain                        -- Lean4 version
```

実装は各 stub を `sorry` で開始。Tier 1 から順に `sorry` を解消する。

## 参照する既存コード

Lean4 化する際、Python 側で reference になる関数 (再実装ではなく仕様の対応関係をマッピング):

- `src/lean_spec/types/uint.py:84-126` — `to_bytes(8, 'little')` の Lean4 対応
- `src/lean_spec/types/boolean.py:87-103` — true/false → 0x01/0x00
- `src/lean_spec/types/byte_arrays.py:59-76` — fixed-length 検査
- `src/lean_spec/forks/lstar/containers/slot.py` — `is_justifiable_after` (3 条件 disjunction)
- `src/lean_spec/forks/lstar/containers/state/state.py:113-180` — process_slots
- `src/lean_spec/forks/lstar/store.py:639-762` — LMD-GHOST head selection
- `src/lean_spec/subspecs/networking/reqresp/handler.py:283-287` — BlocksByRange bounds

## Open Questions

- **Mathlib 依存**: Tier 3-C (体公理) は Mathlib 必須。Mathlib を入れるか独自実装か？
- **Python 仕様との対応**: Lean4 側の型定義は Python 側を 1:1 で写すか、抽象化して書き直すか？
- **テスト fixtures との連携**: `tests/consensus/` の JSON fixtures を Lean4 で実行可能 spec として使うか？
- **`axiom` 化の境界**: hash collision resistance, XMSS security はどこまで `axiom` として置くか？
- **抽象化の段階**: 本文書は L1〜L2 中心。L3 (system-level) は次フェーズで切り出す予定。
