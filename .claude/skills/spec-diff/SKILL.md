---
name: spec-diff
description: Show what changed in leanSpec between devnet versions or HEAD
---

# /spec-diff - Spec Changelog Between Versions

Show what changed in the **spec code** (`src/lean_spec/`) and **consensus test vectors**
(`tests/consensus/`) between two devnet versions (or HEAD).

**Scope**: Protocol-level spec types, functions, containers, forkchoice logic, and the
test fixtures that generate cross-client test vectors.

**Excluded**: Test framework infrastructure (`packages/testing/`, `consensus_testing/`,
`execution_testing/`), unit tests (`tests/lean_spec/`), interop tests (`tests/interop/`),
documentation (`docs/`), CI/tooling configs, and the node implementation layer
(networking, sync, storage, node runner).

## Usage

- `/spec-diff devnet3` - Changes from devnet 3 to HEAD
- `/spec-diff devnet2 devnet3` - Changes from devnet 2 to devnet 3
- `/spec-diff devnet0 devnet3` - Full changelog across multiple devnets

## Steps

### 1. Resolve version commits

Look up commit hashes from `VERSIONS.md` in the repo root. It contains a table mapping
version names (e.g. "Devnet 3") to commit hashes.

Parse the argument(s):
- If one argument: compare that version → HEAD
- If two arguments: compare first → second
- Match case-insensitively and flexibly (e.g. `devnet3`, `Devnet 3`, `d3` should all resolve to the same entry)

If a version is not found in VERSIONS.md, report the available versions and abort.

### 2. Get changed files

Run both commands:
```bash
git diff --name-only <from-commit> <to-commit> -- src/lean_spec/
git diff --name-only <from-commit> <to-commit> -- tests/consensus/
```

Filter to `.py` files only.

### 3. Analyze spec changes

For each changed spec file (`src/lean_spec/`), run:
```bash
git diff <from-commit> <to-commit> -- <file>
```

Categorize each item as:
- **New** - functions/types/modules that didn't exist in the from-version
- **Modified** - functions/types whose signature or body changed (includes renames)
- **Removed** - functions/types that were deleted

For modified items, briefly describe what changed (e.g. "added `deadline` parameter",
"changed return type from `bool` to `Optional[bool]`").

**Detecting renames**: A rename+change appears in the diff as a removal in one place and
an addition in another. Before classifying something as `[Removed]` + `[New]`, check
whether the removed item has a corresponding new item with a similar name, similar
parameters, or similar objective. If so, report it as a single `[Modified]` entry:
`old_name()` → renamed to `new_name()`, with a description of what else changed.
Common rename patterns: prefix/suffix changes (`gossip_` → `attestation_`), class
extraction (`function` → `Class.method`), split (`one_func` → `two_funcs`).

### 4. Analyze test vector changes

For each changed consensus test file (`tests/consensus/`), run:
```bash
git diff <from-commit> <to-commit> -- <file>
```

Summarize changes to test vectors grouped by test category (fork choice, SSZ, signature
verification, etc.). Focus on:
- New test cases added
- Tests whose scenarios changed (e.g. "blocks now carry explicit attestations instead of
  relying on auto-collection")
- Tests removed
- Behavioral changes in what's being tested (e.g. "fork weight now based on attestations
  not block count")

### 5. Output report

Group changes by **component** (logical area of the spec), not by file path.
Within each component, prefix each item with `[New]`, `[Modified]`, or `[Removed]`.

After the spec component sections, include a **Test Vectors** section covering
changes to consensus test fixtures (`tests/consensus/`).

```markdown
## Spec changes: Devnet 3 → HEAD

### Block Envelope

- [New] `SignedBlock` — replaces `SignedBlockWithAttestation`
- [Removed] `BlockWithAttestation` — no longer needed

### State Transition

- [Modified] `State` — added `deposit_index` field (Uint64)

### Test Vectors

**Fork Choice** (5 files, +770 -407 lines)
- [Modified] Tests now use explicit attestations — weight from attestations not block count
- [Removed] `test_auto_collect_proposer_attestations` — auto-collection removed

**SSZ Containers** (2 files)
- [Modified] `Validator` tests — dual pubkeys

### Summary
- X spec files, Z test files changed
- Brief description of core design changes
```

Guidelines:
- Group spec changes by logical component (e.g. "Block Envelope", "Validator Model",
  "Aggregation", "Forkchoice Store"), not by file path.
- Each item is a bullet prefixed with `[New]`, `[Modified]`, or `[Removed]`.
- The Test Vectors section groups by test category (fork choice, SSZ, signature
  verification, state transition, etc.) with file counts and line stats.
- Keep descriptions concise. The goal is to give implementation teams a clear picture of
  what they need to update, not a line-by-line diff.
- End with a Summary section highlighting core design changes.
