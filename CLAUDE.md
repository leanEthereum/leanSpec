# Working with leanSpec

## Repository Overview

This is a Python repository for the Lean Ethereum Python specifications. It is set up as
a single `uv` project containing the main specifications and various cryptographic
subspecifications that the Lean Ethereum protocol relies on.

## Key Directories

- `src/lean_spec/` - Main specifications for the Lean Ethereum protocol
- `tests/` - Specification tests
- `docs/` - MkDocs documentation source

## Important Notes

- Python 3.12+ required
- Use Pydantic models for validation
- Keep specs simple, readable, and clear
- Repository is `leanSpec` not `lean-spec`
- **Always run linter checks before finishing**: Run `just check` at the end of any code changes to ensure all linting, formatting, type checking, and spell checking passes.
- **Pull requests target the main repo by default**: Unless the user explicitly says otherwise, open pull requests against the upstream main repository (`leanEthereum/leanSpec`, the `upstream` remote, base `main`) — NOT against a personal fork. Push the branch to the fork and open a cross-fork PR with `gh pr create --repo leanEthereum/leanSpec --base main --head <fork-owner>:<branch>`.
- **CRITICAL - NO BACKWARD COMPATIBILITY**: This is a STRICT requirement. NEVER add backward compatibility code under any circumstances. This means:
  - NO legacy constants (like `KEY_TYPE_ED25519 = KeyType.ED25519`)
  - NO wrapper functions that delegate to new classes
  - NO re-exports of deprecated APIs
  - NO deprecation shims or aliases
  - When refactoring from functions to classes, DELETE the old functions entirely
  - Update ALL call sites to use the new API directly
  - Old patterns must be REMOVED, not preserved alongside new ones
- **CRITICAL - NO ABBREVIATIONS IN IDENTIFIERS**: This is a STRICT requirement. Every
  identifier — variables, parameters, function and method names, class names, attributes,
  and constants — must spell words out in full. A reference spec must be as explicit as
  possible; abbreviations make it ambiguous. This applies to source, tests, and the
  `packages/` testing framework.
  - Expand truncated words. Examples:
    - `att` / `att_data` → `attestation` / `attestation_data`
    - `msg` → `message`, `sig` → `signature`, `sk` → `secret_key`, `pk` / `pubkey` → `public_key`
    - `idx` → `index`, `prev` → `previous`, `curr` → `current`, `agg` → `aggregate`
    - `prop` → `proposal`, `conn` → `connection`, `addr` → `address`, `cert` → `certificate`
    - `privkey` → `private_key`, `elem` → `element`, `buf` → `buffer`, `dir` → `directory`
    - `len` → `length` (inside a name, never the `len()` builtin), `fe` → `field_elements`
    - `exc` / `e` → `exception` (in `except X as exc:` clauses, use `exception`; the stdlib
      `exc_info` name is still kept verbatim)
  - Use the correct domain term, not just any expansion: a validator is referenced by its
    INDEX, so `validator_id` → `validator_index` (never `validator_id`).
  - KEEP canonical protocol identifiers that genuinely use "ID": `peer_id`, `node_id`,
    `protocol_id`, `subnet_id`, `stream_id`. The trailing `_id` is fine on these; only expand
    the word part (`msg_id` → `message_id`, but `peer_id` stays).
  - KEEP canonical short field/format names and accepted prefixes: `attnets` and `seq`
    (ENR fields), `pem`, `num`/`num_*` (eth2 number-of style, e.g. `num_validators`), and the
    `reqresp` libp2p protocol name.
  - KEEP universal Python idioms and library/stdlib API names verbatim: `args`, `kwargs`,
    `config`, `model_config`, `tmp_path`, `dest` (argparse), `exc_info`, `__init__`, `__repr__`.
  - NEVER rename external/wire identifiers: third-party library symbols (e.g. functions
    imported from `lean_multisig_py`), protobuf field names, JSON/YAML keys, pydantic aliases,
    or any on-the-wire string. Rename the Python identifier, never the serialized contract.
  - When a fully-expanded name becomes unwieldy, prefer a shorter but still complete phrasing
    (drop redundant words) rather than re-introducing an abbreviation.
- **CRITICAL - DESCRIPTIVE, SELF-DOCUMENTING NAMES**: This is a STRICT requirement, separate from
  the no-abbreviations rule above. Every identifier must let the reader understand what it holds by
  reading it alone, without scanning the surrounding code. A name that is fully spelled out but
  still vague is NOT acceptable. This applies to source, tests, and `packages/`.
  - BAN vague placeholder names that describe nothing: `selected`, `result`, `data`, `value`,
    `item`, `temp`, `obj`, `info`, `payload` (when unqualified), `current`, `entry`, `thing`,
    `out`, `ret`, `expected`, `actual`, `part`/`parts`, single-letter names (except a conventional
    math index `i`/`j` in a tight numeric loop, or notation mirroring a cited formula). Name the
    THING, not its role: `selected` → `selected_proofs`, `result` →
    `post_state` / `merged_signature`, `current` → `current_justified_checkpoint`.
  - `expected` and `actual` must name WHAT is expected: `expected` →
    `expected_public_key_count` / `expected_state_root` / `expected_encoding`; `actual` →
    `actual_field_value`. This applies everywhere, including next to a test assert.
  - `index` alone is banned when what it indexes is not obvious; say what it walks:
    `validator_index`, `aggregate_index`, `byte_index`, `chunk_index`.
  - Never shadow-alias a well-named value into a vague one (`data = attestation_data` is banned);
    use the descriptive name directly, even if lines must wrap.
  - Encode the type or domain meaning when a bare word is ambiguous. A variable holding a
    `Checkpoint` is `justified_checkpoint`, not `justified`; a bitfield of justified slots is
    `justified_slots`, not `slots`; a boolean is a predicate phrase (`found_new_entries`,
    `is_genesis_self_vote`), never a noun.
  - NEVER reuse one vague name for two different things in the same scope. If an inner loop holds
    something different from an outer variable of the same name, rename it (e.g. payload proofs vs.
    grouped signatures → `proofs` and `grouped_signatures`).
  - The bar: a reviewer reading any single line in isolation should know what each name refers to.
    If they would have to scroll up to find out, the name is wrong.
- **CRITICAL - TEST STRUCTURE MIRRORS SOURCE STRUCTURE**: This is a STRICT requirement. The
  test tree under `tests/` mirrors the source tree under `src/lean_spec/` one-to-one.
  A source module `src/lean_spec/<path>/<name>.py` has its unit tests in
  `tests/<path>/test_<name>.py`, and every test file tests the single source module it
  mirrors.
  - When you MOVE a class or function to a different module, MOVE its tests to the matching test
    module in the SAME change. Never leave tests behind in the old location.
  - When you CREATE a new source module, its tests go in the mirrored test path, not appended to
    an unrelated test file.
  - When you DELETE or RENAME a source module, delete or rename its test module to match.
  - A test file must never test a type that lives in a different source module. For example, tests
    for `SlotClock` (in `node/chain/clock.py`) belong in `tests/node/chain/test_clock.py`,
    never in an unrelated test module.
  - This mirroring covers non-fork modules only (`node/`, `spec/crypto/`, `spec/ssz/`, etc.). The
    fork specs under `src/lean_spec/spec/forks/` are exempt — see the forks-are-vectors rule below.
- **CRITICAL - FORKS ARE TESTED BY VECTORS, NOT PYTESTS**: This is a STRICT requirement. The fork
  specs under `src/lean_spec/spec/forks/` are tested exclusively through consensus test vectors
  under `tests/consensus/` (generated with `uv run fill`), never through pytest unit tests.
  - There is NO `tests/spec/forks/` tree, and you must never create one.
  - When you add or change any fork behavior — fork choice, state transition, block production,
    validator duties, aggregation, the containers, slot/interval math, the fork registry or
    protocol — add or update a consensus test-vector fixture, not a pytest.
  - Write these with the `state_transition`, `fork_choice`, `ssz`, `slot_clock`, `verify_signatures`,
    and related fixtures in `packages/testing/src/consensus_testing/`.
- **CRITICAL - ASSERT THE COMPLETE ERROR MESSAGE**: This is a STRICT requirement. When a test
  checks a raised exception, assert the FULL message with string equality, never a substring or
  partial regex. A partial match lets the rest of the message drift or regress unnoticed.
  - Use `with pytest.raises(SomeError) as exception_info:` then
    `assert str(exception_info.value) == "the entire expected message"`.
  - Do NOT use `pytest.raises(SomeError, match="fragment")` to assert a fragment. If you use
    `match=`, it must anchor the whole message (`match=r"^...full message...$"` with regex
    metacharacters escaped); prefer the explicit full-equality assertion above.
  - This mirrors the full-equality rule for ordinary assertions: assert the whole object, never a
    piece of it.
- **CRITICAL - KEEP TEST DOCUMENTATION IN SYNC WITH THE TEST**: This is a STRICT requirement. Every
  time you change a test, update the documentation that describes it in the SAME change, following
  the documentation rules (`.claude/rules/documentation.md`, and for `tests/consensus/` the
  Given/When/Then standard in that file). A test's docstring is part of the test; a change that
  leaves the docstring describing the old behavior is incomplete.
  - When you add, remove, or change a step, assertion, or expected value, reconcile the docstring so
    it still describes exactly what the test does.
  - For `tests/consensus/` vectors, the step assertions and the Given/When/Then docstring must stay
    one-to-one: if an assertion changes, the matching docstring line changes with it.
  - Do not weaken a docstring into vagueness to avoid updating it; describe the new behavior
    precisely, as the doc-writer rules require.
