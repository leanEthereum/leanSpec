---
paths:
  - "**/*.py"
---

# Documentation Rules (CRITICAL)

These rules govern every docstring and inline comment in the codebase.
They apply equally to production code, helpers, and tests.
Violations should be fixed on sight.

## Hard rules

### 1. Never reference function, method, variable, or type names in doc text

Names change.
Documentation becomes stale.
Use plain English instead.

Bad:
```python
# The shutdown task waits for stop() to be called, then signals all services to terminate.
```

Good:
```python
# A separate task monitors the shutdown signal.
# When triggered, it stops all services.
```

### 2. Never use backticks in comments or docstrings

This is source code, not rendered documentation.
No single backticks, no double backticks.
Write identifiers as plain text or quote literal values with normal double quotes.

Bad:
```python
# The ``GossipAggregatedAttestationStep`` puts payloads into ``latest_new_aggregated_payloads``.
```

Good:
```python
# Gossip aggregated steps place payloads into the "new" pool.
```

### 3. One sentence per line — hard rule

Every docstring, doc comment, and inline comment splits one sentence per line.
Two sentences on one line means the second moves to a new line.
Multi-clause sentences joined by "and", "but", or semicolons split into separate lines.
Short lines expose structural meaning at a glance.

Bad:
```python
# Accepts lists, tuples, or iterables of bool-like values; stored as a tuple after validation.
```

Good:
```python
# Accepts lists, tuples, or iterables of bool-like values.
# Stored as an immutable tuple after validation.
```

### 4. Default to no comments

Add a comment only when the WHY is non-obvious.
Do not restate code.
Do not narrate steps.
If removing the comment would not confuse a future reader, do not write it.

### 5. Preserve existing documentation

Never remove or rewrite a comment or docstring unless the documented behavior actually changed.
Removing valid docs creates diff noise and destroys context.

## Style requirements

### Sentences

- Under 15 words per sentence is the target.
- Active voice, present tense.
- No filler ("This is responsible for...", "This is used to...", "This handles...").
- No marketing tone ("powerful", "seamless", "elegant").

### Structure

- Bullet points for any list of more than two items.
- Numbered steps for sequential operations.
- Blank lines between logical groups inside a comment block.
- Never include code examples in docstrings.
  Unit tests serve as usage examples.

### Constants

Document the WHY behind the value, not just what it is.
Cite the constraint, math, or protocol reference that drives the choice.

Bad:
```python
MAX_VALIDATORS = 4096
"""Maximum number of validators."""
```

Good:
```python
MAX_VALIDATORS = 4096
"""Cap derived from the bitfield budget.
One bit per validator must fit in 512 bytes."""
```

### File-level headers

Single short line unless the module introduces complex math or non-obvious domain context.
Do not pad simple modules with prose that restates the file name.

## Standard doc sections

Use these section headers when a header doc expands past one overview line.
They are the shared vocabulary for navigating doc-heavy code.

- **Overview** — what this item does and why it exists, at a high level.
- **Algorithm** — step-by-step description, only when the math or CS concept is non-obvious.
- **Performance** — complexity, allocation behavior, hot-path notes.
- **Invariants** — preconditions and rules the caller must preserve.
- **Args / Returns / Raises** — Google style, one bullet per item.
- **Why X** — load-bearing rationale that deserves a header instead of being buried in prose.
  Examples: "Why this threshold", "Why we skip the first byte", "Why a delimiter".

## Inline comment patterns

Inline comments must be educative.
A reader new to the domain should understand the invariant and the data flow without looking elsewhere.

### Structured labels

Use these labels inside inline comments where they add clarity:

- `# Why:` — when the reason is not obvious from the code.
- `# Invariant:` — the rule being enforced or relied upon.
- `# Threshold:` — for supermajority or quorum arithmetic.
- `# Timing:` — for interval, slot, or epoch calculations.
- `# Phase N:` — for multi-step algorithms.
- `# Fixture state:` — concrete numbers in tests.

### Concrete values over abstract descriptions

Bad:
```python
# Validate the count.
```

Good:
```python
# Three rounds means three commitments and three openings expected.
```

### ASCII diagrams

When code transforms, packs, or rearranges data, show the before/after layout.
Use them for bit layouts, chain topology, and data flow.

```python
# Layout:
#
#     bits = [1, 0, 1]   ->  byte 0:  0 0 0 0 [1] 1 0 1   (delimiter at bit 3)
#     bits = [1] * 8     ->  byte 1:  0 0 0 0 0 0 0 [1]   (delimiter spills)
```

### Role-labeled flow

When the comment describes prover/verifier, sender/receiver, or producer/consumer interaction, align the roles in a block:

```python
# Aggregation flow:
#
#     proposer  : selects attestations targeting their head.
#     attesters : sign once per slot for the head they observed.
#     network   : gossip with mesh of size 8, slot timeout 6s.
```

The reader sees both roles aligned at a glance instead of parsing prose.

### Comments are glued to code

Every comment sits directly above the line or block it explains.
No floating explanation blocks separated from the code they describe.

## Anti-patterns — never do these

- Multi-clause sentences on one line.
- Function, method, or variable names in doc prose.
- Backticks anywhere in docstrings or comments.
- Filler phrases ("This method is responsible for...", "This is used to...").
- Restating obvious code as comments (e.g. `# increment i` above `i += 1`).
- Documenting code that was not changed in the current task.
- Padding simple module or file headers with prose.
- Describing individual methods inside the class header — each gets its own docstring.
- Banner-style separator comments such as `# =====` or `# -----`.
- Dense prose blocks longer than three contiguous lines — break into bullets or labeled sub-sections.
- Algorithm recap in the docstring when the body already has labeled phase comments.
- Skipping the WHY comment when behavior is non-obvious from code.
