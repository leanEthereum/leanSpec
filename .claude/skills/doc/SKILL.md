---
name: doc
description: Document code in this repository.
---

# /doc — document code

Write or refine documentation for leanSpec code.
The atomic style rules live in `.claude/rules/documentation.md` — defer to that file.
This skill defines what to document, how to scope the work, and shows a gold-standard exemplar.

## Scope

Determine what to document from the argument passed to `/doc`:

1. **No argument** — document only new or modified code.
   Run `git diff` and `git diff --cached` to identify scope.
   Do not touch unchanged code.
2. **File or folder path** — document everything inside that path recursively.
3. **Module, class, or function name** — locate the item in the codebase, then document it and everything inside it.

When an argument is provided, document the target fully — not just uncommitted changes.
The argument overrides the diff-only restriction.

## What to document

- **Module-level docstrings** — single short line unless the module introduces complex math or non-obvious domain context.
- **All public items** — classes, methods, functions, constants, type aliases, module-level Pydantic fields.
- **Constants** — explain the WHY behind the value, with the constraint or protocol reference that drives the choice.
- **Inline comments** — add them only where the WHY is non-obvious.
  Do not paper every line.

## Standard sections — use these names

When a header doc grows past one overview line, organize the detail under these section names:

- **Overview** — what and why at a high level.
- **Algorithm** — step-by-step, only for genuinely non-obvious math or CS concepts.
- **Performance** — complexity, allocation, hot-path notes.
- **Invariants** — preconditions and rules the caller must preserve.
- **Why X** — load-bearing rationale that deserves a header instead of buried prose.
- **Args / Returns / Raises** — Google style, bullets.

## Workflow

1. Read the implementation carefully before writing a single line of documentation.
2. Identify the educational angle.
   What does a reader new to Ethereum consensus need to know?
3. Write the header tightly.
   Use the standard section vocabulary when overview alone is not enough.
4. Add inline WHY comments.
   Glue each comment to the code it explains.
5. Re-read as a learner.
   If a fresh reader would stall, add one more comment — and only one.

## Test-specific format

Test docstrings stay short.
A one-line summary is usually enough.
Education goes inline in structured blocks:

```
Invariant: <rule the test enforces>

Fixture state: <concrete numbers>

Mutation: <what we change and why>

    <ASCII diagram of before/after>
```

Never write essay-style prose blocks in test docstrings.

## Project-specific anti-patterns

These are the failure modes most likely to slip into leanSpec PRs:

- **Backticks in docstrings or comments.**
  Banned everywhere — single or double backticks alike.
  See `.claude/rules/documentation.md` rule 2.
- **Function names in prose.**
  Names rot.
  Describe behavior in plain English.
- **Module docstring listing every class inside.**
  The module name and public exports describe the module.
  Do not pad with a class roster.
- **Algorithm recap in both docstring and inline comments.**
  Pick one.
  Default: phase-labeled inline comments in the body, short overview in the header.
- **Backward-compatibility justifications.**
  The project mandates no backward compatibility.
  Do not write docs that pretend a deprecated path still exists.
- **Documenting code outside the requested scope.**
  Respect the scope rules above.

## Gold-standard exemplar

The target style for a well-documented Python function in this project.
Note the tight one-sentence-per-line header, the structured WHY section, the phase-labeled body, and the ASCII layout diagram.

```python
def encode_bitlist(bits: Sequence[Boolean]) -> bytes:
    """
    Encode a variable-length bitlist to SSZ bytes.

    # Overview

    Data bits are packed little-endian within each byte.
    A single 1 bit is placed immediately after the last data bit.
    The trailing bit lets the decoder recover the original count.

    # Why a delimiter

    SSZ encodes bitlists as raw bytes with no length prefix.
    Without a marker, [1, 0] and [1, 0, 0, 0, 0, 0, 0, 0] would share the byte 0x01.
    A trailing 1 bit is the smallest sentinel that disambiguates them.

    # Layout

        bits = [1, 0, 1]   ->  byte 0:  0 0 0 0 [1] 1 0 1   (delimiter at bit 3)
        bits = [1] * 8     ->  byte 0:  1 1 1 1 1 1 1 1
                               byte 1:  0 0 0 0 0 0 0 [1]   (delimiter spills)

    Args:
        bits: The variable-length bit data.

    Returns:
        SSZ-encoded bytes containing the data bits and the delimiter.
    """
    # Phase 1: handle the empty case.
    #
    # No data bits means the encoding is just the delimiter.
    num_bits = len(bits)
    if num_bits == 0:
        return b"\x01"

    # Phase 2: pack data bits little-endian into a byte array.
    #
    # Bit i of the input lands in byte i // 8 at position i % 8.
    byte_len = (num_bits + 7) // 8
    byte_array = bytearray(byte_len)
    for i, bit in enumerate(bits):
        if bit:
            byte_array[i // 8] |= 1 << (i % 8)

    # Phase 3: place the delimiter immediately after the last data bit.
    #
    # When the bit count is a multiple of 8, the delimiter has no room
    # in the existing array and spills into a fresh trailing byte.
    if num_bits % 8 == 0:
        return bytes(byte_array) + b"\x01"
    byte_array[num_bits // 8] |= 1 << (num_bits % 8)
    return bytes(byte_array)
```

Match this density of structure, brevity of lines, and use of concrete numbers and diagrams.

## Workflow checklist

Before finishing a documentation pass, verify:

- Every sentence is on its own line.
- No backticks anywhere.
- No function or variable names referenced in prose.
- All non-obvious WHYs are documented.
- No banner-style separator comments.
- No documentation added to code that was not in scope.
- Standard section names used where headers expand past one line.
