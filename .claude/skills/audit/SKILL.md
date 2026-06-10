---
name: audit
description: Read-only, multi-agent audit of the leanSpec codebase. Fans out the py-architect, consensus-researcher, code-tester, and doc-writer agents across the source tree to find dead code, over-abstraction, stdlib simplifications, test gaps, safety/security defects, and documentation rot, then synthesizes a precise, prioritized AUDIT_REPORT.md. Never modifies code.
---

# /audit — multi-agent codebase audit

Produce a rigorous, evidence-backed audit of leanSpec and write it to `AUDIT_REPORT.md`
at the repository root. This skill **never edits source, tests, or docs** — its only
artifact is the report. Findings become follow-up pull requests.

The bar is the one used for life-critical software: cryptography, spacecraft flight
software (NASA/JPL "Power of Ten", DO-178C), and formally-verified kernels (seL4). A
reference Ethereum specification is read by implementers across the ecosystem; an
ambiguous line or a dead abstraction here propagates into every client. Audit as if a
client bug would trace back to this exact line.

## Hard rules

- **Read-only.** Do not call Edit, Write, or NotebookEdit on anything under `src/`,
  `tests/`, `packages/`, or `docs/`. The only file you create is `AUDIT_REPORT.md`.
- **Evidence or it does not exist.** Every finding cites `file:line` and quotes the
  offending code. No vague "consider improving error handling" entries.
- **Recommend, do not rewrite.** Show the fix as a short illustrative snippet, not a
  finished patch. The report drives PRs; it is not itself a PR.
- **Respect the project laws.** The audit's own standard is `CLAUDE.md` plus
  `.claude/rules/*`. Flag violations of those rules; never recommend anything that breaks
  them (no backward-compat shims, no abbreviations, no `TYPE_CHECKING`, test tree mirrors
  source, forks tested by vectors not pytest, full-equality assertions).

## What counts as a finding

Hunt across these dimensions. Each maps to a lens (and an agent) below.

1. **Dead code** — unused functions, classes, methods, variables, parameters, imports,
   constants, type aliases, or whole modules. The recommendation is always *delete*
   (no deprecation shims — see CLAUDE.md). Confirm with a repo-wide usage search before
   reporting; a symbol used only in tests, re-exported in `__init__.py`, or referenced by
   string is not dead.
2. **Over-abstraction & helper sprawl** — a function/class with exactly one caller, a
   wrapper that only forwards, an indirection the reader must chase. Recommend inlining.
   This is a top priority: helpers tax every future reader.
3. **Stdlib & idiom simplification** — hand-rolled code that a single standard-library
   call replaces (`itertools`, `functools`, `collections`, `bisect`, `math.ceil/floor`,
   `enumerate`, `zip`, comprehensions, `dataclasses`, `Enum`). Quantify the lines saved.
   (Respect repo taste: `math.ceil`/`math.floor` over `(a+b-1)//b` — see project memory.)
4. **Modernization** — Python 3.12 / Pydantic v2 features that read better: `match`,
   `Self`, `@override`, PEP 695 type params, `StrEnum`, frozen models, computed fields,
   field validators. Only where it genuinely clarifies; never churn for fashion.
5. **Refactoring & reorganization** — oversized modules, mixed concerns, misplaced types,
   a class living in the wrong file, inconsistent module shape across siblings.
6. **Test gaps** — uncovered branches, missing boundary/adversarial/error-path cases,
   weak assertions (substring instead of full-equality), over-mocking, and especially
   **test-tree mirroring violations** and any pytest that should be a consensus vector.
7. **Safety & security** — the gravest class. Consensus safety/liveness hazards,
   non-determinism (set/dict iteration order, `Math.random`-style, float in consensus),
   unvalidated external input, integer over/underflow, unbounded allocation from wire
   data, panics on attacker-controlled paths, crypto misuse (non-constant-time compares
   on secrets, nonce reuse, weak domain separation, RFC/test-vector deviations).
8. **Naming & documentation** — abbreviations, vague placeholder names, stale or missing
   docstrings, comments that restate code, missing "why" on a non-obvious constant.

## The lenses (sub-agents)

Launch these four project agents. Each owns a lens but reads the whole tree; the
orchestrator sharded the tree only so the work parallelizes.

- **py-architect** → dimensions 1–5 (dead code, helper sprawl, stdlib, modernization,
  refactoring). It is the simplicity guardian; trust its instinct to inline and delete.
- **consensus-researcher** → dimension 7 (safety & security) plus spec-fidelity of the
  consensus and crypto logic. It reasons about adversaries, finality, and soundness.
- **code-tester** → dimension 6 (test gaps, mirroring, assertion quality, vector vs.
  pytest placement).
- **doc-writer** → dimension 8 (naming clarity, docstring accuracy, comment noise,
  reorganization for comprehension).

## Workflow

1. **Scope.** Read the `/audit` argument:
   - *No argument* → audit the full tree (`src/lean_spec/` and `packages/`).
   - *A path* → audit only that subtree.
   - *A subsystem name* (e.g. `crypto`, `ssz`, `forks`, `networking`, `chain`,
     `packages`) → map it to its directory and audit that.

2. **Shard.** Split the in-scope tree into coherent subsystems so agents run in parallel.
   The natural shards:
   - `src/lean_spec/spec/crypto/` (XMSS, hashing, signatures, aggregation)
   - `src/lean_spec/spec/ssz/`
   - `src/lean_spec/spec/forks/` (state transition, fork choice, containers, validator
     duties, aggregation)
   - `src/lean_spec/node/networking/` (gossipsub, reqresp, quic, discovery)
   - `src/lean_spec/node/chain/` (clock, store, sync) and the rest of `node/`
   - `src/lean_spec/cli/`, `base.py`, `config.py`, `log.py`, `__main__.py`,
     `spec/observability/`
   - `packages/testing/` (the consensus-testing framework)

3. **Fan out.** For each shard, spawn the relevant lenses **in parallel** (one message,
   multiple Agent calls). Give every agent the same contract:
   - It is **read-only**. It produces findings, not edits.
   - It returns findings in the exact schema below — nothing else.
   - It must run a usage search before claiming any symbol is dead.
   - It must read `CLAUDE.md` and `.claude/rules/*` first and judge against them.

   For a large audit, prefer the **Workflow** tool: a `pipeline` of
   (shard × lens) → adversarial verification → synthesis scales better than manual
   fan-out and keeps each finding independently checked. Manual Agent fan-out is fine for
   a single subsystem.

4. **Verify (anti-false-positive pass).** Before a finding lands in the report, confirm
   it. A "dead" symbol must have zero non-test references (`grep`/usage search across
   `src`, `tests`, `packages`, and string-keyed registries). A "simplification" must be
   behavior-preserving — call out any semantic difference (e.g. `itertools` laziness,
   exception types). Discard anything you cannot stand behind. False positives destroy
   the report's credibility faster than missing findings.

5. **Synthesize.** Merge agent outputs, dedupe overlaps, drop unverified items, and write
   `AUDIT_REPORT.md` in the format below. Sort the backlog by severity then effort so the
   top of the list is the obvious first PR.

## Finding schema

Every agent returns findings as a list of records with these fields:

```
ID:           <SHARD>-<NN>            e.g. CRYPTO-03
Location:     path/to/file.py:LINE    (range if multi-line)
Category:     dead-code | over-abstraction | stdlib | modernization |
              refactor | test-gap | safety | security | naming | docs
Severity:     Critical | Major | Minor
Title:        one line, imperative ("Inline single-use `_pad_chunk` helper")
Evidence:     a short quoted snippet of the offending code
Why:          the concrete cost — reader confusion, attack surface, drift risk,
              lines wasted. Tie safety items to a property (safety/liveness/soundness).
Recommendation: the fix, with a minimal before/after snippet. State lines saved.
Effort:       Trivial | Small | Medium | Large
References:   optional — paper, RFC, CPython docs, or a sibling file that does it right
```

Severity rubric:

- **Critical** — can cause consensus divergence, fund loss, a crypto break, a panic on
  attacker-controlled input, or non-determinism in state transition / fork choice.
- **Major** — meaningful correctness, test-coverage, or maintainability risk: a real
  dead-code path, an untested error branch, an abstraction that obscures protocol logic.
- **Minor** — clarity, naming, idiom, single-line simplification.

## Report format (`AUDIT_REPORT.md`)

```markdown
# leanSpec Audit Report

_Scope: <what was audited> · Commit: <git short sha> · Date: <date>_

## Executive summary

3–6 sentences: overall health, the single most important finding, and the themes
(e.g. "helper sprawl in networking", "untested error paths in SSZ decode").

## Findings by severity

A table: ID · Severity · Category · Location · Title. Sorted Critical → Minor.

## Detailed findings

One subsection per finding, rendered from the schema above. Group by subsystem.
Lead with Critical and Major.

## Recommended PR backlog

An ordered checklist mapping findings to PRs, grouped so each line is one shippable
change. Note dependencies ("do X before Y"). This is the section the maintainer acts on.

## Coverage & limitations

What was audited, what was skipped and why, and any finding the auditors could not fully
verify (flagged so a human checks it). No silent gaps.
```

## Quality gates for the report itself

- Lean. No filler, no restating the code, no "it is recommended that". One idea per line.
- Every finding is independently actionable and independently verifiable.
- Concrete over abstract: show the snippet, name the stdlib call, count the lines.
- Honest about uncertainty: a low-confidence finding says so rather than overclaiming.
- The reader should be able to open the report, pick the top item, and start a PR with no
  further investigation.
