# Contributing

This repository treats **design taste as an enforceable constraint**, not a vibe. We optimize for:

- **Compositional design** (small parts that snap together cleanly)
- **Local reasoning** (you can understand a change without loading the whole system into your head)
- **Information hiding** (interfaces are stable; implementation details are private)
- **Minimal incidental complexity** (state, control, and configuration don't leak everywhere)
- **Readability as a feature** (obvious code beats clever code)
- **Correctness by construction** (derive from a spec; encode invariants; test laws)

If you want a mental model: changes should read like a "functional pearl" even if the language is not functional.

---

## Contents

- [Repository structure](#repository-structure)
- [What changes we accept](#what-changes-we-accept)
- [Non-negotiables](#non-negotiables)
- [Design rules](#design-rules)
- [Code organization](#code-organization)
- [Style and readability](#style-and-readability)
- [Testing and correctness](#testing-and-correctness)
- [Performance and complexity](#performance-and-complexity)
- [Documentation requirements](#documentation-requirements)
- [Change workflow](#change-workflow)
- [Commit and PR standards](#commit-and-pr-standards)
- [Review standards](#review-standards)
- [Security](#security)
- [Taste canon](#taste-canon)

---

## Repository structure

### Layout

```
crates/
  common/                  # Shared types, errors, utilities (krusty-kms-common)
  crypto/                  # Cryptographic primitives and proofs (krusty-kms-crypto)
  kms/                     # Key management and derivation (krusty-kms)
  sdk/                     # Confidential transaction SDK (krusty-kms-sdk)
  client/                  # Starknet RPC client (krusty-kms-client)
  wasm/                    # WASM bindings (krusty-kms-wasm)
  ffi/                     # C ABI shared library (krusty-kms-cabi)
  experimental/            # Non-default crates/packages
    gaming-experimental/
```

Rules:
- `crates/{common,crypto,kms,sdk,client}` is the stable production dependency chain.
- `crates/wasm` contains WASM bindings; `crates/ffi` provides the C ABI.
- `crates/experimental/*` is intentionally non-default and can evolve faster.

### Conventions

- **Module declarations**: Keep public exports centralized in each crate's `src/lib.rs`; keep helper modules private by default.
- **Test structure**: Unit tests live next to modules in `src/*`; integration tests live in `<crate>/tests/*.rs`; benches live in `<crate>/benches/*.rs`.
- **Naming**: Rust conventions apply: `snake_case` for modules/functions/variables, `PascalCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.

---

## What changes we accept

We gladly accept contributions that:

- Reduce complexity (fewer concepts, fewer edge cases, fewer moving parts).
- Improve clarity (better names, better factoring, better docs).
- Strengthen module boundaries (less leakage of representation/policy).
- Add features **without** expanding the public surface unnecessarily.
- Improve tests by expressing **properties/laws**, not just examples.
- Replace "control-heavy" code with **data transformations** where sensible.

We are skeptical of contributions that:

- Add new global state, implicit coupling, or "action at a distance."
- Add large dependencies without clear payoff.
- Expose new public APIs without strong motivation and well-defined laws.
- Introduce cleverness that can't be explained succinctly.

---

## Non-negotiables

A PR will be blocked (or asked to be split/reworked) if it violates any of these:

1. **Every change must have a stated purpose**: a bug, a feature, a refactor with a measurable simplification, or a doc/test improvement.
2. **Public API changes require a design note** (see [Design rules](#design-rules)).
3. **No complexity leaks**: internal details (representation, storage, concurrency, caching, policy choices) must not become user-facing.
4. **No "spooky action"**: avoid hidden side effects, implicit singletons, implicit runtime configuration, or untracked global mutations.
5. **No drive-by reformatting**: keep diffs focused. If formatting is needed, isolate it in its own commit or PR.
6. **Tests are required** for:
   - Bug fixes (regression test)
   - New behavior (new tests)
   - New abstractions (laws / properties where applicable)
7. **Small PRs by default** (see size limits below). Large PRs require an explicit justification and a plan.

---

## Design rules

### 1) Start with a spec, not an implementation

Before writing code, write down:

- **What is the input/output behavior?**
- **What invariants must always hold?**
- **What is the smallest interface that solves the problem?**
- **What are the failure modes?** (and how they are represented)

For non-trivial changes, include this in a short design note:

- `docs/design/<YYYY-MM-DD>-<slug>.md` (preferred), or
- a clearly labeled "Design" section in the PR description.

Design notes should be short and sharp: 1–2 pages max. If it's longer, split it.

### 2) Derive and simplify ("design by calculation")

Treat refactors as algebra:

- Prefer stepwise transformations where each step preserves meaning.
- If you can rewrite a function into a simpler equivalent, do it.
- When changing logic, **preserve semantics explicitly** (tests, properties, or reasoning notes).

If a section of logic is subtle, add a brief comment explaining the transformation:
- **Explain why**, not what.
- Prefer tiny, checkable statements over prose.

### 3) Prefer parametric designs (avoid clever, type-dependent behavior)

If you expose generic APIs (generics/templates/traits/interfaces):

- Keep them **parametric**: avoid reflection, runtime type inspection, "if T is X then…", and unsafe casting.
- Don't smuggle policy through ad-hoc conventions.
- Document any required laws (see next rule).

Rule of thumb: if your function works for "any type," it should not depend on secrets about the type.

### 4) Every abstraction needs laws (and ideally tests)

If you introduce an abstraction (interface/class/module) that others will build on, document:

- **Laws / invariants** (identities, associativity, monotonicity, idempotence, etc.)
- **What is deliberately not promised** (important!)

Then add tests that check those laws where practical.

If the language doesn't support property testing easily, simulate it with:
- table-driven tests
- randomized tests with fixed seeds
- carefully chosen edge cases

### 5) Composition beats configuration

Prefer:
- small, orthogonal functions/modules
- explicit dependency passing
- composition/pipelines

Avoid:
- sprawling configuration objects
- "do-everything" managers
- magic behavior controlled by flags sprinkled across the codebase

If a feature needs many flags, that's often a sign the design is mixing concerns.

### 6) Isolate effects at the boundary

Even in imperative languages:

- Keep "core logic" as pure as possible (deterministic functions with explicit inputs/outputs).
- Push I/O (network, file system, DB, clock, randomness) to thin boundary layers.
- Make dependencies explicit (constructor injection, parameters, passed-in clients).

The goal is to make most code testable without mocks and reasoned about like math.

### 7) State is a liability: pay for it twice

State creates:
- more edge cases
- harder tests
- harder refactors
- more "who changed this?" debugging

Rules:
- Prefer immutability/persistent structures where reasonable.
- Avoid shared mutable state.
- If state is required, localize it and guard it with clear invariants.

Control flow (callbacks, async chains, complex branching) is also a form of complexity—simplify it like you would simplify state.

---

## Code organization

### Module boundaries (information hiding)

- Modules should hide:
  - representation choices
  - algorithms and data structures
  - caching strategies
  - concurrency strategies
  - storage details
  - policy decisions likely to change

Expose only what callers need.

**If a caller can depend on it, it will be depended on.** Treat every exported symbol as a long-term commitment.

### Deep modules over shallow wrappers

Prefer a module that:
- has a **small, simple interface**, and
- contains meaningful internal complexity

over a module that:
- re-exports everything
- adds a new layer without hiding complexity

### File and change size limits (strict)

These are defaults. If you exceed them, explain why in the PR description.

- **PR size**: aim for ≤ **400 changed lines** and ≤ **10 files**.
  - If larger: split into logical PRs (prep refactor → feature → cleanup).
- **Source files**: aim for ≤ **350 lines** per file.
  - Hard stop at **500 lines** unless there's a strong reason.
- **Functions**: aim for ≤ **40 lines**.
- **Classes / types**: aim for ≤ **200 lines** of definition logic.
- **Nesting**: avoid > **3** nested blocks/closures; refactor instead.

If you must exceed a limit, add one of:
- a module-level comment: `// NOTE: intentionally long because ...`
- a short section in the PR: "Why this file is long"

---

## Style and readability

Readability is not "nice to have." It is a correctness tool.

### Names

- Use precise nouns for data and verbs for actions.
- Prefer domain names over implementation names.
- Avoid abbreviations unless they're universally recognized in this codebase.

### Comments

- Comment **why**, not what.
- If code needs a comment to be understood, consider rewriting it first.
- When a trick is necessary, document:
  - the invariant it relies on
  - the failure mode if violated

### Error messages and diagnostics

- Errors should include:
  - what failed
  - relevant identifiers/inputs (non-sensitive)
  - how to recover (when helpful)

Avoid leaking secrets in logs or error messages.

### "No cleverness" rule

If a reviewer can't explain the code back after one read, it's not done.
Prefer the obvious solution unless there is a measured reason not to.

---

## Testing and correctness

### Minimum expectations

- Bug fix → regression test.
- Feature → tests for:
  - the happy path
  - edge cases
  - failure modes
- New abstraction → laws/properties tested where feasible.

### Determinism

Tests must be:
- deterministic
- fast enough to run locally and in CI
- independent of network and external services unless explicitly marked/integration-only

If randomness is used, seed it and log the seed on failure.

### Invariants as first-class citizens

Encode invariants in the strongest available form:
- types (wrappers, enums/sum types, non-nullable types)
- constructors that validate
- internal assertions for "impossible" states (not for user errors)

---

## Performance and complexity

Performance work is welcome when:

- it's measured (before/after)
- it doesn't compromise clarity
- it doesn't leak complexity into the API

Rules of thumb:

- Prefer algorithmic improvements over micro-optimizations.
- Don't add caching without:
  - invalidation strategy
  - memory bounds
  - a clear interface boundary

Complexity is a cost. If a change speeds things up but makes the system harder to reason about, it needs a strong justification.

---

## Documentation requirements

If your PR changes behavior, update docs accordingly:

- public API docs
- READMEs and examples
- changelog/release notes (if the repo uses one)

Docs should be:

- short
- concrete
- example-driven

Prefer "show one good example" over "explain every possibility."

---

## Change workflow

1. **Set up git hooks** (once per clone):
   ```bash
   git config core.hooksPath .githooks
   ```
   This enables the pre-commit hook that checks Rust formatting (via `cargo fmt --check`) and will abort the commit if formatting is incorrect so you can run `cargo fmt` and re-stage changes.
2. **Pick an issue** (or open one).
3. For non-trivial changes, write a **design note** before coding.
4. Implement in small steps:
   - keep commits coherent
   - keep code compiling / tests passing
5. Run the full check suite locally (format/lint/tests).
6. Open a PR early if you want feedback; mark it as draft.

**Non-trivial** includes:
- new public API
- new dependency
- new module or architectural change
- changes that touch multiple layers (API → core → storage)
- concurrency/async behavior changes

---

## Commit and PR standards

### Commits

- Use imperative mood: "Fix…", "Add…", "Refactor…"
- One concept per commit when possible.
- Don't mix refactors and behavior changes in the same commit unless unavoidable.

### PR description must include

- **What** changed (1–3 bullets)
- **Why** it changed (the real motivation)
- **How to review** (where to focus)
- **Tests** added/updated
- **Risks** and how they're mitigated
- Link to design note (if applicable)

### PR checklist (author)

- [ ] I can explain the change in one paragraph without hand-waving.
- [ ] Public APIs are minimal and come with documented laws/invariants.
- [ ] Complexity did not leak across module boundaries.
- [ ] Side effects are isolated at the boundary (or explicitly justified).
- [ ] File/function size limits are respected (or justified).
- [ ] Tests cover behavior + edge cases (and properties where applicable).
- [ ] Docs are updated (if behavior changed).
- [ ] Diffs are focused; no unrelated formatting churn.

---

## Review standards

Review is not just "does it work?" It is "does it *belong*?"

Reviewers will look for:

1. **Boundary quality**
   - Are modules decomposed by information hiding?
   - Does the interface reveal unnecessary policy/representation?

2. **Compositionality**
   - Can the new parts be combined cleanly with existing parts?
   - Are there sharp edges or special cases?

3. **Complexity control**
   - Did the PR add new concepts? If yes, did it remove more than it added?
   - Is state minimized and localized?

4. **Correctness**
   - Are invariants clear and enforced?
   - Are failure modes explicit?

5. **Readability**
   - Is the code obvious?
   - Is naming crisp and consistent?
   - Are comments explaining "why"?

If a reviewer asks for a simplification pass, treat it as part of "done," not as optional polish.

---

## Security

If you believe you've found a security vulnerability, do **not** open a public issue.
Instead, follow the repository's security policy (e.g., `SECURITY.md`) if present.
If none exists, contact the maintainers privately via the channel listed in the README.

---

## Taste canon

This repo's contribution bar is shaped by a particular view of software "beauty":

**Functional program aesthetics**
- "Functional Pearls" (small, compositional, enlightening programs)
- Richard Bird (design by calculation; equational reasoning)
- Philip Wadler ("Theorems for free!"; parametricity as constraint)
- John Hughes (FP as modularity through composition)

**Language-agnostic design taste**
- Parnas (information hiding; module boundaries)
- Ousterhout (complexity is the enemy; deep modules)
- Moseley & Marks (state/control as sources of incidental complexity)
- Lampson (interface/design judgment heuristics)
- Boswell & Foucher (code should be obvious; readability as craft)

You do not need to have read these to contribute—but you do need to write changes that respect the constraints they imply.

---
