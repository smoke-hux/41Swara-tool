# Accuracy Benchmarking

The 41Swara scanner's dominant failure mode is **false-positive drift**: a rule
gets added or loosened, the test suite still passes because no test asserts
"this file should produce *nothing*", and findings on known-good code quietly
multiply until reviewers stop reading the output.

`scripts/benchmark.sh` exists to make that visible. It scans two small vendored
corpora, records per-category finding counts, and compares them against a
committed baseline. A run that produces more noise than the baseline allows —
or that loses a detection it used to have — fails.

It is wired into CI as the `benchmark` job, which gates merges.

---

## The two corpora

Both live under `tests/corpus/` and are checked into the repository. (Note that
`.gitignore` excludes `tests/*` but explicitly re-includes `tests/corpus/` —
without that the harness has nothing to scan in a fresh checkout.)

### `tests/corpus/clean/` — the false-positive corpus

Solidity that is believed **correct**. **Every finding reported on a file in
this directory is a suspected false positive.** The goal is not zero findings
today; it is that the number never grows without someone noticing.

The files deliberately exercise the patterns the scanner is documented to handle
safely, so that a regression in the suppression logic shows up here first:

| File | Pattern under test |
| --- | --- |
| `01_ownable_two_step.sol` | OpenZeppelin `Ownable` / `Ownable2Step` |
| `02_access_control_roles.sol` | Role-based `AccessControl`, `onlyRole`, `grantRole` |
| `03_reentrancy_guard.sol` | `ReentrancyGuard` + checks-effects-interactions |
| `04_safe_erc20.sol` | `SafeERC20` wrapper, `Address.functionCall`, library assembly |
| `05_checked_arithmetic.sol` | Solidity 0.8 checked math, guarded `unchecked` block |
| `06_pull_payment.sol` | Pull-payment withdrawal (no push loop, no DoS surface) |
| `07_twap_oracle.sol` | TWAP + Chainlink with staleness and deviation bounds |
| `08_transfer_2300_gas.sol` | `.transfer` / `.send` — 2300 gas stipend, safe by design |
| `09_view_pure_library.sol` | `pure` math library, `view` accessors, bit shifts |
| `10_interfaces.sol` | Pure interface declarations (no bodies, no bugs possible) |
| `11_pausable_erc20.sol` | Conforming pausable ERC-20 |
| `12_merkle_claim.sol` | Merkle claim using `abi.encode` (not `encodePacked`) |
| `13_timelock.sol` | `block.timestamp` as a coarse multi-day deadline |
| `14_bounded_loop_registry.sol` | Length-validated batch, paginated reads |

### `tests/corpus/vuln/` — the false-negative corpus

Solidity with **unmistakable, classic planted bugs**. A finding that disappears
from here is a false negative and fails the run.

Each file declares what it expects (see the next section). The set covers
reentrancy, missing access control, `tx.origin` auth, on-chain randomness,
unchecked return values, arbitrary `delegatecall`, pre-0.8 overflow, floating
pragma, unbounded loops / push payments, timestamp dependence, spot-price
oracle use, `abi.encodePacked` collisions plus signature replay, an unprotected
initializer, unprotected `selfdestruct` and arbitrary call, and a swap with no
slippage bound.

---

## Expectation format

Every file in `tests/corpus/vuln/` must carry a machine-readable expectation in
its **leading comment block** (the first 15 lines of the file):

```solidity
// SPDX-License-Identifier: MIT
// EXPECT: Reentrancy
// VULN CORPUS CASE — classic single-function reentrancy.
pragma solidity 0.8.24;
```

Rules:

- The marker is `// EXPECT:` followed by one or more category names.
- Several categories go on one line, comma-separated: `// EXPECT: Reentrancy, AccessControl`.
  Repeating the `// EXPECT:` line on several lines also works; all of them are collected.
- The names must match the `VulnerabilityCategory` variants in
  `src/vulnerabilities.rs` **exactly** (they are serialised verbatim into the
  scanner's JSON output). For example the delegatecall category is spelled
  `DelegateCalls`, not `DelegatecallIssues`.
- `// EXPECT:` names the category **the scanner assigns**, which is often more
  specific than the textbook SWC name. `tx.origin` auth lands in `TxOriginAuth`
  rather than `AccessControl`; a dropped return value lands in
  `UncheckedReturnValues` rather than `UnhandledExceptions`; a re-callable
  initializer lands in `DoubleInitialization`. Write the textbook name in the
  prose comment and the scanner's name in the `EXPECT` line.
- The marker is only read from the first 15 lines, so an `EXPECT` appearing
  inside a contract body cannot accidentally become an assertion.
- A vuln-corpus file with **no** `// EXPECT:` line is itself a failure. This is
  intentional: it prevents a case from being added and then silently asserting
  nothing.

The harness checks the expectation **per file**: category `X` declared in
`07_integer_overflow_unchecked.sol` must be reported *on that file*, not merely
somewhere in the corpus.

---

## Running the harness

```bash
# Default: build, scan both corpora, compare against the committed baseline.
scripts/benchmark.sh

# Machine-readable result on stdout (the table goes to stderr).
scripts/benchmark.sh --json

# Reuse an existing release binary instead of rebuilding.
scripts/benchmark.sh --no-build

# Deliberately rewrite the baseline (see "Updating the baseline" below).
scripts/benchmark.sh --update-baseline
```

Full option list: `scripts/benchmark.sh --help`.

| Option | Meaning |
| --- | --- |
| `--update-baseline` | Rewrite `tests/corpus/baseline.json` from this run. |
| `--json` | Emit a result document on stdout; narration goes to stderr. |
| `--with-upstream` | Additionally benchmark pinned upstream libraries. Off by default; advisory only. |
| `--min-severity S` | `info`/`low`/`medium`/`high`/`critical`. Default `low`. Must match the baseline. |
| `--tolerance N` | Allowed increase in **total** clean-corpus findings. Defaults to the baseline's stored value. |
| `--baseline PATH` | Compare against a different baseline file. |
| `--no-build` | Skip `cargo build --release`. |

Exit codes: **0** no regression, **1** regression detected, **2** usage or
setup error.

The harness respects `CARGO_TARGET_DIR`, and runs the scanner from a temporary
working directory so that the auto-saved markdown report does not litter the
repository.

### The `--min-severity` lock

The baseline records the `--min-severity` it was generated at. Running the
comparison at a *different* severity is rejected rather than reported as a
regression, because the two sets of counts simply are not comparable. If you
want to change the severity floor, change it and regenerate the baseline in the
same commit.

---

## Reading the output

```
========================================================================
41Swara accuracy regression report
========================================================================
scanner version : 0.11.0
baseline        : tests/corpus/baseline.json
baseline taken  : 2026-08-30T10:09:27Z
min-severity    : low
clean tolerance : +0 total findings

CLEAN CORPUS  (every finding is a suspected FALSE POSITIVE)   total 55 -> 58
  CATEGORY                  BASE  CURRENT   DELTA
  ----------------------  ------  -------  ------
  AccessControl                3        3       0
  CompilerBug                 13       13       0
  Reentrancy                   3        6      +3 ^
  ...

CLEAN CORPUS -- files whose count changed
  CATEGORY                BASE  CURRENT   DELTA
  --------------------  ------  -------  ------
  03_reentrancy_guard.sol    4        7      +3 ^

REGRESSIONS
  x FALSE POSITIVE DRIFT: clean corpus went from 55 to 58 findings (+3,
    tolerance +0). Every finding on the clean corpus is a suspected false
    positive.

RESULT: FAIL
```

- **CLEAN CORPUS table** — the one that matters most. Any `^` here is new noise
  on code that is believed correct. A `v` is a false-positive fix.
- **VULN CORPUS table** — a `v` here may be a lost detection. Dropping a
  category to zero is always a failure.
- **files whose count changed** — printed only when a clean-corpus file's count
  moved, so you can jump straight to the file that regressed.
- **WARNINGS** — movement that did not breach a threshold. Worth reading; not
  fatal. A clean-corpus *decrease* is reported here as a prompt to lock the
  improvement into the baseline.
- **REGRESSIONS** — the reasons the run failed.

### What makes a run fail

1. **False-positive drift.** Total clean-corpus findings exceed
   `baseline.clean.total + tolerance`.
2. **False negative.** A `// EXPECT:` category is not reported on its own file.
3. **Lost detection.** A category that had a non-zero count on the vuln corpus
   in the baseline now has zero.
4. **Non-comparable options.** The run's `--min-severity` differs from the
   baseline's.

A change in the scanner's own version is a warning, not a failure.

---

## Updating the baseline

**Updating the baseline is a deliberate, reviewed act. It is not a way to
silence a regression.**

If the harness fails, the first question is always *"is the new finding real?"*
Only two answers justify touching `tests/corpus/baseline.json`:

- **The new findings are genuine.** The corpus file really did contain a bug, or
  a legitimately-detectable pattern was added to it. Fix the corpus file if it
  was meant to be clean; if the finding is correct and the file should keep it,
  update the baseline.
- **A false positive was fixed and the count went *down*.** Locking the lower
  number in is exactly the point — otherwise the improvement can silently
  regress later.

The procedure:

```bash
scripts/benchmark.sh --update-baseline
git diff tests/corpus/baseline.json      # read every changed number
```

Then, in the pull request description, state **which category moved, by how
much, and why**. A baseline diff with no explanation should not be approved.

Two guardrails are built in:

- `--update-baseline` **refuses to write** while any `// EXPECT:` in the vuln
  corpus is unmet. You cannot bake a false negative into the baseline.
- The baseline records the scanner version, the timestamp, and the scan options
  it was produced under, so a stale or mismatched baseline is visible in review.

The committed baseline was generated by an actual run of this harness, not
written by hand. Keep it that way.

---

## Adding a new corpus case

### Adding a clean case (a false positive you just fixed)

1. Write a `.sol` file into `tests/corpus/clean/` named `NN_short_name.sol`.
   Keep it small, self-contained (no imports — the corpus has no dependency
   resolution), and deterministic.
2. Open with a comment block naming the pattern under test and stating that
   every finding on the file is a suspected false positive.
3. Run `scripts/benchmark.sh`. It will fail, because the new file adds findings
   over the baseline total — that is expected for a new file.
4. Inspect those findings. If any remain, they are the false positives your
   change is *supposed* to remove; fix the rule first.
5. Regenerate the baseline with `--update-baseline` and explain the delta in
   the PR.

### Adding a vuln case (a detection you want to keep)

1. Write a `.sol` file into `tests/corpus/vuln/` named `NN_short_name.sol`.
2. Add `// EXPECT: <Category>` to the leading comment block, using the exact
   `VulnerabilityCategory` variant name from `src/vulnerabilities.rs`.
3. Comment the vulnerable line itself with `// VULNERABLE:` and one sentence
   explaining the bug, so a reviewer does not have to reverse-engineer intent.
4. Run `scripts/benchmark.sh --update-baseline`. If the scanner does not
   actually detect the bug, the update is refused and you are told which
   category is missing — that is a genuine false negative to fix before the case
   can be committed.

### Choosing the right corpus

If you are unsure whether a pattern is safe: it belongs in the **clean** corpus
only if you would be comfortable telling a user that a finding on it is a bug in
the scanner. Otherwise leave it out. The clean corpus is only useful while every
file in it is genuinely, defensibly correct.

---

## Scanner gaps found while building this corpus

Writing the vuln corpus surfaced real detection gaps. They are recorded here
rather than papered over, and the corpus was written around them so that the
baseline reflects honest current behaviour:

- **Unbounded `>=` pragmas are not detected.** `pragma solidity >=0.4.0;`
  produces no `PragmaIssues` finding, while `^0.7.6` and `^0.8.0` both do.
  `>=` with no upper bound is *strictly worse* than a caret range, so this is
  the more dangerous of the two going unreported.
  `08_floating_pragma.sol` therefore uses `^0.8.0`, which is detected.
- **`block.timestamp` is only flagged when directly compared.** The rule is
  `block\.timestamp\s*[<>=!]+`, so `block.timestamp % 15 == 0` and
  `block.timestamp - lastPlay < 3` slip past it — a modulo of the timestamp is
  a *textbook* manipulation primitive. `10_timestamp_dependence.sol` keeps the
  modulo case (as documentation of the gap) and adds a direct comparison so the
  file has a detectable expectation.
- **A swap that delegates to an external router is not flagged.** The
  `FrontRunning` / `MissingSwapDeadline` rules match on a `swap*` function
  declaration, but the original `15_front_running.sol` — which forwarded to a
  Uniswap-style router with `amountOutMin = 0` and `deadline = block.timestamp`
  — produced neither. The file now performs the swap in-contract so that it is
  detected. The router-forwarding pattern is extremely common in real
  integrations and is worth a rule.

None of these are fixed by this harness; they are candidates for follow-up work
in `src/vulnerabilities.rs`.

---

## Optional: benchmarking against upstream libraries

```bash
scripts/benchmark.sh --with-upstream
```

This clones three widely-audited Solidity libraries at **pinned tags** into a
gitignored `.bench-cache/` and reports their finding counts:

| Repository | Tag | Scanned subdirectory |
| --- | --- | --- |
| `OpenZeppelin/openzeppelin-contracts` | `v5.0.2` | `contracts` |
| `transmissions11/solmate` | `v7` | `src` |
| `Vectorized/solady` | `v0.0.201` | `src` |

These are large, heavily reviewed bodies of code, so a finding on them is
*probably* a false positive — which makes them a good sanity check on absolute
noise levels alongside the small vendored corpus. Observed at v0.11.0,
`--min-severity low`:

| Repository | Findings | Files | Largest category |
| --- | ---: | ---: | --- |
| openzeppelin-contracts v5.0.2 | 257 | 217 | `PragmaIssues` (125) |
| solmate v7 | 82 | 63 | `CallbackReentrancy` (19) |
| solady v0.0.201 | 261 | 54 | `AssemblyUsage` (111) |

Those three headline numbers are worth a look on their own: 125 `PragmaIssues`
on OpenZeppelin is one finding per two files for a library that deliberately
ships caret pragmas, and 111 `AssemblyUsage` findings on solady is one per
half-file for a library whose entire purpose is hand-written assembly.

Important properties of this mode:

- It is **off by default** and is **never run in the default CI path**. CI must
  not depend on a third party's repository being reachable.
- It is **advisory**: the upstream numbers are printed but do not affect the
  exit code.
- It **fails gracefully when offline**. A failed clone prints a clear message
  and the run continues on the vendored corpora.
- The tags are pinned. Bump them deliberately in their own commit — a moving
  target destroys the numbers' value as a regression signal.

`.bench-cache/` is gitignored. Delete it to force a fresh clone.

---

## Files

| Path | Role |
| --- | --- |
| `scripts/benchmark.sh` | Entry point: builds, scans, orchestrates. |
| `scripts/bench_compare.py` | Aggregation, baseline comparison, diff table (stdlib only). |
| `tests/corpus/clean/` | False-positive corpus. |
| `tests/corpus/vuln/` | False-negative corpus, with `// EXPECT:` declarations. |
| `tests/corpus/baseline.json` | Committed baseline, generated by a real run. |
| `.github/workflows/ci.yml` | The `benchmark` job that gates merges. |
