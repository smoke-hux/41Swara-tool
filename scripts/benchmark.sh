#!/usr/bin/env bash
#
# 41Swara scanner -- accuracy regression harness.
#
# The scanner's dominant failure mode is false-positive drift: a rule gets added
# or loosened, and nobody notices that findings on known-clean code exploded.
# This harness pins that down by scanning two vendored corpora and comparing the
# per-category finding counts against a committed baseline.
#
#   tests/corpus/clean/  code believed correct -> every finding is a suspected
#                        FALSE POSITIVE, so the total must not grow.
#   tests/corpus/vuln/   code with planted bugs, each file declaring its
#                        expectation as `// EXPECT: <Category>` -> a missing
#                        finding is a FALSE NEGATIVE.
#
# Usage:
#   scripts/benchmark.sh                    compare against tests/corpus/baseline.json
#   scripts/benchmark.sh --json             machine-readable result on stdout
#   scripts/benchmark.sh --update-baseline  deliberately rewrite the baseline
#   scripts/benchmark.sh --with-upstream    also benchmark pinned upstream repos
#   scripts/benchmark.sh --help             full option list
#
# Exit codes: 0 = no regression, 1 = regression, 2 = usage/setup error.
#
# See docs/BENCHMARKING.md for the full story.

set -euo pipefail

# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

CORPUS_DIR="${REPO_ROOT}/tests/corpus"
CLEAN_DIR="${CORPUS_DIR}/clean"
VULN_DIR="${CORPUS_DIR}/vuln"
BASELINE="${CORPUS_DIR}/baseline.json"
CACHE_DIR="${REPO_ROOT}/.bench-cache"
COMPARE="${SCRIPT_DIR}/bench_compare.py"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

UPDATE_BASELINE=0
JSON_OUTPUT=0
WITH_UPSTREAM=0
SKIP_BUILD=0
MIN_SEVERITY="low"
TOLERANCE=""

usage() {
    sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's|^# \{0,1\}||'
    cat <<'EOF'

Options:
  --update-baseline   Rewrite tests/corpus/baseline.json from this run. This is a
                      deliberate, reviewed act -- it is NOT a way to silence a
                      regression. Refuses to write while any `// EXPECT:` in the
                      vuln corpus is unmet.
  --json              Emit a machine-readable result document on stdout; the
                      human-readable table goes to stderr.
  --with-upstream     Additionally clone pinned upstream libraries into
                      .bench-cache/ and report their finding counts. OFF by
                      default, never run in the default CI path, requires
                      network. Advisory only: it does not affect the exit code.
  --min-severity S    info|low|medium|high|critical (default: low). Must match
                      the value recorded in the baseline, or the run is rejected
                      as non-comparable.
  --tolerance N       Allowed increase in TOTAL clean-corpus findings before the
                      run fails. Defaults to the value stored in the baseline.
  --baseline PATH     Use a different baseline file.
  --no-build          Reuse an already-built release binary.
  -h, --help          This message.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update-baseline) UPDATE_BASELINE=1; shift ;;
        --json)            JSON_OUTPUT=1; shift ;;
        --with-upstream)   WITH_UPSTREAM=1; shift ;;
        --no-build)        SKIP_BUILD=1; shift ;;
        --min-severity)    MIN_SEVERITY="${2:?--min-severity needs a value}"; shift 2 ;;
        --tolerance)       TOLERANCE="${2:?--tolerance needs a value}"; shift 2 ;;
        --baseline)        BASELINE="${2:?--baseline needs a value}"; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 usage >&2; die "unknown argument: $1" ;;
    esac
done

# Narration must not pollute stdout when --json is in play.
if [[ ${JSON_OUTPUT} -eq 1 ]]; then
    exec 3>&2
else
    exec 3>&1
fi
log() { printf '%s\n' "$*" >&3; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

command -v python3 >/dev/null 2>&1 || die "python3 is required (standard library only)"
[[ -d "${CLEAN_DIR}" ]] || die "clean corpus missing: ${CLEAN_DIR}"
[[ -d "${VULN_DIR}"  ]] || die "vuln corpus missing: ${VULN_DIR}"
[[ -f "${COMPARE}"   ]] || die "comparison script missing: ${COMPARE}"

# Honour a caller-provided CARGO_TARGET_DIR (CI and parallel agents rely on it).
TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

if [[ ${SKIP_BUILD} -eq 0 ]]; then
    command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust or pass --no-build"
    log "==> building scanner (release)"
    ( cd "${REPO_ROOT}" && cargo build --release --bin 41swara ) >&3 2>&3
fi

SCANNER="${TARGET_DIR}/release/41swara"
[[ -x "${SCANNER}" ]] || die "scanner binary not found at ${SCANNER} (drop --no-build?)"

SCANNER_VERSION="$("${SCANNER}" --version 2>/dev/null | awk '{print $NF}')"
[[ -n "${SCANNER_VERSION}" ]] || SCANNER_VERSION="unknown"

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/41swara-bench.XXXXXX")"
cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

# The scanner auto-saves a markdown report relative to its working directory, so
# run it from a scratch directory and redirect that report there. Otherwise a
# benchmark run litters the repository with report files.
scan_corpus() {
    local corpus_dir="$1" out_file="$2" label="$3"
    log "==> scanning ${label} corpus: ${corpus_dir}"
    (
        cd "${WORK_DIR}"
        "${SCANNER}" "${corpus_dir}" \
            --format json \
            --quiet \
            --no-color \
            --min-severity "${MIN_SEVERITY}" \
            --output "${WORK_DIR}/${label}-report.md" \
            > "${out_file}"
    ) || {
        # A non-zero exit is normal here only if --fail-on were set; it is not,
        # so treat it as a real failure unless the JSON still parsed.
        [[ -s "${out_file}" ]] || die "scanner failed on the ${label} corpus"
    }
}

CLEAN_RAW="${WORK_DIR}/clean.json"
VULN_RAW="${WORK_DIR}/vuln.json"

scan_corpus "${CLEAN_DIR}" "${CLEAN_RAW}" "clean"
scan_corpus "${VULN_DIR}"  "${VULN_RAW}"  "vuln"

# ---------------------------------------------------------------------------
# Optional: pinned upstream corpora (advisory, never gates CI)
# ---------------------------------------------------------------------------

# Pinned tags. Bump these deliberately; a moving target makes the numbers
# meaningless as a regression signal.
UPSTREAM_REPOS=(
    "openzeppelin-contracts|https://github.com/OpenZeppelin/openzeppelin-contracts.git|v5.0.2|contracts"
    "solmate|https://github.com/transmissions11/solmate.git|v7|src"
    "solady|https://github.com/Vectorized/solady.git|v0.0.201|src"
)

run_upstream() {
    log ""
    log "==> --with-upstream: benchmarking pinned upstream libraries (advisory only)"
    command -v git >/dev/null 2>&1 || {
        log "    SKIPPED: git is not installed."
        return 0
    }
    mkdir -p "${CACHE_DIR}"

    local entry name url tag subdir dest
    for entry in "${UPSTREAM_REPOS[@]}"; do
        IFS='|' read -r name url tag subdir <<<"${entry}"
        dest="${CACHE_DIR}/${name}"

        if [[ ! -d "${dest}/.git" ]]; then
            log "    cloning ${name} @ ${tag} ..."
            if ! git clone --quiet --depth 1 --branch "${tag}" "${url}" "${dest}" 2>/dev/null; then
                rm -rf "${dest}"
                log "    SKIPPED ${name}: clone failed."
                log "      This mode needs network access and reachable GitHub."
                log "      It is optional and advisory; the default harness run does not use it."
                continue
            fi
        else
            log "    using cached ${name} (${dest})"
        fi

        local scan_path="${dest}/${subdir}"
        [[ -d "${scan_path}" ]] || scan_path="${dest}"

        local raw="${WORK_DIR}/upstream-${name}.json"
        (
            cd "${WORK_DIR}"
            "${SCANNER}" "${scan_path}" \
                --format json --quiet --no-color \
                --min-severity "${MIN_SEVERITY}" \
                --output "${WORK_DIR}/upstream-${name}-report.md" \
                > "${raw}"
        ) || true

        if [[ -s "${raw}" ]]; then
            python3 - "${raw}" "${name}" "${tag}" >&3 <<'PY'
import json, sys
raw, name, tag = sys.argv[1], sys.argv[2], sys.argv[3]
decoder = json.JSONDecoder()
text = open(raw, encoding="utf-8").read()
report = None
for i, ch in enumerate(text):
    if ch == "{":
        try:
            report, _ = decoder.raw_decode(text[i:])
            break
        except json.JSONDecodeError:
            continue
if report is None:
    print(f"    {name} @ {tag}: could not parse scanner output")
    sys.exit(0)
counts = {}
total = 0
for entry in report.get("results", []):
    for v in entry.get("vulnerabilities") or []:
        c = v.get("category")
        c = c if isinstance(c, str) else next(iter(c), "Unknown")
        counts[c] = counts.get(c, 0) + 1
        total += 1
files = report.get("files_scanned", len(report.get("results", [])))
print(f"    {name} @ {tag}: {total} findings over {files} files")
for c, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]:
    print(f"        {n:>6}  {c}")
PY
        else
            log "    ${name}: scanner produced no output"
        fi
    done
    log "    (upstream numbers are advisory: they do not affect the exit code)"
}

# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------

COMPARE_ARGS=(
    --clean-raw "${CLEAN_RAW}"
    --vuln-raw  "${VULN_RAW}"
    --clean-dir "${CLEAN_DIR}"
    --vuln-dir  "${VULN_DIR}"
    --baseline  "${BASELINE}"
    --scanner-version "${SCANNER_VERSION}"
    --min-severity "${MIN_SEVERITY}"
)
# Written as `if` blocks rather than `cond && cmd`: under `set -e` a bare
# `[[ false ]] && cmd` list evaluates to 1 and kills the script.
if [[ ${UPDATE_BASELINE} -eq 1 ]]; then COMPARE_ARGS+=(--update-baseline); fi
if [[ ${JSON_OUTPUT}     -eq 1 ]]; then COMPARE_ARGS+=(--json); fi
if [[ -n "${TOLERANCE}"        ]]; then COMPARE_ARGS+=(--tolerance "${TOLERANCE}"); fi

set +e
python3 "${COMPARE}" "${COMPARE_ARGS[@]}"
STATUS=$?
set -e

if [[ ${WITH_UPSTREAM} -eq 1 ]]; then
    run_upstream
fi

exit "${STATUS}"
