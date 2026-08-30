//! Cross-file import and inheritance resolution.
//!
//! Resolves Solidity `import` directives to files on disk and linearizes contract
//! inheritance (C3), so that rules can see modifiers, state variables and functions
//! that a contract inherits from a base defined in another file.
//!
//! # Why this exists
//!
//! Every other analysis phase sees one file at a time. That produces three classes of
//! wrong answers:
//!
//! * **Access-control false positives.** `contract Vault is Ownable { function f()
//!   external onlyOwner {} }` — `onlyOwner` lives in another file, so a single-file
//!   scanner cannot tell it is a real guard.
//! * **Guard false positives.** `ReentrancyGuard::nonReentrant`, `Pausable::whenNotPaused`
//!   and project-specific base modifiers are invisible for the same reason.
//! * **Proxy storage-collision false negatives.** A slot collision only exists relative to
//!   the *full* storage layout of an inheritance chain, which cannot be computed from one
//!   file.
//!
//! # Usage
//!
//! ```ignore
//! let index = ProjectIndex::for_file(path);       // once per scan root; cheap to clone-share
//! let resolved = index.resolve(path);             // cached per file
//! if resolved.has_access_control_modifier("onlyOwner") { /* suppress the finding */ }
//! ```
//!
//! [`ProjectIndex`] memoizes both parsed files and resolved files in concurrent maps, so a
//! 500-file project parses each base exactly once no matter how many derived contracts
//! import it. All regexes are compiled once via `once_cell::sync::Lazy`.
//!
//! # Security boundary
//!
//! Import targets are canonicalized and rejected unless they live under the scan root.
//! `../../../etc/passwd`, and symlinks pointing outside the root, resolve to *nothing*
//! rather than being read. Scanning a hostile repository never reads outside it.
//!
//! # Robustness
//!
//! Nothing in this module panics or errors on bad input. Missing files (a dependency that
//! was never vendored is completely normal), unreadable files, non-UTF-8 bytes, empty
//! files, CRLF, a missing trailing newline, cyclic imports, cyclic inheritance, self
//! imports and inheritance chains thousands deep all degrade to a partial result plus a
//! diagnostic string. Recursion is depth-bounded; the C3 merge is iterative.
//!
//! # Approximations
//!
//! This is a regex/brace-matching parser, not a Solidity front end. Known deliberate
//! approximations:
//!
//! * **Contract scoping is global over the import closure.** Two different files that both
//!   declare `contract Token` collapse to one entry (the one in the file being scanned
//!   wins, then first-seen in import order). Solidity scopes per file.
//! * **Unresolvable bases fall back to a built-in table** ([`well_known_base_modifiers`])
//!   covering OpenZeppelin / Solmate / Solady. That keeps `is Ownable` working when
//!   `lib/` was never checked out, which is the common case for a bare `.sol` upload.
//! * **Storage layout**: `constant`, `immutable` and `transient` variables are skipped
//!   (they occupy no persistent slot). Value types ≤32 bytes pack right-to-left into the
//!   current slot when they fit; `mapping`, `bytes`, `string` and dynamic arrays take a
//!   fresh whole slot and force the next variable onto a new slot; structs and fixed
//!   arrays are slot-aligned and sized recursively (bounded depth). A fixed array whose
//!   length is a named constant, and any user-defined type that is not visible in the
//!   resolved chain, is charged one whole slot. Inherited variables are laid out
//!   most-base-first, matching solc.
//! * **Function/modifier bodies are not parsed**; a modifier is classified as an access
//!   control or reentrancy guard by keyword heuristics over its body text.
//! * `using ... for ...` directives, free functions, and `constructor`/`receive`/`fallback`
//!   are recognized and skipped rather than modelled.

use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

// =============================================================================
// Limits — every one of these exists to make hostile input terminate.
// =============================================================================

/// Maximum transitive import depth followed from the file being scanned.
const MAX_IMPORT_DEPTH: usize = 32;
/// Maximum inheritance recursion depth. Deeper chains return a partial linearization.
const MAX_INHERIT_DEPTH: usize = 64;
/// Maximum nesting depth when sizing a struct/array type.
const MAX_TYPE_DEPTH: u8 = 6;
/// Maximum files pulled into one import closure.
const MAX_CLOSURE_FILES: usize = 2_048;
/// Largest source file this module will parse (matches the scanner's own cap).
const MAX_SOURCE_BYTES: u64 = 10 * 1024 * 1024;
/// Bytes scanned forward from an `import` keyword looking for its terminating `;`.
const MAX_IMPORT_STMT_BYTES: usize = 1_024;

// =============================================================================
// Pre-compiled regexes
// =============================================================================

/// `import` as a standalone word. Matched against *masked* source, so occurrences
/// inside comments and string literals are already blanked out.
static RE_IMPORT_KW: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bimport\b").expect("invalid import regex"));

/// A contract/interface/library declaration at the start of a line.
static RE_CONTRACT_DECL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^[ \t]*(abstract[ \t\r\n]+contract|contract|interface|library)[ \t\r\n]+([A-Za-z_$][A-Za-z0-9_$]*)")
        .expect("invalid contract declaration regex")
});

/// `uintN` / `intN`.
static RE_INT_TYPE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^u?int([0-9]*)$").expect("invalid int type regex"));

/// `bytesN`.
static RE_BYTES_N: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^bytes([0-9]+)$").expect("invalid bytesN regex"));

// =============================================================================
// Data model
// =============================================================================

/// What kind of top-level definition a declaration is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContractKind {
    Contract,
    Abstract,
    Interface,
    Library,
}

impl ContractKind {
    /// Interfaces and libraries never contribute persistent storage to a deriving
    /// contract, and a library cannot be inherited from at all.
    pub(crate) fn contributes_storage(self) -> bool {
        matches!(self, ContractKind::Contract | ContractKind::Abstract)
    }
}

/// What a modifier actually guards, inferred from its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardKind {
    /// Compares the caller against an owner/role/allowlist.
    AccessControl,
    /// Mutex-style reentrancy lock.
    ReentrancyGuard,
    /// Circuit breaker (`whenNotPaused`).
    Pause,
    /// One-shot initializer guard.
    Initializer,
    /// Anything else (input validation, deadline checks, ...).
    Other,
}

impl GuardKind {
    /// Whether a finding of "function has no authorization" should be suppressed when
    /// this modifier is present on the function.
    pub(crate) fn restricts_callers(self) -> bool {
        matches!(
            self,
            GuardKind::AccessControl | GuardKind::Pause | GuardKind::Initializer
        )
    }
}

// NOTE (dead_code): the items marked below are read by this module's own
// `#[cfg(test)] mod tests`, which `dead_code` does not count in a non-test build.
// The scanner currently consumes only part of the resolver's surface (reentrancy /
// access-control queries and the file-wide modifier union); the rest is the parsed
// contract that those tests pin down — C3 linearization, storage layout, override
// shadowing, modifier classification. Deleting it would delete the tests that prove
// the resolver correct, and wiring it into the scan would change scan results, so
// each item carries a scoped allow rather than a module-wide one.

/// A `modifier` definition.
#[derive(Debug, Clone)]
// `declared_in` / `line` are asserted on by the override-shadowing tests.
#[allow(dead_code)]
pub(crate) struct ModifierDef {
    pub(crate) name: String,
    pub(crate) guard: GuardKind,
    /// Contract the winning definition came from (after `override` shadowing).
    pub(crate) declared_in: String,
    pub(crate) line: usize,
}

/// A `function` definition or signature.
#[derive(Debug, Clone)]
// Everything but `name` is asserted on by the signature-parsing tests.
#[allow(dead_code)]
pub(crate) struct FunctionDef {
    pub(crate) name: String,
    /// `public` / `external` / `internal` / `private`; empty when not written.
    pub(crate) visibility: String,
    /// `view` / `pure` / `payable` / `nonpayable`.
    pub(crate) mutability: String,
    /// Modifier invocations written on the signature, argument lists stripped.
    pub(crate) modifiers: Vec<String>,
    /// True when the function has no body (interface / abstract signature).
    pub(crate) is_signature_only: bool,
    pub(crate) declared_in: String,
    pub(crate) line: usize,
}

/// Storage mutability of a state variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VarMutability {
    Mutable,
    Constant,
    Immutable,
    /// EIP-1153 `transient` storage (Solidity 0.8.28+); not part of persistent layout.
    Transient,
}

impl VarMutability {
    /// Whether the variable consumes a persistent storage slot.
    pub(crate) fn occupies_storage(self) -> bool {
        matches!(self, VarMutability::Mutable)
    }
}

/// A state variable (or a struct member — the syntax is the same).
#[derive(Debug, Clone)]
// `visibility` / `line` are asserted on by the state-variable parsing tests.
#[allow(dead_code)]
pub(crate) struct StateVarDef {
    pub(crate) name: String,
    pub(crate) ty: String,
    pub(crate) mutability: VarMutability,
    pub(crate) visibility: String,
    pub(crate) declared_in: String,
    pub(crate) line: usize,
}

/// One variable placed in the storage layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StorageSlot {
    pub(crate) name: String,
    pub(crate) ty: String,
    /// Contract in the linearized chain that declared it.
    pub(crate) declared_in: String,
    /// Zero-based slot index.
    pub(crate) slot: u64,
    /// Byte offset within the slot (0 unless packed).
    pub(crate) offset: u16,
    /// Byte size for packed value types; 32 for anything slot-aligned.
    pub(crate) size: u16,
}

/// The ordered storage layout of a contract including all inherited variables.
#[derive(Debug, Clone, Default)]
// `total_slots` is asserted on by the solc storage-packing test.
#[allow(dead_code)]
pub(crate) struct StorageLayout {
    pub(crate) slots: Vec<StorageSlot>,
    /// Number of slots consumed in total.
    pub(crate) total_slots: u64,
}

/// A slot occupied by incompatible variables in two layouts (e.g. proxy vs impl).
#[derive(Debug, Clone)]
pub(crate) struct SlotCollision {
    pub(crate) slot: u64,
    pub(crate) offset: u16,
    /// `name: type` as laid out by the first contract.
    pub(crate) left: String,
    /// `name: type` as laid out by the second contract.
    pub(crate) right: String,
    pub(crate) reason: &'static str,
}

impl StorageLayout {
    /// Slots where `self` and `other` disagree about the *type* stored at a given
    /// (slot, offset). Used to detect a proxy/implementation storage collision: write
    /// through one layout, read through the other, and the bytes are reinterpreted.
    ///
    /// A pure rename with an identical type is reported with a weaker `reason` so the
    /// caller can decide whether it is worth surfacing.
    pub(crate) fn collisions_with(&self, other: &StorageLayout) -> Vec<SlotCollision> {
        let mut by_pos: HashMap<(u64, u16), &StorageSlot> = HashMap::new();
        for s in &self.slots {
            by_pos.insert((s.slot, s.offset), s);
        }
        let mut out = Vec::new();
        for r in &other.slots {
            let Some(l) = by_pos.get(&(r.slot, r.offset)) else {
                continue;
            };
            let same_type = normalize_type(&l.ty) == normalize_type(&r.ty);
            let same_name = l.name == r.name;
            if same_type && same_name {
                continue;
            }
            out.push(SlotCollision {
                slot: r.slot,
                offset: r.offset,
                left: format!("{} {} ({})", l.ty, l.name, l.declared_in),
                right: format!("{} {} ({})", r.ty, r.name, r.declared_in),
                reason: if same_type {
                    "same type, different variable — layout drift"
                } else {
                    "different type at the same slot — storage collision"
                },
            });
        }
        out.sort_by_key(|c| (c.slot, c.offset));
        out
    }
}

// =============================================================================
// Parsed (pre-resolution) representation
// =============================================================================

#[derive(Debug)]
struct ImportDecl {
    /// The literal path written in the source.
    raw: String,
    /// Where it landed on disk, if it resolved inside the scan root.
    resolved: Option<PathBuf>,
    /// `{Original as Alias}` → `Alias -> Original`.
    aliases: Vec<(String, String)>,
}

#[derive(Debug)]
struct ContractDecl {
    name: String,
    kind: ContractKind,
    /// Base names in source order (Solidity lists them most-base-first).
    bases: Vec<String>,
    modifiers: Vec<ModifierDef>,
    functions: Vec<FunctionDef>,
    state_vars: Vec<StateVarDef>,
    events: Vec<String>,
    /// `struct Name` → its members, for storage sizing.
    structs: HashMap<String, Vec<StateVarDef>>,
    enums: HashSet<String>,
    /// `type X is uint128;` → `X -> uint128`.
    value_types: HashMap<String, String>,
}

/// One parsed `.sol` file. Cached by canonical path inside [`ProjectIndex`].
#[derive(Debug)]
struct ParsedFile {
    contracts: Vec<Arc<ContractDecl>>,
    imports: Vec<ImportDecl>,
}

impl ParsedFile {
    fn empty() -> Self {
        ParsedFile {
            contracts: Vec::new(),
            imports: Vec::new(),
        }
    }
}

// =============================================================================
// Resolved (post-linearization) representation — the crate-facing output
// =============================================================================

/// A contract with everything it inherits folded in.
#[derive(Debug, Clone)]
// The declaration lists and the linearization are asserted on by the C3 / inheritance
// tests; the scanner only reads `name`, `kind` and `storage`.
#[allow(dead_code)]
pub(crate) struct ResolvedContract {
    pub(crate) name: String,
    pub(crate) kind: ContractKind,
    /// C3 linearization, most-derived first (`[Vault, Pausable, Ownable, Context]`).
    pub(crate) linearization: Vec<String>,
    /// Every visible modifier after `override` shadowing, sorted by name.
    pub(crate) modifiers: Vec<ModifierDef>,
    /// Every visible function after `override` shadowing, sorted by name.
    pub(crate) functions: Vec<FunctionDef>,
    /// Storage-ordered (most-base-first) state variables, including inherited ones.
    pub(crate) state_variables: Vec<StateVarDef>,
    /// Event names visible in the chain, sorted.
    pub(crate) events: Vec<String>,
    pub(crate) storage: StorageLayout,
    /// Bases that could not be found on disk and were not in the built-in table.
    pub(crate) unresolved_bases: Vec<String>,
    /// Human-readable notes (cycles, depth caps, inconsistent hierarchies).
    pub(crate) diagnostics: Vec<String>,
    /// Sorted names of modifiers whose guard restricts callers. Kept separate so the
    /// hot filter path is a `binary_search` over `&str` with no allocation.
    access_modifiers: Vec<String>,
    has_reentrancy_guard: bool,
}

// Per-contract queries: the scanner asks the file-wide `ResolvedFile` equivalents
// instead, so only the tests reach these.
#[allow(dead_code)]
impl ResolvedContract {
    /// Is `name` a modifier visible on this contract (own or inherited)?
    pub(crate) fn has_modifier(&self, name: &str) -> bool {
        self.modifiers
            .binary_search_by(|m| m.name.as_str().cmp(name))
            .is_ok()
    }

    /// Is `name` a modifier that actually restricts who may call the function?
    /// This is the query that kills the `is Ownable` → "missing access control"
    /// false positive.
    pub(crate) fn has_access_control_modifier(&self, name: &str) -> bool {
        self.access_modifiers
            .binary_search_by(|m| m.as_str().cmp(name))
            .is_ok()
    }

    /// Does the chain provide a reentrancy lock (OZ `ReentrancyGuard` or a custom mutex)?
    pub(crate) fn has_reentrancy_guard(&self) -> bool {
        self.has_reentrancy_guard
    }

    /// Every visible modifier name, cheapest possible iteration.
    pub(crate) fn modifier_names(&self) -> impl Iterator<Item = &str> {
        self.modifiers.iter().map(|m| m.name.as_str())
    }

    /// Does this contract inherit (transitively) from `base`?
    pub(crate) fn inherits_from(&self, base: &str) -> bool {
        self.linearization.iter().skip(1).any(|n| n == base)
    }
}

/// Everything in one `.sol` file, resolved. Also carries file-wide unions so the
/// scanner can answer "is this a known modifier anywhere in this file's chains?"
/// without picking a contract first.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedFile {
    /// Asserted on by the import-resolution tests.
    #[allow(dead_code)]
    pub(crate) path: PathBuf,
    pub(crate) contracts: Vec<ResolvedContract>,
    /// Asserted on by the cycle / depth-cap tests.
    #[allow(dead_code)]
    pub(crate) diagnostics: Vec<String>,
    all_modifiers: Vec<String>,
    all_access_modifiers: Vec<String>,
    has_reentrancy_guard: bool,
}

impl ResolvedFile {
    /// The contract by name, if the file defines it.
    #[allow(dead_code)] // reached only by this module's tests; see the note above
    pub(crate) fn contract(&self, name: &str) -> Option<&ResolvedContract> {
        self.contracts.iter().find(|c| c.name == name)
    }

    /// The most-derived concrete contract in the file — the one a scan is usually about.
    /// Falls back to the last declaration when nothing concrete is present.
    #[allow(dead_code)] // reached only by this module's tests; see the note above
    pub(crate) fn primary(&self) -> Option<&ResolvedContract> {
        self.contracts
            .iter()
            .filter(|c| c.kind == ContractKind::Contract)
            .max_by_key(|c| c.linearization.len())
            .or_else(|| self.contracts.last())
    }

    /// Is `name` a modifier visible anywhere in this file (own or inherited)?
    #[allow(dead_code)] // reached only by this module's tests; see the note above
    pub(crate) fn has_modifier(&self, name: &str) -> bool {
        self.all_modifiers
            .binary_search_by(|m| m.as_str().cmp(name))
            .is_ok()
    }

    /// Is `name` a caller-restricting modifier visible anywhere in this file?
    pub(crate) fn has_access_control_modifier(&self, name: &str) -> bool {
        self.all_access_modifiers
            .binary_search_by(|m| m.as_str().cmp(name))
            .is_ok()
    }

    /// Does any contract in the file inherit a reentrancy lock?
    pub(crate) fn has_reentrancy_guard(&self) -> bool {
        self.has_reentrancy_guard
    }

    /// Every modifier name visible in the file, sorted and deduplicated. Drop-in
    /// replacement for the scanner's `resolve_known_modifiers` string-matching.
    pub(crate) fn modifier_names(&self) -> &[String] {
        &self.all_modifiers
    }

    /// True when nothing inherited was discovered — the caller can then keep its
    /// existing single-file heuristics unchanged.
    pub(crate) fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }
}

// =============================================================================
// ProjectIndex
// =============================================================================

/// Per-scan-root cache of parsed and resolved Solidity files.
///
/// Build one per scan and share it; both caches are concurrent so rayon workers can
/// resolve different files in parallel without re-parsing shared bases.
pub(crate) struct ProjectIndex {
    root: PathBuf,
    /// `prefix` → `target`, longest prefix wins. Sorted longest-first at construction.
    remappings: Vec<(String, String)>,
    parsed: DashMap<PathBuf, Arc<ParsedFile>>,
    resolved: DashMap<PathBuf, Arc<ResolvedFile>>,
    /// `(importer dir, raw import string)` → resolved path. Import resolution probes up
    /// to ~14 candidate locations, each a `canonicalize` syscall; without this a project
    /// where every file imports the same OpenZeppelin path pays that once per file.
    imports: DashMap<(PathBuf, String), Option<PathBuf>>,
}

impl ProjectIndex {
    /// Build an index rooted at `root`. Reads `remappings.txt` and `foundry.toml`
    /// remappings when present.
    pub(crate) fn for_root<P: AsRef<Path>>(root: P) -> Self {
        let root = canonical_or_lexical(root.as_ref());
        let remappings = load_remappings(&root);
        ProjectIndex {
            root,
            remappings,
            parsed: DashMap::new(),
            resolved: DashMap::new(),
            imports: DashMap::new(),
        }
    }

    /// Infer the project root by walking up from `file` looking for a project marker
    /// (`foundry.toml`, `remappings.txt`, `hardhat.config.*`, `package.json`, `.git`),
    /// then build an index for it. Falls back to the file's own directory.
    #[allow(dead_code)] // reached only by this module's tests; see the note above
    pub(crate) fn for_file<P: AsRef<Path>>(file: P) -> Self {
        Self::for_root(root_for(file.as_ref()))
    }

    /// The scan root. Imports resolving outside it are rejected.
    #[allow(dead_code)] // reached only by this module's tests; see the note above
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve every contract in `file`, following imports. Cached: the second call for
    /// the same path is a map lookup, and shared bases are parsed exactly once per index.
    pub(crate) fn resolve<P: AsRef<Path>>(&self, file: P) -> Arc<ResolvedFile> {
        let key = canonical_or_lexical(file.as_ref());
        if let Some(hit) = self.resolved.get(&key) {
            return Arc::clone(&hit);
        }
        let built = Arc::new(self.build_resolved(&key));
        self.resolved.insert(key, Arc::clone(&built));
        built
    }

    // ---- internals ---------------------------------------------------------

    fn parse(&self, path: &Path) -> Arc<ParsedFile> {
        if let Some(hit) = self.parsed.get(path) {
            return Arc::clone(&hit);
        }
        let parsed = Arc::new(self.parse_uncached(path));
        self.parsed.insert(path.to_path_buf(), Arc::clone(&parsed));
        parsed
    }

    fn parse_uncached(&self, path: &Path) -> ParsedFile {
        let Some(source) = read_source(path) else {
            return ParsedFile::empty();
        };
        let masked = mask_source(&source);
        let lines = LineTable::new(&masked.text);
        let dir = path.parent().unwrap_or_else(|| Path::new("."));

        let mut imports = parse_imports(&masked);
        let mut alias_map = HashMap::new();
        for imp in &mut imports {
            imp.resolved = self.resolve_import(&imp.raw, dir);
            for (alias, original) in &imp.aliases {
                alias_map.insert(alias.clone(), original.clone());
            }
        }

        // Resolve base names through this file's import aliases once, at parse time.
        // Every later phase then reads `bases` directly, so building the per-file scope
        // map is pure borrowing with no allocation.
        let mut parsed_contracts = parse_contracts(&masked.text, &lines);
        for decl in &mut parsed_contracts {
            for base in &mut decl.bases {
                // `N.Ownable` (namespace import) -> `Ownable`, then alias -> original.
                let short = base.rsplit('.').next().unwrap_or(base).to_string();
                *base = alias_map.get(&short).cloned().unwrap_or(short);
            }
        }
        let contracts = parsed_contracts.into_iter().map(Arc::new).collect();

        ParsedFile { contracts, imports }
    }

    /// Map an import string onto a real file, or `None` if it is not vendored / escapes
    /// the scan root. Memoized per `(importer dir, import string)`.
    fn resolve_import(&self, raw: &str, importer_dir: &Path) -> Option<PathBuf> {
        let key = (importer_dir.to_path_buf(), raw.to_string());
        if let Some(hit) = self.imports.get(&key) {
            return hit.clone();
        }
        let resolved = self.resolve_import_uncached(raw, importer_dir);
        self.imports.insert(key, resolved.clone());
        resolved
    }

    fn resolve_import_uncached(&self, raw: &str, importer_dir: &Path) -> Option<PathBuf> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }

        let mut candidates: Vec<PathBuf> = Vec::new();
        if raw.starts_with("./") || raw.starts_with("../") || raw.starts_with('.') {
            candidates.push(importer_dir.join(raw));
        } else {
            // Remappings first (longest prefix wins).
            for (prefix, target) in &self.remappings {
                if let Some(rest) = raw.strip_prefix(prefix.as_str()) {
                    let joined = format!("{}{}", target, rest);
                    let p = Path::new(&joined);
                    candidates.push(if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        self.root.join(p)
                    });
                }
            }
            // Then the conventional layouts.
            candidates.extend(self.package_candidates(raw));
            // Then plain project-relative and importer-relative.
            candidates.push(self.root.join(raw));
            candidates.push(importer_dir.join(raw));
        }

        for cand in candidates {
            if let Some(ok) = self.accept(&cand) {
                return Some(ok);
            }
        }
        None
    }

    /// `@scope/pkg/rest` and `pkg/rest` under `node_modules/` and Foundry's `lib/`.
    fn package_candidates(&self, raw: &str) -> Vec<PathBuf> {
        let mut out = Vec::new();
        out.push(self.root.join("node_modules").join(raw));

        let (pkg, rest) = split_package(raw);
        let Some(rest) = rest else { return out };
        // Foundry vendors `@openzeppelin/contracts` as `lib/openzeppelin-contracts`.
        let mut dir_names = vec![pkg.to_string()];
        if let Some(stripped) = pkg.strip_prefix('@') {
            dir_names.push(stripped.replace('/', "-"));
            if let Some((_, name)) = stripped.split_once('/') {
                dir_names.push(name.to_string());
            }
        }
        for dir in dir_names {
            let base = self.root.join("lib").join(&dir);
            out.push(base.join(rest));
            out.push(base.join("src").join(rest));
            out.push(base.join("contracts").join(rest));
            // `@openzeppelin/contracts/access/Ownable.sol` under
            // `lib/openzeppelin-contracts/contracts/access/Ownable.sol`: `rest` already
            // starts with `contracts/`, so `base.join(rest)` above covers it.
        }
        out
    }

    /// Canonicalize a candidate and enforce the scan-root boundary.
    fn accept(&self, candidate: &Path) -> Option<PathBuf> {
        let normalized = normalize_lexical(candidate);
        // `canonicalize` both proves existence and resolves symlinks, which is exactly
        // what the boundary check needs — a symlink out of the tree must be rejected.
        // `canonicalize` proves existence and resolves symlinks in one syscall; whether
        // the target is a regular file is re-checked by `read_source` before parsing.
        let real = std::fs::canonicalize(&normalized).ok()?;
        if !real.starts_with(&self.root) {
            return None;
        }
        Some(real)
    }

    /// Depth-first import closure. Cycles and self-imports terminate via `visited`.
    fn closure(&self, entry: &Path) -> (Vec<Arc<ParsedFile>>, Vec<String>) {
        let mut diagnostics = Vec::new();
        let mut visited: HashSet<PathBuf> = HashSet::new();
        let mut order: Vec<Arc<ParsedFile>> = Vec::new();
        let mut stack: Vec<(PathBuf, usize)> = vec![(entry.to_path_buf(), 0)];

        while let Some((path, depth)) = stack.pop() {
            if !visited.insert(path.clone()) {
                continue;
            }
            if order.len() >= MAX_CLOSURE_FILES {
                diagnostics.push(format!(
                    "import closure truncated at {MAX_CLOSURE_FILES} files; results are partial"
                ));
                break;
            }
            let parsed = self.parse(&path);
            if depth < MAX_IMPORT_DEPTH {
                for imp in &parsed.imports {
                    if let Some(target) = &imp.resolved {
                        stack.push((target.clone(), depth + 1));
                    }
                }
            } else {
                diagnostics.push(format!(
                    "import depth limit ({MAX_IMPORT_DEPTH}) reached at {}",
                    path.display()
                ));
            }
            order.push(parsed);
        }
        (order, diagnostics)
    }

    fn build_resolved(&self, path: &Path) -> ResolvedFile {
        let (files, mut diagnostics) = self.closure(path);
        let Some(entry_file) = files.first() else {
            return ResolvedFile {
                path: path.to_path_buf(),
                contracts: Vec::new(),
                diagnostics,
                all_modifiers: Vec::new(),
                all_access_modifiers: Vec::new(),
                has_reentrancy_guard: false,
            };
        };

        // Global scope map over the closure. Imported definitions are first-seen-wins;
        // the scanned file's own definitions always win (see module docs).
        let mut scope: Scope<'_> = HashMap::with_capacity(files.len() * 2);
        for file in files.iter().skip(1) {
            for decl in &file.contracts {
                scope.entry(decl.name.as_str()).or_insert(decl.as_ref());
            }
        }
        for decl in &entry_file.contracts {
            scope.insert(decl.name.as_str(), decl.as_ref());
        }

        let mut memo: HashMap<String, Vec<String>> = HashMap::new();
        let mut contracts = Vec::new();
        for decl in &entry_file.contracts {
            contracts.push(resolve_contract(decl, &scope, &mut memo));
        }

        // File-wide unions for the cheap scanner queries.
        let mut all: BTreeSet<&str> = BTreeSet::new();
        let mut access: BTreeSet<&str> = BTreeSet::new();
        let mut guard = false;
        for c in &contracts {
            for m in &c.modifiers {
                all.insert(m.name.as_str());
                if m.guard.restricts_callers() {
                    access.insert(m.name.as_str());
                }
            }
            guard |= c.has_reentrancy_guard;
            diagnostics.extend(c.diagnostics.iter().cloned());
        }
        let all_modifiers: Vec<String> = all.into_iter().map(str::to_string).collect();
        let all_access_modifiers: Vec<String> = access.into_iter().map(str::to_string).collect();

        ResolvedFile {
            path: path.to_path_buf(),
            contracts,
            diagnostics,
            all_modifiers,
            all_access_modifiers,
            has_reentrancy_guard: guard,
        }
    }
}

/// Contract-name lookup over one file's import closure. Borrowed from the closure's
/// `ParsedFile`s, so building it for a file allocates nothing per contract.
type Scope<'a> = HashMap<&'a str, &'a ContractDecl>;

// =============================================================================
// C3 linearization
// =============================================================================

/// Standard C3 merge. Returns `None` for an inconsistent hierarchy (which solc also
/// rejects) so the caller can fall back to a deterministic DFS order.
fn c3_merge(mut seqs: Vec<VecDeque<String>>) -> Option<Vec<String>> {
    let mut out = Vec::new();
    loop {
        seqs.retain(|s| !s.is_empty());
        if seqs.is_empty() {
            return Some(out);
        }
        let mut head: Option<String> = None;
        for s in &seqs {
            let candidate = &s[0];
            let in_tail = seqs
                .iter()
                .any(|o| o.iter().skip(1).any(|x| x == candidate));
            if !in_tail {
                head = Some(candidate.clone());
                break;
            }
        }
        let head = head?;
        for s in seqs.iter_mut() {
            if s.front().map(String::as_str) == Some(head.as_str()) {
                s.pop_front();
            }
        }
        out.push(head);
    }
}

/// Linearize `name` into a most-derived-first list.
///
/// Solidity lists bases most-base-first, so the base list is reversed before the merge;
/// the result matches solc's `C3` ordering. Cycles are broken (with a diagnostic) rather
/// than recursed into, and depth is capped so a pathological chain returns a partial
/// answer instead of overflowing the stack.
fn linearize(
    name: &str,
    scope: &Scope<'_>,
    memo: &mut HashMap<String, Vec<String>>,
    active: &mut Vec<String>,
    diagnostics: &mut Vec<String>,
    depth: usize,
) -> Vec<String> {
    if let Some(hit) = memo.get(name) {
        return hit.clone();
    }
    if active.iter().any(|n| n == name) {
        diagnostics.push(format!("inheritance cycle broken at `{name}`"));
        return vec![name.to_string()];
    }
    if depth >= MAX_INHERIT_DEPTH {
        diagnostics.push(format!(
            "inheritance depth limit ({MAX_INHERIT_DEPTH}) reached at `{name}`; partial chain"
        ));
        return vec![name.to_string()];
    }
    let Some(decl) = scope.get(name) else {
        // Unknown base (dependency not vendored). It is still a node in the chain.
        return vec![name.to_string()];
    };

    // Reverse to Python/C3 orientation (most-derived first), dropping duplicate bases.
    let mut bases: Vec<String> = Vec::with_capacity(decl.bases.len());
    for b in decl.bases.iter().rev() {
        if !bases.iter().any(|x| x == b) {
            bases.push(b.clone());
        }
    }

    active.push(name.to_string());
    let mut seqs: Vec<VecDeque<String>> = bases
        .iter()
        .map(|b| {
            linearize(b, scope, memo, active, diagnostics, depth + 1)
                .into_iter()
                .collect()
        })
        .collect();
    seqs.push(bases.iter().cloned().collect());
    active.pop();

    let mut result = vec![name.to_string()];
    match c3_merge(seqs) {
        Some(rest) => result.extend(rest),
        None => {
            diagnostics.push(format!(
                "inconsistent inheritance graph for `{name}`; using depth-first order"
            ));
            let mut seen: HashSet<String> = HashSet::new();
            seen.insert(name.to_string());
            for b in &bases {
                for n in linearize(b, scope, memo, active, diagnostics, depth + 1) {
                    if seen.insert(n.clone()) {
                        result.push(n);
                    }
                }
            }
        }
    }
    // A broken cycle can repeat a name; keep the first occurrence so the chain stays a set.
    let mut seen: HashSet<String> = HashSet::new();
    result.retain(|n| seen.insert(n.clone()));
    memo.insert(name.to_string(), result.clone());
    result
}

// =============================================================================
// Member + storage resolution
// =============================================================================

fn resolve_contract(
    decl: &ContractDecl,
    scope: &Scope<'_>,
    memo: &mut HashMap<String, Vec<String>>,
) -> ResolvedContract {
    let mut diagnostics = Vec::new();
    let mut active = Vec::new();
    let linearization = linearize(
        &decl.name,
        scope,
        memo,
        &mut active,
        &mut diagnostics,
        0,
    );

    // Walk most-base-first so a derived `override` definition overwrites its base.
    let mut modifiers: HashMap<String, ModifierDef> = HashMap::new();
    let mut functions: HashMap<String, FunctionDef> = HashMap::new();
    let mut events: BTreeSet<String> = BTreeSet::new();
    let mut ordered_vars: Vec<StateVarDef> = Vec::new();
    let mut unresolved_bases = Vec::new();

    let mut structs: HashMap<String, Vec<StateVarDef>> = HashMap::new();
    let mut enums: HashSet<String> = HashSet::new();
    let mut value_types: HashMap<String, String> = HashMap::new();

    for contract_name in linearization.iter().rev() {
        let Some(d) = scope.get(contract_name.as_str()) else {
            // Not on disk — fall back to the built-in table of well-known bases.
            let known = well_known_base_modifiers(contract_name);
            if known.is_empty() {
                unresolved_bases.push(contract_name.clone());
            } else {
                for (mname, guard) in known {
                    modifiers.insert(
                        mname.to_string(),
                        ModifierDef {
                            name: mname.to_string(),
                            guard: *guard,
                            declared_in: contract_name.clone(),
                            line: 0,
                        },
                    );
                }
            }
            continue;
        };
        for m in &d.modifiers {
            modifiers.insert(m.name.clone(), m.clone());
        }
        for f in &d.functions {
            functions.insert(f.name.clone(), f.clone());
        }
        for e in &d.events {
            events.insert(e.clone());
        }
        for (k, v) in &d.structs {
            structs.entry(k.clone()).or_insert_with(|| v.clone());
        }
        enums.extend(d.enums.iter().cloned());
        for (k, v) in &d.value_types {
            value_types.entry(k.clone()).or_insert_with(|| v.clone());
        }
        if d.kind.contributes_storage() {
            ordered_vars.extend(d.state_vars.iter().cloned());
        }
    }

    let env = TypeEnv {
        structs: &structs,
        enums: &enums,
        value_types: &value_types,
        contracts: scope,
    };
    let storage = compute_layout(&ordered_vars, &env);

    let mut modifiers: Vec<ModifierDef> = modifiers.into_values().collect();
    modifiers.sort_by(|a, b| a.name.cmp(&b.name));
    let mut functions: Vec<FunctionDef> = functions.into_values().collect();
    functions.sort_by(|a, b| a.name.cmp(&b.name));

    let access_modifiers: Vec<String> = modifiers
        .iter()
        .filter(|m| m.guard.restricts_callers())
        .map(|m| m.name.clone())
        .collect();
    let has_reentrancy_guard = modifiers.iter().any(|m| m.guard == GuardKind::ReentrancyGuard);

    ResolvedContract {
        name: decl.name.clone(),
        kind: decl.kind,
        linearization,
        modifiers,
        functions,
        state_variables: ordered_vars,
        events: events.into_iter().collect(),
        storage,
        unresolved_bases,
        diagnostics,
        access_modifiers,
        has_reentrancy_guard,
    }
}

/// Base contracts whose modifiers we know without seeing the source. Used only when the
/// base could not be resolved on disk, which is the normal state for a single uploaded
/// `.sol` file or a repo with `lib/` uncommitted.
fn well_known_base_modifiers(name: &str) -> &'static [(&'static str, GuardKind)] {
    // Strip the OZ-upgradeable suffix so `OwnableUpgradeable` hits the `Ownable` row.
    let base = name.strip_suffix("Upgradeable").unwrap_or(name);
    match base {
        "Ownable" | "Ownable2Step" | "Owned" | "OwnedThreeStep" => {
            &[("onlyOwner", GuardKind::AccessControl)]
        }
        "OwnableRoles" => &[
            ("onlyOwner", GuardKind::AccessControl),
            ("onlyRoles", GuardKind::AccessControl),
            ("onlyOwnerOrRoles", GuardKind::AccessControl),
            ("onlyRolesOrOwner", GuardKind::AccessControl),
        ],
        "ReentrancyGuard" | "ReentrancyGuardTransient" | "ReentrancyGuardUpgradeable" => {
            &[("nonReentrant", GuardKind::ReentrancyGuard)]
        }
        "Pausable" => &[
            ("whenNotPaused", GuardKind::Pause),
            ("whenPaused", GuardKind::Pause),
        ],
        "AccessControl"
        | "AccessControlEnumerable"
        | "AccessControlDefaultAdminRules"
        | "IAccessControl" => &[("onlyRole", GuardKind::AccessControl)],
        "AccessManaged" | "AccessManagedUpgradeable" => {
            &[("restricted", GuardKind::AccessControl)]
        }
        "Initializable" => &[
            ("initializer", GuardKind::Initializer),
            ("reinitializer", GuardKind::Initializer),
            ("onlyInitializing", GuardKind::Initializer),
        ],
        "UUPSUpgradeable" => &[
            ("onlyProxy", GuardKind::AccessControl),
            ("notDelegated", GuardKind::AccessControl),
        ],
        "Auth" => &[("requiresAuth", GuardKind::AccessControl)],
        "Governor" | "GovernorUpgradeable" => &[("onlyGovernance", GuardKind::AccessControl)],
        "CCIPReceiver" => &[("onlyRouter", GuardKind::AccessControl)],
        _ => &[],
    }
}

// =============================================================================
// Storage layout
// =============================================================================

struct TypeEnv<'a> {
    structs: &'a HashMap<String, Vec<StateVarDef>>,
    enums: &'a HashSet<String>,
    value_types: &'a HashMap<String, String>,
    contracts: &'a Scope<'a>,
}

/// How a type occupies storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeClass {
    /// A value type of N bytes that may share a slot.
    Value(u16),
    /// Occupies N whole slots and never shares.
    Slots(u64),
}

fn compute_layout(vars: &[StateVarDef], env: &TypeEnv<'_>) -> StorageLayout {
    let mut slots = Vec::new();
    let mut slot: u64 = 0;
    let mut offset: u16 = 0;
    for v in vars {
        if !v.mutability.occupies_storage() {
            continue;
        }
        match type_size(&v.ty, env, 0) {
            SizeClass::Value(size) => {
                if offset + size > 32 {
                    slot += 1;
                    offset = 0;
                }
                slots.push(StorageSlot {
                    name: v.name.clone(),
                    ty: v.ty.clone(),
                    declared_in: v.declared_in.clone(),
                    slot,
                    offset,
                    size,
                });
                offset += size;
            }
            SizeClass::Slots(n) => {
                if offset > 0 {
                    slot += 1;
                    offset = 0;
                }
                slots.push(StorageSlot {
                    name: v.name.clone(),
                    ty: v.ty.clone(),
                    declared_in: v.declared_in.clone(),
                    slot,
                    offset: 0,
                    size: 32,
                });
                slot += n.max(1);
            }
        }
    }
    let total_slots = if offset > 0 { slot + 1 } else { slot };
    StorageLayout { slots, total_slots }
}

fn type_size(ty: &str, env: &TypeEnv<'_>, depth: u8) -> SizeClass {
    if depth >= MAX_TYPE_DEPTH {
        return SizeClass::Slots(1);
    }
    let t = normalize_type(ty);
    let t = t.as_str();

    // Arrays: split on the trailing `[...]`.
    if t.ends_with(']') {
        if let Some(open) = matching_open_bracket(t) {
            let elem = t[..open].trim();
            let len = t[open + 1..t.len() - 1].trim();
            if len.is_empty() {
                return SizeClass::Slots(1); // dynamic array: one slot for the length
            }
            let Ok(n) = len.parse::<u64>() else {
                // Length is a named constant — cannot size it; charge one slot.
                return SizeClass::Slots(1);
            };
            return match type_size(elem, env, depth + 1) {
                SizeClass::Value(s) if s > 0 => {
                    let per_slot = (32 / s.max(1)) as u64;
                    SizeClass::Slots(n.div_ceil(per_slot.max(1)))
                }
                SizeClass::Value(_) => SizeClass::Slots(n),
                SizeClass::Slots(k) => SizeClass::Slots(n.saturating_mul(k.max(1))),
            };
        }
    }

    if t.starts_with("mapping") {
        return SizeClass::Slots(1);
    }
    match t {
        "bytes" | "string" => return SizeClass::Slots(1),
        "bool" => return SizeClass::Value(1),
        "address" | "address payable" | "addresspayable" => return SizeClass::Value(20),
        _ => {}
    }
    if let Some(caps) = RE_INT_TYPE.captures(t) {
        let bits = caps
            .get(1)
            .map(|m| m.as_str())
            .filter(|s| !s.is_empty())
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(256);
        if bits > 0 && bits <= 256 && bits % 8 == 0 {
            return SizeClass::Value(bits / 8);
        }
        return SizeClass::Value(32);
    }
    if let Some(caps) = RE_BYTES_N.captures(t) {
        if let Some(n) = caps.get(1).and_then(|m| m.as_str().parse::<u16>().ok()) {
            if (1..=32).contains(&n) {
                return SizeClass::Value(n);
            }
        }
    }

    // User-defined names, possibly qualified (`Lib.Kind`).
    let short = t.rsplit('.').next().unwrap_or(t);
    if env.enums.contains(short) {
        return SizeClass::Value(1);
    }
    if let Some(under) = env.value_types.get(short) {
        return type_size(under, env, depth + 1);
    }
    if let Some(members) = env.structs.get(short) {
        let inner = compute_layout_sized(members, env, depth + 1);
        return SizeClass::Slots(inner.max(1));
    }
    if let Some(decl) = env.contracts.get(short) {
        if matches!(
            decl.kind,
            ContractKind::Contract | ContractKind::Abstract | ContractKind::Interface
        ) {
            return SizeClass::Value(20); // contract/interface handles are addresses
        }
    }
    // Unknown type: assume it needs its own slot.
    SizeClass::Slots(1)
}

/// Slot count of a member list, used for struct sizing.
fn compute_layout_sized(members: &[StateVarDef], env: &TypeEnv<'_>, depth: u8) -> u64 {
    let mut slot: u64 = 0;
    let mut offset: u16 = 0;
    for m in members {
        match type_size(&m.ty, env, depth) {
            SizeClass::Value(size) => {
                if offset + size > 32 {
                    slot += 1;
                    offset = 0;
                }
                offset += size;
            }
            SizeClass::Slots(n) => {
                if offset > 0 {
                    slot += 1;
                    offset = 0;
                }
                slot += n.max(1);
            }
        }
    }
    if offset > 0 {
        slot + 1
    } else {
        slot
    }
}

/// Collapse whitespace and drop `payable` from `address payable` so two spellings of the
/// same type compare equal.
fn normalize_type(ty: &str) -> String {
    let mut out = String::with_capacity(ty.len());
    let mut prev_space = false;
    for ch in ty.trim().chars() {
        if ch.is_whitespace() {
            if !prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    let out = out.trim().to_string();
    if out == "address payable" {
        return "address".to_string();
    }
    out
}

/// Index of the `[` matching the final `]` of `t`, at bracket depth 0.
fn matching_open_bracket(t: &str) -> Option<usize> {
    let bytes = t.as_bytes();
    if bytes.last() != Some(&b']') {
        return None;
    }
    let mut depth = 0i32;
    for i in (0..bytes.len()).rev() {
        match bytes[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// =============================================================================
// Source masking
// =============================================================================

/// Source with comments and string-literal *contents* replaced by spaces, preserving
/// every byte offset and line break. Parsing against this makes it impossible to match
/// `import` or `is` inside a comment or a string.
struct Masked {
    text: String,
    /// `(byte offset of the opening quote, literal contents)`, in source order.
    strings: Vec<(usize, String)>,
}

fn mask_source(src: &str) -> Masked {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut strings: Vec<(usize, String)> = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(b' ');
            out.push(b' ');
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    break;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            let quote = b;
            let quote_at = out.len();
            out.push(quote);
            i += 1;
            let mut lit: Vec<u8> = Vec::new();
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    lit.push(bytes[i + 1]);
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    continue;
                }
                if bytes[i] == quote || bytes[i] == b'\n' {
                    break;
                }
                lit.push(bytes[i]);
                out.push(b' ');
                i += 1;
            }
            if i < bytes.len() && bytes[i] == quote {
                out.push(quote);
                i += 1;
            }
            strings.push((quote_at, String::from_utf8_lossy(&lit).into_owned()));
            continue;
        }
        out.push(b);
        i += 1;
    }

    Masked {
        text: String::from_utf8_lossy(&out).into_owned(),
        strings,
    }
}

/// Byte offset → 1-based line number, via binary search over line starts.
struct LineTable {
    starts: Vec<usize>,
}

impl LineTable {
    fn new(text: &str) -> Self {
        let mut starts = vec![0usize];
        for (i, b) in text.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        LineTable { starts }
    }

    fn line_of(&self, offset: usize) -> usize {
        match self.starts.binary_search(&offset) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }
}

// =============================================================================
// Import parsing
// =============================================================================

fn parse_imports(masked: &Masked) -> Vec<ImportDecl> {
    let text = &masked.text;
    let mut out = Vec::new();

    for m in RE_IMPORT_KW.find_iter(text) {
        let after = m.end();
        let window_end = (after + MAX_IMPORT_STMT_BYTES).min(text.len());
        let stmt_end = text[after..window_end]
            .find(';')
            .map(|i| after + i)
            .unwrap_or(window_end);

        // The path is always the first string literal after the `import` keyword.
        let Some((quote_at, raw)) = masked
            .strings
            .iter()
            .find(|(off, _)| *off >= after && *off < stmt_end)
            .cloned()
        else {
            continue;
        };

        let header = &text[after..quote_at];
        let mut aliases = Vec::new();
        if let (Some(open), Some(close)) = (header.find('{'), header.find('}')) {
            if open < close {
                for part in header[open + 1..close].split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let mut words = part.split_whitespace();
                    let original = words.next().unwrap_or_default();
                    let alias = match (words.next(), words.next()) {
                        (Some("as"), Some(a)) => a,
                        _ => original,
                    };
                    if !original.is_empty() {
                        aliases.push((alias.to_string(), original.to_string()));
                    }
                }
            }
        }

        out.push(ImportDecl {
            raw,
            resolved: None,
            aliases,
        });
    }
    out
}

// =============================================================================
// Contract / member parsing
// =============================================================================

fn parse_contracts(text: &str, lines: &LineTable) -> Vec<ContractDecl> {
    let mut out = Vec::new();
    let mut cursor = 0usize;

    while cursor < text.len() {
        let Some(caps) = RE_CONTRACT_DECL.captures_at(text, cursor) else {
            break;
        };
        let whole = caps.get(0).expect("group 0 always present");
        let keyword = caps.get(1).map(|m| m.as_str()).unwrap_or("contract");
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        cursor = whole.end();
        if name.is_empty() {
            continue;
        }

        let kind = if keyword.starts_with("abstract") {
            ContractKind::Abstract
        } else if keyword == "interface" {
            ContractKind::Interface
        } else if keyword == "library" {
            ContractKind::Library
        } else {
            ContractKind::Contract
        };

        // Everything between the name and the opening brace is the (optional) `is` list.
        let Some(rel_brace) = text[whole.end()..].find('{') else {
            continue;
        };
        let brace = whole.end() + rel_brace;
        let header = &text[whole.end()..brace];
        let bases = parse_base_list(header);

        let Some(body_end) = match_brace(text, brace) else {
            continue;
        };
        let body = &text[brace + 1..body_end];
        cursor = body_end + 1;

        let mut decl = ContractDecl {
            name: name.to_string(),
            kind,
            bases,
            modifiers: Vec::new(),
            functions: Vec::new(),
            state_vars: Vec::new(),
            events: Vec::new(),
            structs: HashMap::new(),
            enums: HashSet::new(),
            value_types: HashMap::new(),
        };
        parse_body(body, brace + 1, lines, &mut decl);
        out.push(decl);
    }
    out
}

/// `is Ownable, Pausable, ERC20("n", "s")` → `["Ownable", "Pausable", "ERC20"]`.
fn parse_base_list(header: &str) -> Vec<String> {
    let trimmed = header.trim_start();
    let Some(rest) = trimmed.strip_prefix("is") else {
        return Vec::new();
    };
    if rest
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
    {
        return Vec::new(); // `island...`, not the `is` keyword
    }

    let mut bases = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in rest.chars() {
        match ch {
            '(' => {
                depth += 1;
            }
            ')' => {
                depth -= 1;
            }
            ',' if depth == 0 => {
                push_base(&mut bases, &current);
                current.clear();
            }
            _ if depth == 0 => current.push(ch),
            _ => {}
        }
    }
    push_base(&mut bases, &current);
    bases
}

fn push_base(bases: &mut Vec<String>, raw: &str) {
    let name: String = raw
        .trim()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$' || *c == '.')
        .collect();
    if !name.is_empty() && !bases.contains(&name) {
        bases.push(name);
    }
}

/// Index of the `}` matching the `{` at `open`, or `None` if unbalanced.
fn match_brace(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// A top-level item inside a contract body: either `header;` or `header { body }`.
struct BodyItem<'a> {
    header: &'a str,
    body: Option<&'a str>,
    offset: usize,
}

/// Split a contract (or struct) body into top-level items, ignoring nested braces.
fn split_items(body: &str) -> Vec<BodyItem<'_>> {
    let bytes = body.as_bytes();
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut header_end: Option<usize> = None;

    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                depth += 1;
                if depth == 1 {
                    header_end = Some(i);
                }
            }
            b'}' => {
                depth -= 1;
                if depth <= 0 {
                    depth = 0;
                    if let Some(he) = header_end {
                        // `S public s = S({a: 1});` — a struct literal inside a statement.
                        let next = body[i + 1..].find(|c: char| !c.is_whitespace());
                        let is_statement =
                            next.is_some_and(|n| body.as_bytes()[i + 1 + n] != b'}');
                        if is_statement
                            && next.is_some_and(|n| {
                                matches!(body.as_bytes()[i + 1 + n], b';' | b')' | b',')
                            })
                        {
                            header_end = None;
                            i += 1;
                            continue;
                        }
                        items.push(BodyItem {
                            header: &body[start..he],
                            body: Some(&body[he + 1..i]),
                            offset: start,
                        });
                    }
                    start = i + 1;
                    header_end = None;
                }
            }
            b';' if depth == 0 => {
                let header = &body[start..i];
                if !header.trim().is_empty() {
                    items.push(BodyItem {
                        header,
                        body: None,
                        offset: start,
                    });
                }
                start = i + 1;
                header_end = None;
            }
            _ => {}
        }
        i += 1;
    }
    items
}

const DECL_KEYWORDS: &[&str] = &[
    "using",
    "pragma",
    "import",
    "error",
    "constructor",
    "receive",
    "fallback",
    "unchecked",
    "assembly",
];

fn parse_body(body: &str, base_offset: usize, lines: &LineTable, decl: &mut ContractDecl) {
    for item in split_items(body) {
        let header = item.header.trim();
        if header.is_empty() {
            continue;
        }
        let line = lines.line_of(base_offset + item.offset + leading_ws(item.header));
        let first = header.split(|c: char| !(c.is_alphanumeric() || c == '_')).next().unwrap_or("");

        match first {
            "modifier" => {
                if let Some(name) = ident_after_keyword(header, "modifier") {
                    let guard = classify_modifier(&name, item.body.unwrap_or(""));
                    decl.modifiers.push(ModifierDef {
                        name,
                        guard,
                        declared_in: decl.name.clone(),
                        line,
                    });
                }
            }
            "function" => {
                if let Some(f) = parse_function(header, &decl.name, line, item.body.is_none()) {
                    decl.functions.push(f);
                }
            }
            "event" => {
                if let Some(name) = ident_after_keyword(header, "event") {
                    decl.events.push(name);
                }
            }
            "struct" => {
                if let Some(name) = ident_after_keyword(header, "struct") {
                    let members = item
                        .body
                        .map(|b| parse_members(b, base_offset + item.offset, lines, &decl.name))
                        .unwrap_or_default();
                    decl.structs.insert(name, members);
                }
            }
            "enum" => {
                if let Some(name) = ident_after_keyword(header, "enum") {
                    decl.enums.insert(name);
                }
            }
            "type" => {
                // `type Price is uint128;`
                if let Some(name) = ident_after_keyword(header, "type") {
                    if let Some(idx) = header.find(" is ") {
                        let under = header[idx + 4..].trim().to_string();
                        if !under.is_empty() {
                            decl.value_types.insert(name, under);
                        }
                    }
                }
            }
            k if DECL_KEYWORDS.contains(&k) => {}
            _ => {
                if item.body.is_none() {
                    if let Some(v) = parse_state_var(header, &decl.name, line) {
                        decl.state_vars.push(v);
                    }
                }
            }
        }
    }
}

fn parse_members(
    body: &str,
    base_offset: usize,
    lines: &LineTable,
    owner: &str,
) -> Vec<StateVarDef> {
    split_items(body)
        .into_iter()
        .filter(|i| i.body.is_none())
        .filter_map(|i| {
            let line = lines.line_of(base_offset + i.offset);
            parse_state_var(i.header.trim(), owner, line)
        })
        .collect()
}

fn leading_ws(s: &str) -> usize {
    s.len() - s.trim_start().len()
}

fn ident_after_keyword(header: &str, keyword: &str) -> Option<String> {
    let rest = header.strip_prefix(keyword)?;
    let rest = rest.trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

const FUNCTION_ATTR_KEYWORDS: &[&str] = &[
    "public",
    "private",
    "internal",
    "external",
    "view",
    "pure",
    "payable",
    "virtual",
    "override",
    "constant",
    "immutable",
    "returns",
    "memory",
    "calldata",
    "storage",
];

fn parse_function(
    header: &str,
    owner: &str,
    line: usize,
    is_signature_only: bool,
) -> Option<FunctionDef> {
    let rest = header.strip_prefix("function")?.trim_start();
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect();
    let after_name = &rest[name.len()..];
    let open = after_name.find('(')?;
    let close = matching_paren(after_name, open)?;
    let attrs = &after_name[close + 1..];

    // Drop the `returns (...)` clause so its types are not read as modifiers.
    let attrs = match attrs.find("returns") {
        Some(idx) => {
            let head = &attrs[..idx];
            let tail = attrs[idx..]
                .find('(')
                .and_then(|o| matching_paren(&attrs[idx..], o).map(|c| &attrs[idx + c + 1..]))
                .unwrap_or("");
            format!("{head} {tail}")
        }
        None => attrs.to_string(),
    };

    let mut visibility = String::new();
    let mut mutability = String::from("nonpayable");
    let mut modifiers = Vec::new();
    for token in attribute_tokens(&attrs) {
        match token.as_str() {
            "public" | "private" | "internal" | "external" => visibility = token,
            "view" | "pure" | "payable" => mutability = token,
            "virtual" | "override" => {}
            _ => {
                if !FUNCTION_ATTR_KEYWORDS.contains(&token.as_str()) {
                    modifiers.push(token);
                }
            }
        }
    }

    Some(FunctionDef {
        name: if name.is_empty() {
            "<anonymous>".to_string()
        } else {
            name
        },
        visibility,
        mutability,
        modifiers,
        is_signature_only,
        declared_in: owner.to_string(),
        line,
    })
}

/// Identifiers in an attribute list, skipping any `(...)` argument groups
/// (`onlyRole(ADMIN)` yields `onlyRole`).
fn attribute_tokens(attrs: &str) -> Vec<String> {
    let bytes = attrs.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            out.push(attrs[start..i].to_string());
            // Skip an argument list attached to this identifier.
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'(' {
                if let Some(close) = matching_paren(attrs, j) {
                    i = close + 1;
                }
            }
            continue;
        }
        i += 1;
    }
    out
}

fn matching_paren(s: &str, open: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

const VAR_QUALIFIERS: &[&str] = &[
    "public",
    "private",
    "internal",
    "external",
    "constant",
    "immutable",
    "transient",
    "override",
];

fn parse_state_var(header: &str, owner: &str, line: usize) -> Option<StateVarDef> {
    // Drop the initializer at paren depth 0, being careful not to split on `=>`/`==`.
    let decl_part = match split_at_assignment(header) {
        Some(idx) => &header[..idx],
        None => header,
    };
    let decl_part = decl_part.trim();
    if decl_part.is_empty() {
        return None;
    }

    let tokens = split_type_tokens(decl_part);
    if tokens.len() < 2 {
        return None;
    }
    let name = tokens.last()?.clone();
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
    {
        return None;
    }
    if VAR_QUALIFIERS.contains(&name.as_str()) {
        return None;
    }

    let mut mutability = VarMutability::Mutable;
    let mut visibility = String::new();
    let mut ty_parts: Vec<String> = Vec::new();
    for tok in &tokens[..tokens.len() - 1] {
        match tok.as_str() {
            "constant" => mutability = VarMutability::Constant,
            "immutable" => mutability = VarMutability::Immutable,
            "transient" => mutability = VarMutability::Transient,
            "public" | "private" | "internal" | "external" => visibility = tok.clone(),
            "override" => {}
            _ => ty_parts.push(tok.clone()),
        }
    }
    if ty_parts.is_empty() {
        return None;
    }
    let ty = normalize_type(&ty_parts.join(" "));
    // A bare `function` type or a leftover keyword is not a state variable.
    if ty == "return" || ty == "emit" || ty == "revert" {
        return None;
    }

    Some(StateVarDef {
        name,
        ty,
        mutability,
        visibility,
        declared_in: owner.to_string(),
        line,
    })
}

/// Byte index of a top-level `=` that is a real assignment (not `=>`, `==`, `>=`, ...).
fn split_at_assignment(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'=' if depth == 0 => {
                let next = bytes.get(i + 1).copied();
                let prev = if i > 0 { Some(bytes[i - 1]) } else { None };
                let is_compare = next == Some(b'=')
                    || next == Some(b'>')
                    || matches!(prev, Some(b'=') | Some(b'!') | Some(b'<') | Some(b'>'));
                if !is_compare {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a declaration into tokens, keeping `mapping(a => b)` and `uint[2]` intact.
fn split_type_tokens(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' => {
                depth += 1;
                cur.push(b as char);
            }
            b')' | b']' => {
                depth -= 1;
                cur.push(b as char);
                if depth == 0 {
                    // Keep a trailing `[]`/`[N]` glued to the type it qualifies.
                    let following_is_space = bytes
                        .get(i + 1)
                        .is_none_or(|c| c.is_ascii_whitespace());
                    if following_is_space && b == b')' {
                        out.push(std::mem::take(&mut cur));
                    }
                }
            }
            _ if b.is_ascii_whitespace() && depth == 0 => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(b as char),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.retain(|t| !t.is_empty());
    out
}

// =============================================================================
// Modifier guard classification
// =============================================================================

const AUTH_TOKENS: &[&str] = &[
    "msg.sender",
    "_msgSender()",
    "_checkOwner",
    "_checkRole",
    "_checkCanCall",
    "hasRole",
    "owner()",
    "_owner",
    "isAuthorized",
    "isOwner",
    "tx.origin",
    "governance",
    "_authority",
    "authority()",
];

const GUARD_CONSTRUCTS: &[&str] = &["require", "revert", "assert", "if", "_check"];

const LOCK_TOKENS: &[&str] = &[
    "_status",
    "_reentrancy",
    "_nonReentrantBefore",
    "_entered",
    "locked",
    "_locked",
    "unlocked",
    "NOT_ENTERED",
    "_ENTERED",
];

fn classify_modifier(name: &str, body: &str) -> GuardKind {
    let lower_name = name.to_ascii_lowercase();

    if lower_name.contains("nonreentrant")
        || lower_name == "lock"
        || lower_name.contains("noreentrancy")
        || LOCK_TOKENS.iter().any(|t| body.contains(t))
    {
        return GuardKind::ReentrancyGuard;
    }
    if lower_name.starts_with("wheninitializ")
        || lower_name == "initializer"
        || lower_name == "reinitializer"
        || lower_name == "onlyinitializing"
    {
        return GuardKind::Initializer;
    }
    if lower_name.contains("paused") || body.contains("paused()") || body.contains("_paused") {
        return GuardKind::Pause;
    }

    let has_auth = AUTH_TOKENS.iter().any(|t| body.contains(t));
    let has_guard = GUARD_CONSTRUCTS.iter().any(|t| body.contains(t));
    if has_auth && has_guard {
        return GuardKind::AccessControl;
    }
    // Name-based fallback for `onlyX` modifiers whose body delegates to a helper.
    if lower_name.starts_with("only") || lower_name.contains("auth") || lower_name == "restricted" {
        return GuardKind::AccessControl;
    }
    GuardKind::Other
}

// =============================================================================
// Paths, roots and remappings
// =============================================================================

fn read_source(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_SOURCE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn canonical_or_lexical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| {
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(p)
        };
        normalize_lexical(&abs)
    })
}

fn normalize_lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

const ROOT_MARKERS: &[&str] = &[
    "foundry.toml",
    "remappings.txt",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
    "package.json",
    ".git",
];

/// The project root [`ProjectIndex::for_file`] would choose for `file`.
///
/// Exposed separately so a caller can key its own per-root index cache (one
/// `ProjectIndex` per scan root, reused across every file under it) without building an
/// index — which would re-read `remappings.txt` / `foundry.toml` on every file.
pub(crate) fn root_for(file: &Path) -> PathBuf {
    infer_root(file)
}

fn infer_root(file: &Path) -> PathBuf {
    let start = canonical_or_lexical(file);
    let mut dir = if start.is_dir() {
        Some(start.as_path())
    } else {
        start.parent()
    };
    let first = dir.map(Path::to_path_buf);
    let mut hops = 0usize;
    while let Some(d) = dir {
        if ROOT_MARKERS.iter().any(|m| d.join(m).exists()) {
            return d.to_path_buf();
        }
        hops += 1;
        if hops > MAX_IMPORT_DEPTH {
            break;
        }
        dir = d.parent();
    }
    first.unwrap_or_else(|| PathBuf::from("."))
}

/// `@openzeppelin/contracts/access/Ownable.sol` → `("@openzeppelin/contracts", Some("access/Ownable.sol"))`
/// for scoped packages, `("forge-std", Some("src/Test.sol"))` otherwise.
fn split_package(raw: &str) -> (&str, Option<&str>) {
    let mut parts = raw.splitn(3, '/');
    let first = parts.next().unwrap_or(raw);
    if first.starts_with('@') {
        let Some(second) = parts.next() else {
            return (raw, None);
        };
        let pkg_len = first.len() + 1 + second.len();
        let rest = raw.get(pkg_len + 1..).filter(|s| !s.is_empty());
        (&raw[..pkg_len], rest)
    } else {
        let rest = raw.get(first.len() + 1..).filter(|s| !s.is_empty());
        (first, rest)
    }
}

fn load_remappings(root: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    if let Ok(text) = std::fs::read_to_string(root.join("remappings.txt")) {
        for line in text.lines() {
            push_remapping(&mut out, line);
        }
    }

    if let Ok(text) = std::fs::read_to_string(root.join("foundry.toml")) {
        if let Ok(value) = text.parse::<toml::Value>() {
            collect_toml_remappings(&value, &mut out, 0);
        }
    }

    // Conventional defaults, appended so an explicit remapping always wins.
    for (prefix, target) in [
        ("@openzeppelin/contracts-upgradeable/", "lib/openzeppelin-contracts-upgradeable/contracts/"),
        ("@openzeppelin/contracts/", "lib/openzeppelin-contracts/contracts/"),
        ("@openzeppelin/", "node_modules/@openzeppelin/"),
        ("forge-std/", "lib/forge-std/src/"),
        ("solmate/", "lib/solmate/src/"),
        ("solady/", "lib/solady/src/"),
        ("ds-test/", "lib/forge-std/lib/ds-test/src/"),
    ] {
        out.push((prefix.to_string(), target.to_string()));
    }

    // Longest prefix first so `@openzeppelin/contracts/` beats `@openzeppelin/`.
    out.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
    out
}

fn push_remapping(out: &mut Vec<(String, String)>, line: &str) {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return;
    }
    // Foundry allows a `context:` prefix; the prefix itself is the last `=`-separated key.
    let Some((prefix, target)) = line.split_once('=') else {
        return;
    };
    let prefix = prefix.rsplit(':').next().unwrap_or(prefix).trim();
    let target = target.trim();
    if prefix.is_empty() || target.is_empty() {
        return;
    }
    if !out.iter().any(|(p, _)| p == prefix) {
        out.push((prefix.to_string(), target.to_string()));
    }
}

fn collect_toml_remappings(value: &toml::Value, out: &mut Vec<(String, String)>, depth: u8) {
    if depth > 4 {
        return;
    }
    match value {
        toml::Value::Table(table) => {
            for (key, v) in table {
                if key == "remappings" {
                    if let Some(arr) = v.as_array() {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                push_remapping(out, s);
                            }
                        }
                    }
                } else {
                    collect_toml_remappings(v, out, depth + 1);
                }
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                collect_toml_remappings(item, out, depth + 1);
            }
        }
        _ => {}
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> PathBuf {
        // `INHERITANCE_FIXTURES` lets the module be tested from outside this crate
        // (useful while other parts of the tree are mid-refactor and will not compile).
        match std::env::var_os("INHERITANCE_FIXTURES") {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts/inheritance"),
        }
    }

    fn index_for(project: &str) -> (ProjectIndex, PathBuf) {
        let root = fixtures().join(project);
        (ProjectIndex::for_root(&root), root)
    }

    // ---- 1. simple linear chain ----------------------------------------

    #[test]
    fn linear_chain_across_files() {
        let (index, root) = index_for("linear");
        let resolved = index.resolve(root.join("src/Child.sol"));
        let child = resolved.contract("Child").expect("Child resolved");
        assert_eq!(child.linearization, vec!["Child", "Middle", "Base"]);
        assert!(child.has_modifier("onlyBase"), "{:?}", child.modifiers);
        assert!(child.has_modifier("onlyMiddle"));
        assert!(child.has_access_control_modifier("onlyBase"));
        // Functions from every level are visible.
        let names: Vec<&str> = child.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"baseFn"), "{names:?}");
        assert!(names.contains(&"middleFn"), "{names:?}");
    }

    // ---- 2. diamond ----------------------------------------------------

    #[test]
    fn diamond_c3_order() {
        let (index, root) = index_for("diamond");
        let resolved = index.resolve(root.join("Diamond.sol"));
        let d = resolved.contract("D").expect("D resolved");
        // Solidity: contract D is B, C  =>  D, C, B, A
        assert_eq!(d.linearization, vec!["D", "C", "B", "A"]);
        assert!(d.diagnostics.is_empty(), "{:?}", d.diagnostics);
    }

    // ---- 3. cycles do not hang -----------------------------------------

    #[test]
    fn inheritance_cycle_terminates() {
        let (index, root) = index_for("cycles");
        let resolved = index.resolve(root.join("Cycle.sol"));
        let a = resolved.contract("A").expect("A resolved");
        assert!(
            a.diagnostics.iter().any(|d| d.contains("cycle")),
            "expected a cycle diagnostic, got {:?}",
            a.diagnostics
        );
        assert!(a.linearization.len() < 10);
    }

    #[test]
    fn import_cycle_and_self_import_terminate() {
        let (index, root) = index_for("cycles");
        // ImportA imports ImportB imports ImportA; SelfImport imports itself.
        let a = index.resolve(root.join("ImportA.sol"));
        assert!(a.contract("ImportA").is_some());
        let s = index.resolve(root.join("SelfImport.sol"));
        assert!(s.contract("SelfImport").is_some());
    }

    // ---- 4. remapping resolution + the access-control FP ----------------

    #[test]
    fn vault_is_ownable_resolves_onlyowner_through_remapping() {
        let (index, root) = index_for("foundry");
        let resolved = index.resolve(root.join("src/Vault.sol"));
        let vault = resolved.contract("Vault").expect("Vault resolved");
        assert_eq!(
            vault.linearization,
            vec!["Vault", "ReentrancyGuard", "Ownable", "Context"],
            "diagnostics: {:?}",
            vault.diagnostics
        );
        // The FP this module exists to kill:
        assert!(
            vault.has_access_control_modifier("onlyOwner"),
            "onlyOwner not resolved: {:?}",
            vault.modifier_names().collect::<Vec<_>>()
        );
        assert!(vault.has_reentrancy_guard());
        assert!(vault.has_modifier("nonReentrant"));
        assert!(vault.unresolved_bases.is_empty(), "{:?}", vault.unresolved_bases);
        // File-level query used on the scanner's hot path.
        assert!(resolved.has_access_control_modifier("onlyOwner"));
        assert!(resolved.has_reentrancy_guard());
        assert!(resolved.modifier_names().contains(&"onlyOwner".to_string()));
        assert!(vault.inherits_from("Ownable"));
    }

    #[test]
    fn unvendored_base_falls_back_to_builtin_table() {
        let (index, root) = index_for("unvendored");
        let resolved = index.resolve(root.join("Bare.sol"));
        let c = resolved.contract("Bare").expect("Bare resolved");
        assert!(c.has_access_control_modifier("onlyOwner"));
        assert!(c.has_modifier("nonReentrant"));
        assert!(c.has_reentrancy_guard());
    }

    /// Reads every field the scanner integration is expected to consume, so the
    /// crate-facing surface is exercised end to end and stays warning-free.
    #[test]
    fn full_api_surface_is_populated() {
        let (index, root) = index_for("foundry");
        let resolved = index.resolve(root.join("src/Vault.sol"));
        assert!(resolved.diagnostics.is_empty(), "{:?}", resolved.diagnostics);
        assert!(resolved.has_modifier("onlyOwner"));
        assert!(!resolved.has_modifier("definitelyNotAModifier"));

        let vault = resolved.contract("Vault").expect("Vault resolved");
        assert_eq!(vault.kind, ContractKind::Contract);

        // Declarations are collected most-base-first: Context (none), Ownable,
        // ReentrancyGuard, then Vault itself.
        let names: Vec<&str> = vault
            .state_variables
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["_owner", "NOT_ENTERED", "ENTERED", "_status", "deposits"],
            "{names:?}"
        );
        let owner_var = &vault.state_variables[0];
        assert_eq!(owner_var.declared_in, "Ownable");
        assert_eq!(owner_var.visibility, "private");
        assert_eq!(owner_var.mutability, VarMutability::Mutable);
        assert!(owner_var.line > 0);

        // The two `private constant`s occupy no slot, so the layout is exactly
        // `_owner` (address, slot 0), `_status` (uint256, slot 1), `deposits` (slot 2).
        let laid_out: Vec<&str> = vault
            .storage
            .slots
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(laid_out, vec!["_owner", "_status", "deposits"], "{laid_out:?}");
        assert_eq!(vault.storage.total_slots, 3);
        assert_eq!(vault.storage.slots[0].size, 20);
        assert_eq!(vault.storage.slots[0].ty, "address");
        assert_eq!(vault.storage.slots[0].declared_in, "Ownable");

        // Events are inherited too.
        assert_eq!(vault.events, vec!["OwnershipTransferred".to_string()]);

        // Modifier + function metadata.
        let m = vault
            .modifiers
            .iter()
            .find(|m| m.name == "onlyOwner")
            .expect("onlyOwner");
        assert_eq!(m.guard, GuardKind::AccessControl);
        assert_eq!(m.declared_in, "Ownable");
        assert!(m.line > 0);

        let f = vault
            .functions
            .iter()
            .find(|f| f.name == "sweep")
            .expect("sweep");
        assert_eq!(f.visibility, "external");
        assert_eq!(f.mutability, "nonpayable");
        assert_eq!(f.modifiers, vec!["onlyOwner".to_string()]);
        assert!(!f.is_signature_only);
        assert!(f.line > 0);
    }

    // ---- 5. path escape rejection --------------------------------------

    #[test]
    fn import_escaping_root_is_rejected() {
        let (index, root) = index_for("escape");
        // The file it tries to import genuinely exists, one level above the root.
        assert!(fixtures().join("secret/Leak.sol").is_file());
        let resolved = index.resolve(root.join("Escaper.sol"));
        let c = resolved.contract("Escaper").expect("Escaper resolved");
        // `Leaked` must NOT have been resolved: the base stays unknown.
        assert!(
            c.unresolved_bases.contains(&"Leaked".to_string()),
            "path escape was followed: {:?}",
            c.unresolved_bases
        );
        assert!(!c.has_modifier("leakedModifier"));
    }

    #[test]
    fn accept_rejects_paths_outside_root() {
        let (index, _root) = index_for("escape");
        assert!(index.accept(Path::new("/etc/passwd")).is_none());
        assert!(index.root().is_absolute());
    }

    // ---- 6. storage packing --------------------------------------------

    #[test]
    fn storage_packing_matches_solc_rules() {
        let (index, root) = index_for("storage");
        let resolved = index.resolve(root.join("Layout.sol"));
        let c = resolved.contract("Layout").expect("Layout resolved");
        let at = |name: &str| {
            c.storage
                .slots
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("{name} missing from {:?}", c.storage.slots))
        };
        // bool(1) + uint8(1) + address(20) = 22 bytes, all in slot 0.
        assert_eq!((at("flag").slot, at("flag").offset), (0, 0));
        assert_eq!((at("small").slot, at("small").offset), (0, 1));
        assert_eq!((at("owner").slot, at("owner").offset), (0, 2));
        // uint256 no longer fits in slot 0.
        assert_eq!((at("total").slot, at("total").offset), (1, 0));
        // A mapping always takes a fresh whole slot.
        assert_eq!((at("balances").slot, at("balances").offset), (2, 0));
        // ...and forces the next variable onto a new slot even though it would fit.
        assert_eq!((at("tail").slot, at("tail").offset), (3, 0));
        // constant/immutable consume nothing.
        assert!(c.storage.slots.iter().all(|s| s.name != "MAX"));
        assert!(c.storage.slots.iter().all(|s| s.name != "deployer"));
    }

    #[test]
    fn proxy_implementation_collision_is_detected() {
        let (index, root) = index_for("storage");
        let resolved = index.resolve(root.join("Proxy.sol"));
        let proxy = resolved.contract("MyProxy").expect("MyProxy resolved");
        let impl_c = resolved.contract("MyImpl").expect("MyImpl resolved");
        let collisions = proxy.storage.collisions_with(&impl_c.storage);
        let slot0 = collisions
            .iter()
            .find(|c| c.slot == 0)
            .unwrap_or_else(|| panic!("no slot-0 collision found: {collisions:?}"));
        assert_eq!(slot0.offset, 0);
        assert!(slot0.reason.contains("storage collision"));
        assert!(slot0.left.contains("implementation"), "{}", slot0.left);
        assert!(slot0.right.contains("totalSupply"), "{}", slot0.right);
        // Identical layouts must produce no findings.
        assert!(proxy.storage.collisions_with(&proxy.storage).is_empty());
    }

    // ---- 7. override shadowing -----------------------------------------

    #[test]
    fn override_shadows_base_definition() {
        let (index, root) = index_for("shadow");
        let resolved = index.resolve(root.join("Shadow.sol"));
        let d = resolved.contract("Derived").expect("Derived resolved");
        let m = d
            .modifiers
            .iter()
            .find(|m| m.name == "guard")
            .expect("guard modifier");
        assert_eq!(m.declared_in, "Derived", "base definition won the override");
        let f = d
            .functions
            .iter()
            .find(|f| f.name == "value")
            .expect("value fn");
        assert_eq!(f.declared_in, "Derived");
        assert_eq!(f.visibility, "public");
    }

    // ---- 8. hostile / malformed input ----------------------------------

    #[test]
    fn comments_and_strings_are_not_parsed() {
        let (index, root) = index_for("tricky");
        let resolved = index.resolve(root.join("Tricky.sol"));
        // `import "./Ghost.sol";` inside a comment and inside a string must be ignored,
        // and `contract Commented is Ghost` inside a block comment must not appear.
        assert!(resolved.contract("Commented").is_none());
        let real = resolved.contract("Real").expect("Real resolved");
        assert_eq!(real.linearization, vec!["Real"]);
        assert!(!real.has_modifier("ghostModifier"));
    }

    #[test]
    fn base_defined_later_in_same_file() {
        let (index, root) = index_for("tricky");
        let resolved = index.resolve(root.join("ForwardRef.sol"));
        let d = resolved.contract("UsesLater").expect("UsesLater resolved");
        assert_eq!(d.linearization, vec!["UsesLater", "DefinedLater"]);
        assert!(d.has_access_control_modifier("onlyLater"));
    }

    #[test]
    fn missing_empty_and_binary_files_are_safe() {
        let (index, root) = index_for("tricky");
        assert!(index.resolve(root.join("DoesNotExist.sol")).is_empty());
        assert!(index.resolve(root.join("Empty.sol")).is_empty());
        // A directory, not a file.
        assert!(index.resolve(&root).is_empty());
    }

    #[test]
    fn crlf_and_missing_trailing_newline_parse() {
        let (index, root) = index_for("tricky");
        let resolved = index.resolve(root.join("Crlf.sol"));
        let c = resolved.contract("Crlf").expect("Crlf resolved");
        assert!(c.has_access_control_modifier("onlyCrlf"));
    }

    #[test]
    fn deep_chain_is_bounded() {
        // A chain far deeper than MAX_INHERIT_DEPTH. Declared most-derived first so the
        // deepest contract is linearized before memoization can shorten the walk — the
        // worst case for recursion depth.
        let mut src = String::from("// SPDX-License-Identifier: MIT\n");
        for i in (0..400).rev() {
            if i == 0 {
                src.push_str(
                    "contract C0 { modifier onlyC0() { require(msg.sender == address(0)); _; } }\n",
                );
            } else {
                src.push_str(&format!("contract C{i} is C{} {{ }}\n", i - 1));
            }
        }
        let dir = scratch_dir("deep");
        let file = dir.join("Deep.sol");
        std::fs::write(&file, src).expect("write deep fixture");
        let index = ProjectIndex::for_root(&dir);
        let resolved = index.resolve(&file);
        let last = resolved.contract("C399").expect("C399 resolved");
        assert!(last.linearization.len() <= MAX_INHERIT_DEPTH + 2);
        assert!(last.diagnostics.iter().any(|d| d.contains("depth limit")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unbalanced_braces_do_not_panic() {
        let dir = scratch_dir("unbalanced");
        let file = dir.join("Bad.sol");
        std::fs::write(&file, "contract A is B { function f() public { /* never closed\n").unwrap();
        let index = ProjectIndex::for_root(&dir);
        let _ = index.resolve(&file);
        std::fs::write(&file, "contract").unwrap();
        let index2 = ProjectIndex::for_root(&dir);
        let _ = index2.resolve(&file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "41swara-inh-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    /// Perf harness, not part of the normal suite. Point `INHERITANCE_BENCH_DIR` at a
    /// Solidity project and run:
    /// `cargo test --lib inheritance::tests::bench -- --ignored --nocapture`
    #[test]
    #[ignore = "benchmark; needs INHERITANCE_BENCH_DIR"]
    fn bench_project_index() {
        let Some(dir) = std::env::var_os("INHERITANCE_BENCH_DIR") else {
            return;
        };
        let root = PathBuf::from(dir);
        let files: Vec<PathBuf> = walkdir::WalkDir::new(&root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "sol"))
            .map(|e| e.path().to_path_buf())
            .collect();

        let t0 = std::time::Instant::now();
        let index = ProjectIndex::for_root(&root);
        let build = t0.elapsed();

        let t1 = std::time::Instant::now();
        let mut contracts = 0usize;
        let mut modifiers = 0usize;
        for f in &files {
            let r = index.resolve(f);
            contracts += r.contracts.len();
            modifiers += r.modifier_names().len();
        }
        let cold = t1.elapsed();

        let t2 = std::time::Instant::now();
        for f in &files {
            let _ = index.resolve(f);
        }
        let warm = t2.elapsed();

        eprintln!(
            "files={} contracts={} modifier-names={}\n  index build : {:?}\n  cold resolve: {:?} ({:?}/file)\n  warm resolve: {:?} ({:?}/file)",
            files.len(),
            contracts,
            modifiers,
            build,
            cold,
            cold / files.len().max(1) as u32,
            warm,
            warm / files.len().max(1) as u32,
        );
    }

    // ---- 9. unit-level helpers -----------------------------------------

    #[test]
    fn c3_merge_detects_inconsistent_hierarchy() {
        let seqs = vec![
            VecDeque::from(vec!["A".to_string(), "B".to_string()]),
            VecDeque::from(vec!["B".to_string(), "A".to_string()]),
        ];
        assert!(c3_merge(seqs).is_none());
    }

    #[test]
    fn masking_blanks_comments_and_string_bodies() {
        let src = "contract A { string s = \"import \\\"x.sol\\\";\"; } // contract B is A\n";
        let masked = mask_source(src);
        assert_eq!(masked.text.len(), src.len(), "offsets must be preserved");
        assert!(!masked.text.contains("import"));
        assert!(!masked.text.contains("contract B"));
        assert!(masked.text.contains("contract A"));
    }

    #[test]
    fn split_package_handles_scopes() {
        assert_eq!(
            split_package("@openzeppelin/contracts/access/Ownable.sol"),
            ("@openzeppelin/contracts", Some("access/Ownable.sol"))
        );
        assert_eq!(split_package("forge-std/Test.sol"), ("forge-std", Some("Test.sol")));
        assert_eq!(split_package("Bare.sol"), ("Bare.sol", None));
    }

    #[test]
    fn state_var_parsing() {
        let v = parse_state_var("mapping(address => uint256) public balances", "X", 1).unwrap();
        assert_eq!(v.name, "balances");
        assert_eq!(v.ty, "mapping(address => uint256)");
        assert_eq!(v.mutability, VarMutability::Mutable);

        let v = parse_state_var("uint256 public constant MAX", "X", 1).unwrap();
        assert_eq!(v.mutability, VarMutability::Constant);
        assert!(!v.mutability.occupies_storage());

        let v = parse_state_var("address payable immutable treasury", "X", 1).unwrap();
        assert_eq!(v.ty, "address");
        assert_eq!(v.mutability, VarMutability::Immutable);
    }

    #[test]
    fn function_parsing_extracts_modifiers_not_return_types() {
        let f = parse_function(
            "function f(uint256 a) public payable onlyRole(ADMIN) virtual override returns (bool ok)",
            "X",
            3,
            false,
        )
        .unwrap();
        assert_eq!(f.name, "f");
        assert_eq!(f.visibility, "public");
        assert_eq!(f.mutability, "payable");
        assert_eq!(f.modifiers, vec!["onlyRole".to_string()]);
        assert!(!f.is_signature_only);
    }

    #[test]
    fn modifier_classification() {
        assert_eq!(
            classify_modifier("onlyOwner", "{ require(msg.sender == _owner); _; }"),
            GuardKind::AccessControl
        );
        assert_eq!(
            classify_modifier("nonReentrant", "{ require(_status != _ENTERED); _; }"),
            GuardKind::ReentrancyGuard
        );
        assert_eq!(
            classify_modifier("whenNotPaused", "{ require(!_paused); _; }"),
            GuardKind::Pause
        );
        assert_eq!(
            classify_modifier("validAmount", "{ require(amount > 0); _; }"),
            GuardKind::Other
        );
        assert!(GuardKind::AccessControl.restricts_callers());
        assert!(!GuardKind::Other.restricts_callers());
    }

    #[test]
    fn resolve_is_cached() {
        let (index, root) = index_for("linear");
        let a = index.resolve(root.join("src/Child.sol"));
        let b = index.resolve(root.join("src/Child.sol"));
        assert!(Arc::ptr_eq(&a, &b), "resolve() must be memoized");
        assert!(a.primary().is_some());
        assert_eq!(a.path, canonical_or_lexical(&root.join("src/Child.sol")));
    }

    #[test]
    fn for_file_infers_project_root() {
        let root = fixtures().join("foundry");
        let index = ProjectIndex::for_file(root.join("src/Vault.sol"));
        assert_eq!(index.root(), canonical_or_lexical(&root).as_path());
        // `root_for` must agree with `for_file` — the scanner keys its index cache on it.
        assert_eq!(
            canonical_or_lexical(&root_for(&root.join("src/Vault.sol"))),
            canonical_or_lexical(&root)
        );
    }

    #[test]
    fn contract_kind_storage_contribution() {
        assert!(ContractKind::Contract.contributes_storage());
        assert!(ContractKind::Abstract.contributes_storage());
        assert!(!ContractKind::Interface.contributes_storage());
        assert!(!ContractKind::Library.contributes_storage());
    }
}
