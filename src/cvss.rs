//! CVSS 3.1 Base Score Calculator for Smart Contract Vulnerabilities.
//!
//! Implements the official CVSS 3.1 base scoring formula and provides
//! a static mapping from `VulnerabilityCategory` to default CVSS vectors.
//!
//! Smart contract context:
//! - **AV** = Network always (public blockchain)
//! - **C** = None usually (on-chain data is public)
//! - **I** / **A** = primary impact axes (state/funds)

use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory, VulnerabilitySeverity};

#[derive(Debug, Clone, Copy)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Copy)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Copy)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Copy)]
pub enum Scope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy)]
pub enum Impact {
    None,
    Low,
    High,
}

/// Full CVSS 3.1 base metric vector.
#[derive(Debug, Clone)]
pub struct CvssVector {
    pub av: AttackVector,
    pub ac: AttackComplexity,
    pub pr: PrivilegesRequired,
    pub ui: UserInteraction,
    pub s: Scope,
    pub c: Impact,
    pub i: Impact,
    pub a: Impact,
}

// Shorthand constructors for common patterns to keep the mapping table readable.
impl CvssVector {
    /// AV:N/AC:L/PR:N/UI:N/S:C — Critical: scope-changed, no barriers
    fn nlc(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network,
            ac: AttackComplexity::Low,
            pr: PrivilegesRequired::None,
            ui: UserInteraction::None,
            s: Scope::Changed,
            c: Impact::None,
            i,
            a,
        }
    }
    /// AV:N/AC:H/PR:N/UI:N/S:C — Critical but complex
    fn nhc(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network,
            ac: AttackComplexity::High,
            pr: PrivilegesRequired::None,
            ui: UserInteraction::None,
            s: Scope::Changed,
            c: Impact::None,
            i,
            a,
        }
    }
    /// AV:N/AC:L/PR:N/UI:N/S:U — High: scope-unchanged, no barriers
    fn nlu(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network,
            ac: AttackComplexity::Low,
            pr: PrivilegesRequired::None,
            ui: UserInteraction::None,
            s: Scope::Unchanged,
            c: Impact::None,
            i,
            a,
        }
    }
    /// AV:N/AC:H/PR:N/UI:N/S:U — Medium: scope-unchanged, complex
    fn nhu(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network,
            ac: AttackComplexity::High,
            pr: PrivilegesRequired::None,
            ui: UserInteraction::None,
            s: Scope::Unchanged,
            c: Impact::None,
            i,
            a,
        }
    }
    /// Zero-impact vector (informational findings)
    fn zero() -> Self {
        Self::nhu(Impact::None, Impact::None)
    }
}

impl CvssVector {
    /// Calculate the CVSS 3.1 base score using the official formula.
    pub fn calculate_base_score(&self) -> f64 {
        let iss = self.impact_sub_score();
        if iss <= 0.0 {
            return 0.0;
        }

        let exploitability = self.exploitability_sub_score();
        let scope_changed = matches!(self.s, Scope::Changed);

        let impact = if scope_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02).powf(13.0)
        } else {
            6.42 * iss
        };

        if impact <= 0.0 {
            return 0.0;
        }

        if scope_changed {
            roundup((1.08 * (impact + exploitability)).min(10.0))
        } else {
            roundup((impact + exploitability).min(10.0))
        }
    }

    /// Generate the CVSS 3.1 vector string.
    pub fn to_vector_string(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            match self.av {
                AttackVector::Network => "N",
                AttackVector::Adjacent => "A",
                AttackVector::Local => "L",
                AttackVector::Physical => "P",
            },
            match self.ac {
                AttackComplexity::Low => "L",
                AttackComplexity::High => "H",
            },
            match self.pr {
                PrivilegesRequired::None => "N",
                PrivilegesRequired::Low => "L",
                PrivilegesRequired::High => "H",
            },
            match self.ui {
                UserInteraction::None => "N",
                UserInteraction::Required => "R",
            },
            match self.s {
                Scope::Unchanged => "U",
                Scope::Changed => "C",
            },
            match self.c {
                Impact::None => "N",
                Impact::Low => "L",
                Impact::High => "H",
            },
            match self.i {
                Impact::None => "N",
                Impact::Low => "L",
                Impact::High => "H",
            },
            match self.a {
                Impact::None => "N",
                Impact::Low => "L",
                Impact::High => "H",
            },
        )
    }

    fn impact_sub_score(&self) -> f64 {
        let c = impact_value(self.c);
        let i = impact_value(self.i);
        let a = impact_value(self.a);
        1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    }

    fn exploitability_sub_score(&self) -> f64 {
        let av = match self.av {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.20,
        };
        let ac = match self.ac {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        };
        let pr = match (self.pr, matches!(self.s, Scope::Changed)) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, false) => 0.62,
            (PrivilegesRequired::Low, true) => 0.68,
            (PrivilegesRequired::High, false) => 0.27,
            (PrivilegesRequired::High, true) => 0.50,
        };
        let ui = match self.ui {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        };
        8.22 * av * ac * pr * ui
    }
}

fn impact_value(i: Impact) -> f64 {
    match i {
        Impact::None => 0.0,
        Impact::Low => 0.22,
        Impact::High => 0.56,
    }
}

/// CVSS 3.1 roundup: round to nearest tenth, always up.
fn roundup(val: f64) -> f64 {
    let int_input = (val * 100_000.0).round() as i64;
    if int_input % 10000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10000) + 1) as f64 / 10.0
    }
}

/// Map a `VulnerabilityCategory` to its default CVSS 3.1 vector.
///
/// Returns `None` for categories without an explicit vector. Callers should
/// fall back to [`severity_to_cvss`] in that case so a finding's CVSS (and the
/// risk ranking derived from it) always tracks its severity instead of silently
/// collapsing every unmapped category to a flat Medium score.
pub fn category_to_cvss(category: &VulnerabilityCategory) -> Option<CvssVector> {
    use Impact::{High as HI, Low as LO};

    let vector = match category {
        // === Critical: Direct fund theft / total contract compromise ===
        VulnerabilityCategory::Reentrancy
        | VulnerabilityCategory::CallbackReentrancy
        | VulnerabilityCategory::ERC777CallbackReentrancy
        | VulnerabilityCategory::DepositForReentrancy
        | VulnerabilityCategory::MulticallMsgValueReuse
        | VulnerabilityCategory::MulticallStateReset
        | VulnerabilityCategory::ERC2771MulticallSpoofing
        | VulnerabilityCategory::UninitializedImplementation
        | VulnerabilityCategory::DoubleInitialization
        | VulnerabilityCategory::UnvalidatedCrossChainReceiver => CvssVector::nlc(HI, HI),

        VulnerabilityCategory::CLMMMathOverflow | VulnerabilityCategory::InconsistentRounding => {
            CvssVector::nhc(HI, HI)
        }

        // === High: Significant fund risk ===
        VulnerabilityCategory::InconsistentStateReset
        | VulnerabilityCategory::AccessControl
        | VulnerabilityCategory::RoleBasedAccessControl
        | VulnerabilityCategory::ArbitraryExternalCall => CvssVector::nlu(HI, HI),

        VulnerabilityCategory::UnprotectedProxyUpgrade
        | VulnerabilityCategory::ProxyAdminVulnerability
        | VulnerabilityCategory::DelegateCalls
        | VulnerabilityCategory::BridgeVulnerability
        | VulnerabilityCategory::CrossChainReplay
        | VulnerabilityCategory::CrossChainMessageReplay
        | VulnerabilityCategory::MissingStorageGap => CvssVector::nhc(HI, HI),

        VulnerabilityCategory::ReadOnlyReentrancy
        | VulnerabilityCategory::TransientStorageGasReentrancy
        | VulnerabilityCategory::TransientStorageReentrancy
        | VulnerabilityCategory::FlashLoanAttack => CvssVector::nhu(HI, HI),

        VulnerabilityCategory::OracleManipulation
        | VulnerabilityCategory::DonationAttackVector
        | VulnerabilityCategory::EIP7702TxOriginBypass
        | VulnerabilityCategory::SignatureVulnerabilities
        | VulnerabilityCategory::SignatureReplay
        | VulnerabilityCategory::SignatureVerificationBypass => CvssVector::nhu(HI, LO),

        VulnerabilityCategory::UnprotectedAdminSweep => CvssVector {
            pr: PrivilegesRequired::High,
            ..CvssVector::nlu(HI, HI)
        },
        VulnerabilityCategory::SelfdestructDeprecation => CvssVector {
            pr: PrivilegesRequired::High,
            ..CvssVector::nlc(HI, HI)
        },
        VulnerabilityCategory::ArbitraryReceiverCallback => CvssVector {
            pr: PrivilegesRequired::Low,
            ..CvssVector::nlu(HI, HI)
        },
        VulnerabilityCategory::AVSSlashingRisk => CvssVector {
            pr: PrivilegesRequired::Low,
            ..CvssVector::nlu(HI, LO)
        },
        VulnerabilityCategory::GovernanceAttack => CvssVector {
            pr: PrivilegesRequired::Low,
            ..CvssVector::nhc(HI, LO)
        },
        VulnerabilityCategory::TxOriginAuth => CvssVector {
            ui: UserInteraction::Required,
            ..CvssVector::nhu(HI, Impact::None)
        },

        // === Medium: Conditional exploitation ===
        VulnerabilityCategory::FrontRunning
        | VulnerabilityCategory::MEVExploitable
        | VulnerabilityCategory::ArithmeticIssues
        | VulnerabilityCategory::PrecisionLoss
        | VulnerabilityCategory::UncheckedMathOperation
        | VulnerabilityCategory::UnsafeDowncast
        | VulnerabilityCategory::FeeOnTransferAssumption
        | VulnerabilityCategory::MissingSlippageProtection
        | VulnerabilityCategory::MissingSwapDeadline
        | VulnerabilityCategory::UncheckedReturnValues
        | VulnerabilityCategory::UnusedReturnValues
        | VulnerabilityCategory::LowLevelCalls
        | VulnerabilityCategory::CompilerBug
        | VulnerabilityCategory::InputValidationFailure => CvssVector::nhu(LO, LO),

        VulnerabilityCategory::TimeManipulation
        | VulnerabilityCategory::BlockTimestamp
        | VulnerabilityCategory::IsContractPostPectra
        | VulnerabilityCategory::Push0Compatibility => CvssVector::nhu(LO, Impact::None),

        VulnerabilityCategory::MissingTimelock => CvssVector {
            pr: PrivilegesRequired::High,
            ac: AttackComplexity::Low,
            ..CvssVector::nhu(LO, LO)
        },

        VulnerabilityCategory::DoSAttacks | VulnerabilityCategory::StorageDoSAttacks => {
            CvssVector::nhu(Impact::None, HI)
        }

        VulnerabilityCategory::HardcodedGasAmount | VulnerabilityCategory::UnsafeTransferGas => {
            CvssVector::nhu(Impact::None, LO)
        }

        // === 2026 patterns (v0.9.0) ===
        // Critical: governance vote-buying via flash loan = total protocol takeover
        VulnerabilityCategory::GovernanceFlashloanVoting => CvssVector::nlc(HI, HI),

        // High: signature replay primitives & re-hypothecation cause direct loss
        VulnerabilityCategory::EIP1271SignatureReplay
        | VulnerabilityCategory::ERC4337PaymasterAbuse
        | VulnerabilityCategory::LRTRehypothecation => CvssVector::nlu(HI, HI),

        // High but requires upgrade authority
        VulnerabilityCategory::StorageLayoutCollision => CvssVector {
            pr: PrivilegesRequired::High,
            ..CvssVector::nlc(HI, HI)
        },

        // Medium: user-side risk (Permit2) and MEV-exposure
        VulnerabilityCategory::Permit2UnlimitedApproval
        | VulnerabilityCategory::SandwichResistantMissing => CvssVector::nhu(LO, LO),

        // === Mid-2026 patterns (v0.10.0) ===
        // High, direct fund loss: single-DVN trust, unvalidated cross-chain fill,
        // and V4 flash-accounting drains are all network-reachable value theft.
        VulnerabilityCategory::LayerZeroSingleDVN
        | VulnerabilityCategory::ERC7683UnvalidatedFill
        | VulnerabilityCategory::ERC6909FlashAccountingDrain
        // Late-2026 smart-account execution surface: unrestricted module install /
        // batch execute / executor dispatch are network-reachable account takeover.
        | VulnerabilityCategory::ERC7579UnprotectedModule
        | VulnerabilityCategory::ERC7821UnprotectedExecute
        | VulnerabilityCategory::ERC7579UnrestrictedExecutor => CvssVector::nlu(HI, HI),

        // High but conditional: the 7702 collision needs the user to re-delegate,
        // and the compiler bug needs a specific clear-ordering to trigger.
        VulnerabilityCategory::EIP7702DelegateStorageCollision
        | VulnerabilityCategory::TransientStorageCompilerBug => CvssVector {
            ui: UserInteraction::Required,
            ..CvssVector::nlu(HI, HI)
        },

        // === Low / Informational ===
        VulnerabilityCategory::GasOptimization
        | VulnerabilityCategory::UnusedCode
        | VulnerabilityCategory::MagicNumbers
        | VulnerabilityCategory::NamingConventions
        | VulnerabilityCategory::ComplexityIssues
        | VulnerabilityCategory::ExternalFunction
        | VulnerabilityCategory::ImmutabilityIssues
        | VulnerabilityCategory::MissingEvents
        | VulnerabilityCategory::PragmaIssues => CvssVector::zero(),

        // No explicit vector — let the caller fall back to severity_to_cvss so
        // the score stays consistent with the finding's severity.
        _ => return None,
    };
    Some(vector)
}

/// Coarse CVSS vector derived from a finding's severity.
///
/// Used as a fallback when a category has no explicit vector in
/// [`category_to_cvss`]. Because the detection rules set `severity` per finding,
/// this keeps an unmapped Critical finding scoring like a Critical (≈10.0, P1)
/// rather than the old flat 4.8 (P3). Scores are monotone with severity:
/// Critical 10.0 / High 7.4 / Medium 4.8 / Low 3.7 / Info 0.0.
pub fn severity_to_cvss(severity: &VulnerabilitySeverity) -> CvssVector {
    use Impact::{High as HI, Low as LO};
    match severity {
        VulnerabilitySeverity::Critical => CvssVector::nlc(HI, HI),
        VulnerabilitySeverity::High => CvssVector::nhu(HI, HI),
        VulnerabilitySeverity::Medium => CvssVector::nhu(LO, LO),
        VulnerabilitySeverity::Low => CvssVector::nhu(Impact::None, LO),
        VulnerabilitySeverity::Info => CvssVector::zero(),
    }
}

/// Enrich a list of vulnerabilities with CVSS scores and vector strings.
pub fn enrich_with_cvss(vulnerabilities: &mut [Vulnerability]) {
    for vuln in vulnerabilities.iter_mut() {
        let vector =
            category_to_cvss(&vuln.category).unwrap_or_else(|| severity_to_cvss(&vuln.severity));
        vuln.cvss_score = Some(vector.calculate_base_score());
        vuln.cvss_vector = Some(vector.to_vector_string());
    }
}
