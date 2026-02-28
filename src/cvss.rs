//! CVSS 3.1 Base Score Calculator for Smart Contract Vulnerabilities.
//!
//! Implements the official CVSS 3.1 base scoring formula and provides
//! a static mapping from `VulnerabilityCategory` to default CVSS vectors.
//!
//! Smart contract context:
//! - **AV** = Network always (public blockchain)
//! - **C** = None usually (on-chain data is public)
//! - **I** / **A** = primary impact axes (state/funds)

use crate::vulnerabilities::{Vulnerability, VulnerabilityCategory};

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AttackVector { Network, Adjacent, Local, Physical }

#[derive(Debug, Clone, Copy)]
pub enum AttackComplexity { Low, High }

#[derive(Debug, Clone, Copy)]
pub enum PrivilegesRequired { None, Low, High }

#[derive(Debug, Clone, Copy)]
pub enum UserInteraction { None, Required }

#[derive(Debug, Clone, Copy)]
pub enum Scope { Unchanged, Changed }

#[derive(Debug, Clone, Copy)]
pub enum Impact { None, Low, High }

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
            av: AttackVector::Network, ac: AttackComplexity::Low,
            pr: PrivilegesRequired::None, ui: UserInteraction::None,
            s: Scope::Changed, c: Impact::None, i, a,
        }
    }
    /// AV:N/AC:H/PR:N/UI:N/S:C — Critical but complex
    fn nhc(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network, ac: AttackComplexity::High,
            pr: PrivilegesRequired::None, ui: UserInteraction::None,
            s: Scope::Changed, c: Impact::None, i, a,
        }
    }
    /// AV:N/AC:L/PR:N/UI:N/S:U — High: scope-unchanged, no barriers
    fn nlu(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network, ac: AttackComplexity::Low,
            pr: PrivilegesRequired::None, ui: UserInteraction::None,
            s: Scope::Unchanged, c: Impact::None, i, a,
        }
    }
    /// AV:N/AC:H/PR:N/UI:N/S:U — Medium: scope-unchanged, complex
    fn nhu(i: Impact, a: Impact) -> Self {
        Self {
            av: AttackVector::Network, ac: AttackComplexity::High,
            pr: PrivilegesRequired::None, ui: UserInteraction::None,
            s: Scope::Unchanged, c: Impact::None, i, a,
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

        let base = if scope_changed {
            roundup((1.08 * (impact + exploitability)).min(10.0))
        } else {
            roundup((impact + exploitability).min(10.0))
        };

        base
    }

    /// Generate the CVSS 3.1 vector string.
    pub fn to_vector_string(&self) -> String {
        format!(
            "CVSS:3.1/AV:{}/AC:{}/PR:{}/UI:{}/S:{}/C:{}/I:{}/A:{}",
            match self.av {
                AttackVector::Network => "N", AttackVector::Adjacent => "A",
                AttackVector::Local => "L", AttackVector::Physical => "P",
            },
            match self.ac { AttackComplexity::Low => "L", AttackComplexity::High => "H" },
            match self.pr {
                PrivilegesRequired::None => "N", PrivilegesRequired::Low => "L",
                PrivilegesRequired::High => "H",
            },
            match self.ui { UserInteraction::None => "N", UserInteraction::Required => "R" },
            match self.s { Scope::Unchanged => "U", Scope::Changed => "C" },
            match self.c { Impact::None => "N", Impact::Low => "L", Impact::High => "H" },
            match self.i { Impact::None => "N", Impact::Low => "L", Impact::High => "H" },
            match self.a { Impact::None => "N", Impact::Low => "L", Impact::High => "H" },
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
            AttackVector::Network => 0.85, AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55, AttackVector::Physical => 0.20,
        };
        let ac = match self.ac { AttackComplexity::Low => 0.77, AttackComplexity::High => 0.44 };
        let pr = match (self.pr, matches!(self.s, Scope::Changed)) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, false) => 0.62,
            (PrivilegesRequired::Low, true) => 0.68,
            (PrivilegesRequired::High, false) => 0.27,
            (PrivilegesRequired::High, true) => 0.50,
        };
        let ui = match self.ui { UserInteraction::None => 0.85, UserInteraction::Required => 0.62 };
        8.22 * av * ac * pr * ui
    }
}

fn impact_value(i: Impact) -> f64 {
    match i { Impact::None => 0.0, Impact::Low => 0.22, Impact::High => 0.56 }
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
pub fn category_to_cvss(category: &VulnerabilityCategory) -> CvssVector {
    use Impact::{High as HI, Low as LO};

    match category {
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
        | VulnerabilityCategory::UnvalidatedCrossChainReceiver
            => CvssVector::nlc(HI, HI),

        VulnerabilityCategory::CLMMMathOverflow
        | VulnerabilityCategory::InconsistentRounding
            => CvssVector::nhc(HI, HI),

        // === High: Significant fund risk ===
        VulnerabilityCategory::InconsistentStateReset
        | VulnerabilityCategory::AccessControl
        | VulnerabilityCategory::RoleBasedAccessControl
        | VulnerabilityCategory::ArbitraryExternalCall
            => CvssVector::nlu(HI, HI),

        VulnerabilityCategory::UnprotectedProxyUpgrade
        | VulnerabilityCategory::ProxyAdminVulnerability
        | VulnerabilityCategory::DelegateCalls
        | VulnerabilityCategory::BridgeVulnerability
        | VulnerabilityCategory::CrossChainReplay
        | VulnerabilityCategory::CrossChainMessageReplay
        | VulnerabilityCategory::MissingStorageGap
            => CvssVector::nhc(HI, HI),

        VulnerabilityCategory::ReadOnlyReentrancy
        | VulnerabilityCategory::TransientStorageGasReentrancy
        | VulnerabilityCategory::TransientStorageReentrancy
        | VulnerabilityCategory::FlashLoanAttack
            => CvssVector::nhu(HI, HI),

        VulnerabilityCategory::OracleManipulation
        | VulnerabilityCategory::DonationAttackVector
        | VulnerabilityCategory::EIP7702TxOriginBypass
        | VulnerabilityCategory::SignatureVulnerabilities
        | VulnerabilityCategory::SignatureReplay
        | VulnerabilityCategory::SignatureVerificationBypass
            => CvssVector::nhu(HI, LO),

        VulnerabilityCategory::UnprotectedAdminSweep => CvssVector {
            pr: PrivilegesRequired::High, ..CvssVector::nlu(HI, HI)
        },
        VulnerabilityCategory::SelfdestructDeprecation => CvssVector {
            pr: PrivilegesRequired::High, ..CvssVector::nlc(HI, HI)
        },
        VulnerabilityCategory::ArbitraryReceiverCallback => CvssVector {
            pr: PrivilegesRequired::Low, ..CvssVector::nlu(HI, HI)
        },
        VulnerabilityCategory::AVSSlashingRisk => CvssVector {
            pr: PrivilegesRequired::Low, ..CvssVector::nlu(HI, LO)
        },
        VulnerabilityCategory::GovernanceAttack => CvssVector {
            pr: PrivilegesRequired::Low, ..CvssVector::nhc(HI, LO)
        },
        VulnerabilityCategory::TxOriginAuth => CvssVector {
            ui: UserInteraction::Required, ..CvssVector::nhu(HI, Impact::None)
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
        | VulnerabilityCategory::InputValidationFailure
            => CvssVector::nhu(LO, LO),

        VulnerabilityCategory::TimeManipulation
        | VulnerabilityCategory::BlockTimestamp
        | VulnerabilityCategory::IsContractPostPectra
        | VulnerabilityCategory::Push0Compatibility
            => CvssVector::nhu(LO, Impact::None),

        VulnerabilityCategory::MissingTimelock => CvssVector {
            pr: PrivilegesRequired::High, ac: AttackComplexity::Low, ..CvssVector::nhu(LO, LO)
        },

        VulnerabilityCategory::DoSAttacks
        | VulnerabilityCategory::StorageDoSAttacks
            => CvssVector::nhu(Impact::None, HI),

        VulnerabilityCategory::HardcodedGasAmount
        | VulnerabilityCategory::UnsafeTransferGas
            => CvssVector::nhu(Impact::None, LO),

        // === Low / Informational ===
        VulnerabilityCategory::GasOptimization
        | VulnerabilityCategory::UnusedCode
        | VulnerabilityCategory::MagicNumbers
        | VulnerabilityCategory::NamingConventions
        | VulnerabilityCategory::ComplexityIssues
        | VulnerabilityCategory::ExternalFunction
        | VulnerabilityCategory::ImmutabilityIssues
        | VulnerabilityCategory::MissingEvents
        | VulnerabilityCategory::PragmaIssues
            => CvssVector::zero(),

        // Default for unmapped categories
        _ => CvssVector::nhu(LO, LO),
    }
}

/// Enrich a list of vulnerabilities with CVSS scores and vector strings.
pub fn enrich_with_cvss(vulnerabilities: &mut [Vulnerability]) {
    for vuln in vulnerabilities.iter_mut() {
        let vector = category_to_cvss(&vuln.category);
        vuln.cvss_score = Some(vector.calculate_base_score());
        vuln.cvss_vector = Some(vector.to_vector_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reentrancy_cvss_score() {
        let vector = category_to_cvss(&VulnerabilityCategory::Reentrancy);
        let score = vector.calculate_base_score();
        assert!(score >= 9.0, "Reentrancy should be Critical (>=9.0), got {score}");
    }

    #[test]
    fn test_gas_optimization_zero_impact() {
        let vector = category_to_cvss(&VulnerabilityCategory::GasOptimization);
        let score = vector.calculate_base_score();
        assert_eq!(score, 0.0, "GasOptimization should have 0.0 CVSS score");
    }

    #[test]
    fn test_vector_string_format() {
        let vector = category_to_cvss(&VulnerabilityCategory::Reentrancy);
        let vs = vector.to_vector_string();
        assert!(vs.starts_with("CVSS:3.1/"), "Should start with CVSS:3.1/");
        assert!(vs.contains("AV:N"), "Smart contracts always have AV:N");
    }

    #[test]
    fn test_score_range() {
        let v = CvssVector {
            av: AttackVector::Network, ac: AttackComplexity::Low,
            pr: PrivilegesRequired::None, ui: UserInteraction::None,
            s: Scope::Changed, c: Impact::High, i: Impact::High, a: Impact::High,
        };
        let score = v.calculate_base_score();
        assert!(score <= 10.0 && score >= 0.0, "Score must be in [0, 10], got {score}");
        assert_eq!(score, 10.0, "Maximum vector should produce 10.0");
    }
}
