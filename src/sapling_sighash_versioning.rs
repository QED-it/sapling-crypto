//! This module defines the versioning for Sapling signatures.

use redjubjub::{Binding, SigType, Signature, SpendAuth};

/// The Sapling Sighash version.
/// Represented as a `u8` for compatibility with the PCZT encoding.
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum SaplingSighashVersion {
    /// Version V0.
    V0 = 0,

    /// No version (used for Sapling and TXv5 compatibility).
    /// TXv5 does not require the sighash versioning bytes.
    NoVersion = u8::MAX,
}

/// The Sapling versioned signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SaplingVersionedSig<T: SigType> {
    version: SaplingSighashVersion,
    sig: Signature<T>,
}

impl<T: SigType> SaplingVersionedSig<T> {
    /// Constructs a `SaplingVersionedSig` from its constituent parts.
    pub fn new(version: SaplingSighashVersion, sig: Signature<T>) -> Self {
        Self { version, sig }
    }

    /// Returns the version of the signature.
    pub fn version(&self) -> &SaplingSighashVersion {
        &self.version
    }

    /// Returns the signature.
    pub fn sig(&self) -> &Signature<T> {
        &self.sig
    }
}

/// A versioned Sapling SpendAuth signature.
pub type VerSpendAuthSig = SaplingVersionedSig<SpendAuth>;

/// A versioned Sapling binding signature.
pub type VerBindingSig = SaplingVersionedSig<Binding>;

#[cfg(test)]
mod tests {
    use super::SaplingSighashVersion;
    #[test]
    fn lock_sapling_sighash_version_encoding() {
        // Ensure the encoding of SaplingSighashVersion is as expected.
        assert_eq!(SaplingSighashVersion::V0 as u8, 0);
        assert_eq!(SaplingSighashVersion::NoVersion as u8, u8::MAX);
    }
}
