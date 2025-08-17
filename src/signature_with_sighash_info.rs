//! Defines `SighashInfo` and signatures with `SighashInfo`.

use alloc::vec::Vec;

use redjubjub::{Binding, SigType, SpendAuth};

/// The sighash version and associated information
#[derive(Debug, Clone)]
pub(crate) struct SighashInfo {
    version: u8,
    associated_information: Vec<u8>,
}

/// The sighash version and associated information for Sapling binding/authorizing signatures.
pub(crate) const SAPLING_SIG_V0: SighashInfo = SighashInfo {
    version: 0x00,
    associated_information: vec![],
};

#[derive(Debug, Clone)]
pub struct SignatureWithSighashInfo<T: SigType> {
    info: SighashInfo,
    signature: redjubjub::Signature<T>,
}

impl<T: SigType> SignatureWithSighashInfo<T> {
    pub(crate) fn new(info: SighashInfo, signature: redjubjub::Signature<T>) -> Self {
        Self { info, signature }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.info.associated_information.len() + 64);
        result.push(self.info.version);
        result.extend_from_slice(&self.info.associated_information);
        result.extend_from_slice(&<[u8; 64]>::from(self.signature));
        result
    }

    /// Returns the signature.
    pub fn signature(&self) -> &redjubjub::Signature<T> {
        &self.signature
    }
}

/// Binding signature containing the sighash information and the signature itself.
pub type BindingSignatureWithSighashInfo = SignatureWithSighashInfo<Binding>;

/// Authorizing signature containing the sighash information and the signature itself.
pub type SpendAuthSignatureWithSighashInfo = SignatureWithSighashInfo<SpendAuth>;

#[cfg(test)]
mod tests {
    use super::{BindingSignatureWithSighashInfo, SAPLING_SIG_V0};
    use redjubjub::Binding;

    #[test]
    fn signature_with_sighash_info() {
        let binding_signature_with_info = BindingSignatureWithSighashInfo::new(
            SAPLING_SIG_V0,
            redjubjub::Signature::<Binding>::from([0u8; 64]),
        );
        assert_eq!(binding_signature_with_info.to_bytes(), [0u8; 65]);
    }
}
