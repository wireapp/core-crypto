use core_crypto::prelude::{CiphersuiteName, MlsCiphersuite};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
pub struct Ciphersuite(CiphersuiteName);

#[cfg(not(target_family = "wasm"))]
uniffi::custom_type!(Ciphersuite, u16, {
    lower: |ciphersuite| (&ciphersuite.0).into(),
    try_lift: |val| Ciphersuite::new(val).map_err(Into::into),
});

impl From<MlsCiphersuite> for Ciphersuite {
    fn from(value: MlsCiphersuite) -> Self {
        Self(value.into())
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(cs: Ciphersuite) -> Self {
        cs.0.into()
    }
}

#[derive(Debug, Default, Clone, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Ciphersuites(Vec<CiphersuiteName>);

impl<'a> From<&'a Ciphersuites> for Vec<MlsCiphersuite> {
    fn from(cs: &'a Ciphersuites) -> Self {
        cs.0.iter().copied().map(Into::into).collect()
    }
}

#[cfg(not(target_family = "wasm"))]
uniffi::custom_type!(Ciphersuites, Vec<u16>, {
    lower: |cs| cs.0.into_iter().map(|c| (&c).into()).collect(),
    try_lift: |val| {
        val.iter().try_fold(Ciphersuites(vec![]), |mut acc, c| -> uniffi::Result<Self> {
            let cs = CiphersuiteName::try_from(*c)?;
            acc.0.push(cs);
            Ok(acc)
        })
    }
});

/// Helper to lower arrays of Ciphersuites (js -> rust)
#[cfg(target_family = "wasm")]
pub(crate) fn lower_ciphersuites(ciphersuites: &[u16]) -> crate::WasmCryptoResult<Vec<MlsCiphersuite>> {
    use crate::error::internal::InternalError;

    ciphersuites
        .iter()
        .copied()
        .map(|cs| {
            let cs = CiphersuiteName::try_from(cs).map_err(|_| InternalError::UnknownCiphersuite)?;
            Ok(MlsCiphersuite::from(Ciphersuite::from(cs)))
        })
        .collect::<Result<Vec<_>, _>>()
}
