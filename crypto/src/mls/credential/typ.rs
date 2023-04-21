/// Lists all the supported Credential types. Could list in the future some types not supported by
/// openmls such as Verifiable Presentation
#[derive(Default, Debug, Clone, Copy, strum::EnumCount)]
#[repr(u8)]
pub enum MlsCredentialType {
    /// Basic credential i.e. a KeyPair
    #[default]
    Basic = 0x01,
    /// A x509 certificate generally obtained through e2e identity enrollment process
    X509 = 0x02,
}
