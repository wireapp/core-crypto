import {
    X509CredentialAcquisition as X509CredentialAcquisitionFfi,
    type X509CredentialAcquisitionConfiguration,
    type X509CredentialAcquisitionLike,
    type PkiEnvironmentLike,
    type CredentialRefLike,
    type DatabaseLike,
} from "#core-crypto-ffi";

// UBRN doesn't support default parameters, and we want `coreCryptoDatabase` to be optional in `newFromCredentialRef`.
// The generated function already accepts `undefined` there, so this only widens its type. It doesn't subclass:
// the generated constructors differ per platform, and instances the FFI creates are always of the generated class.
export const X509CredentialAcquisition: typeof X509CredentialAcquisitionFfi & {
    /**
     * Create a new credential acquisition from an existing credential.
     * This API is temporary until our system decouples client identities from a client's public signature key.
     * See <https://wearezeta.atlassian.net/wiki/x/RABtrQ>.
     *
     * Provide `coreCryptoDatabase` if you're using distinct DB instances for `PkiEnvironment` and `CoreCrypto`.
     * Otherwise, the `PkiEnvironment`'s DB will be used to load the full credential.
     */
    newFromCredentialRef(
        pkiEnvironment: PkiEnvironmentLike,
        config: X509CredentialAcquisitionConfiguration,
        credentialRef: CredentialRefLike,
        coreCryptoDatabase?: DatabaseLike,
    ): Promise<X509CredentialAcquisitionLike>;
} = X509CredentialAcquisitionFfi;

export type X509CredentialAcquisition = X509CredentialAcquisitionFfi;
