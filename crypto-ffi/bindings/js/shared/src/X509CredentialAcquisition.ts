import {
    X509CredentialAcquisition as X509CredentialAcquisitionFfi,
    type X509CredentialAcquisitionConfiguration,
    type PkiEnvironmentLike,
    type CredentialRefLike,
    type DatabaseLike,
} from "#core-crypto-ffi";

export class X509CredentialAcquisition extends X509CredentialAcquisitionFfi {
    /**
     * Create a new credential acquisition from an existing credential.
     * This API is temporary until our system decouples client identities from a client's public signature key.
     * See <https://wearezeta.atlassian.net/wiki/x/RABtrQ>.
     *
     * Provide `coreCryptoDatabase` if you're using distinct DB instances for `PkiEnvironment` and `CoreCrypto`.
     * Otherwise, the `PkiEnvironment`'s DB will be used to load the full credential.
     */
    // We're overriding this because UBRN currently doesn't support default parameters, and we want `coreCryptoDatabase`
    // to be optional.
    static override async newFromCredentialRef(
        pkiEnvironment: PkiEnvironmentLike,
        config: X509CredentialAcquisitionConfiguration,
        credentialRef: CredentialRefLike,
        coreCryptoDatabase?: DatabaseLike
    ): Promise<X509CredentialAcquisition> {
        return X509CredentialAcquisitionFfi.newFromCredentialRef(
            pkiEnvironment,
            config,
            credentialRef,
            coreCryptoDatabase
        ) as Promise<X509CredentialAcquisition>;
    }
}
