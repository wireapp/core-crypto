import {
    Ciphersuite,
    ClientId,
    CoreCryptoContext as CoreCryptoContextFfi,
    CredentialRef,
    CredentialType,
} from "#core-crypto-ffi";

export interface CredentialFindFilters {
    clientId?: ClientId;
    publicKey?: ArrayBuffer;
    ciphersuite?: Ciphersuite;
    credentialType?: CredentialType;
    earliestValidity?: bigint;
}

export class CoreCryptoContext extends CoreCryptoContextFfi {
    /** @internal */
    constructor(ctx: CoreCryptoContextFfi) {
        super(ctx);
    }

    /** @internal */
    static instanceOf(obj: unknown): obj is CoreCryptoContextFfi {
        return super.instanceOf(obj);
    }

    /**
     * Get those credentials known to this instance which match the provided filters
     *
     * @param findFilters a set of filters defining which credentials are of interest.
     */
    async findCredentials(
        findFilters: CredentialFindFilters
    ): Promise<CredentialRef[]> {
        return await super.findCredentialsFfi(
            findFilters.clientId,
            findFilters.publicKey,
            findFilters.ciphersuite,
            findFilters.credentialType,
            findFilters.earliestValidity
        );
    }

    /** @internal
     *  We're overriding this just to hide it from the docs
     */
    async findCredentialsFfi(
        clientId?: ClientId,
        publicKey?: ArrayBuffer,
        ciphersuite?: Ciphersuite,
        credentialType?: CredentialType,
        earliestValidity?: bigint,
        asyncOpts_?: { signal: AbortSignal }
    ): Promise<Array<CredentialRef>> {
        return await super.findCredentialsFfi(
            clientId,
            publicKey,
            ciphersuite,
            credentialType,
            earliestValidity,
            asyncOpts_
        );
    }
}
