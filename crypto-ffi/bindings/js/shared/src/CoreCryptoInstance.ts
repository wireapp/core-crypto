// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

import * as CoreCryptoFfiTypes from "#core-crypto-ffi";
import {
    CipherSuite,
    ClientId,
    CoreCryptoContext,
    CoreCryptoError,
    CoreCryptoFfi,
    type CoreCryptoFfiLike,
    CredentialRef,
    coreCryptoHistoryClient,
    coreCryptoNew,
    Database,
    HistorySecret,
    CredentialType,
} from "#core-crypto-ffi";

export interface CredentialFindFilters {
    clientId?: ClientId;
    publicKey?: Uint8Array;
    cipherSuite?: CipherSuite;
    credentialType?: CredentialType;
    earliestValidity?: bigint;
}

/** `CoreCrypto` where the FFI gives `CoreCryptoFfi`: a promise of it where every call is async (browser). */
type Adopted<T> =
    T extends PromiseLike<unknown> ? Promise<CoreCrypto> : CoreCrypto;

// `CoreCryptoFfi` has no primary constructor, so the generated one is private and the class can't be extended as is.
// This is a type-level hack to allow extending the class anyway.
const CoreCryptoFfiBase = CoreCryptoFfi as unknown as Omit<
    typeof CoreCryptoFfi,
    "prototype"
> &
    (abstract new () => CoreCryptoFfi);

/**
 * Wrapper for the WASM-compiled version of CoreCrypto
 */
export class CoreCrypto extends CoreCryptoFfiBase {
    /** @internal */
    static instanceOf(obj: unknown): obj is CoreCryptoFfi {
        return CoreCryptoFfi.instanceOf(obj);
    }

    // Never called: instances come from the FFI and are adopted. It's only here to keep the constructor private.
    private constructor() {
        super();
    }

    /**
     * Make an instance the FFI returned into a `CoreCrypto`.
     */
    private static adopt(ffiInstance: CoreCryptoFfiLike): CoreCrypto {
        return Object.setPrototypeOf(ffiInstance, this.prototype) as CoreCrypto;
    }

    /**
     * Construct a new {@link CoreCrypto} instance.
     * MLS or proteus can be initialized  with {@link CoreCryptoContext.mlsInit} or
     * {@link CoreCryptoContext.proteusInit}, respectively.
     */
    public static new(
        database: Database,
    ): Adopted<ReturnType<typeof coreCryptoNew>> {
        const ffiInstance = coreCryptoNew(database);
        return (
            ffiInstance instanceof Promise
                ? ffiInstance.then((instance) => this.adopt(instance))
                : this.adopt(ffiInstance as CoreCryptoFfiLike)
        ) as Adopted<ReturnType<typeof coreCryptoNew>>;
    }

    /**
     * Instantiate a history client.
     *
     * This client exposes the full interface of {@link CoreCrypto}, but it should only be used to decrypt messages.
     * Other use is a logic error.
     */
    public static async historyClient(
        historySecret: HistorySecret,
    ): Promise<CoreCrypto> {
        return this.adopt(await coreCryptoHistoryClient(historySecret));
    }

    /**
     * Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
     * otherwise, every operation performed with the context will be discarded.
     *
     * @param callback - The callback to execute within the transaction
     *
     * @returns the result of the callback will be returned from this call
     */
    async transaction<R>(
        callback: (ctx: CoreCryptoContext) => Promise<R>,
    ): Promise<R> {
        let result!: R;
        let error: CoreCryptoError | Error | null = null;
        let needOuterRethrow = false;
        try {
            await super.transactionFfi({
                execute: async (ctx) => {
                    try {
                        result = await callback(ctx);
                    } catch (e) {
                        // We want to catch the error before it gets wrapped by core crypto.
                        if (Error.isError(e)) {
                            error = e;
                        } else {
                            // Something unexpected was thrown
                            needOuterRethrow = true;
                        }
                        // This is to tell core crypto that there was an error inside the transaction.
                        // Uniffi can't handle `null` or `undefined` (the transaction would never settle),
                        // so pass an `Error` instead.
                        throw e ?? new Error(String(e));
                    }
                },
            });
        } catch (e) {
            // We prefer the closure error if it's available since the transaction will just wrap and re-throw it.
            // If we caught an object of an unexpected type, we're rethrowing it as a wrapped `CoreCryptoError`.
            if (needOuterRethrow) {
                throw e;
            }
        }
        if (error !== null) {
            throw error;
        }
        return result;
    }

    /** @internal
     *  We're overriding this just to hide it from the docs
     */
    async transactionFfi(
        command: CoreCryptoFfiTypes.CoreCryptoCommand,
        asyncOpts_?: { signal: AbortSignal },
    ): Promise<void> {
        return super.transactionFfi(command, asyncOpts_);
    }

    /**
     * Get those credentials known to this instance which match the provided filters
     *
     * @param findFilters a set of filters defining which credentials are of interest.
     */
    async findCredentials(
        findFilters: CredentialFindFilters,
    ): Promise<CredentialRef[]> {
        return await super.findCredentialsFfi(
            findFilters.clientId,
            findFilters.publicKey,
            findFilters.cipherSuite,
            findFilters.credentialType,
            findFilters.earliestValidity,
        );
    }

    /** @internal
     *  We're overriding this just to hide it from the docs
     */
    async findCredentialsFfi(
        clientId?: ClientId,
        publicKey?: Uint8Array,
        cipherSuite?: CipherSuite,
        credentialType?: CredentialType,
        earliestValidity?: bigint,
        asyncOpts_?: { signal: AbortSignal },
    ): Promise<Array<CredentialRef>> {
        return await super.findCredentialsFfi(
            clientId,
            publicKey,
            cipherSuite,
            credentialType,
            earliestValidity,
            asyncOpts_,
        );
    }
}
