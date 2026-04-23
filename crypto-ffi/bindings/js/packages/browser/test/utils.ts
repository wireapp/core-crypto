import { browser } from "@wdio/globals";

import {
    Ciphersuite,
    CoreCrypto,
    type MlsTransport,
    type CommitBundle,
    type PkiEnvironmentHooks,
    HttpMethod,
    HttpHeader,
} from "@wireapp/core-crypto/browser";
import { shared_setup, type Helpers, type LogEntry } from "../shared/utils";

type ccModuleType = typeof import("@wireapp/core-crypto/browser");

declare global {
    interface Window {
        ccModule: ccModuleType;
        cc: Map<string, CoreCrypto>;
        defaultCipherSuite: Ciphersuite;
        deliveryService: DeliveryService;
        pkiEnvironmentHooks: PkiEnvironmentHooks;
        _latestCommitBundle: CommitBundle;
        recordedLogs: LogEntry[];
        helpers: Helpers;

        // Helper functions that are used inside the browser context
        /**
         * Gets a {@link CoreCrypto} instance initialized previously via
         * {@link ccInit}.
         *
         * @param clientName The name the {@link ccInit} was called with.
         *
         * @returns {CoreCrypto} The {@link CoreCrypto} instance.
         *
         * @throws Error if no instance with the name has been initialized.
         */
        ensureCcDefined: (clientName: string) => CoreCrypto;
    }
}

interface DeliveryService extends MlsTransport {
    getLatestCommitBundle: () => Promise<CommitBundle>;
}

export async function setup() {
    await shared_setup();
    await browser.execute(async () => {
        window.defaultCipherSuite =
            window.ccModule.Ciphersuite.Mls128Dhkemx25519Aes128gcmSha256Ed25519;

        window.pkiEnvironmentHooks = {
            async httpRequest(
                _method: HttpMethod,
                _url: string,
                _headers: Array<HttpHeader>,
                _body: ArrayBuffer
            ) {
                // return a HttpResponse
                return {
                    status: 200,
                    headers: [],
                    body: new Uint8Array().buffer,
                };
            },

            async authenticate(
                _idp: string,
                _keyAuth: string,
                _acmeAud: string
            ) {
                return "dummy-id-token";
            },

            async getBackendNonce() {
                return "dummy-backend-nonce";
            },

            async fetchBackendAccessToken(_dpop) {
                return "dummy-backend-token";
            },
        };

        window.ensureCcDefined = (clientName: string) => {
            const cc = window.cc.get(clientName);
            if (cc === undefined) {
                throw new Error(
                    `Client with name '${clientName}' is not initialized in the browser context.`
                );
            }
            return cc;
        };
    });
}
