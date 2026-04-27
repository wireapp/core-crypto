import { browser } from "@wdio/globals";

import {
    Ciphersuite,
    type CommitBundle,
    type PkiEnvironmentHooks,
    HttpMethod,
    HttpHeader,
} from "@wireapp/core-crypto/browser";
import {
    sharedSetup,
    type DeliveryService,
    type Helpers,
    type LogEntry,
} from "../shared/utils";

export { teardown } from "../shared/utils";

type ccModuleType = typeof import("@wireapp/core-crypto/browser");

declare global {
    interface Window {
        ccModule: ccModuleType;
        defaultCipherSuite: Ciphersuite;
        deliveryService: DeliveryService;
        pkiEnvironmentHooks: PkiEnvironmentHooks;
        _latestCommitBundle: CommitBundle;
        recordedLogs: LogEntry[];
        helpers: Helpers;
    }
}

export async function setup() {
    await sharedSetup();
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
    });
}
