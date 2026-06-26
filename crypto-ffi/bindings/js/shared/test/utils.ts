import { HttpMethod, HttpHeader } from "@wireapp/core-crypto/browser";
import { sharedSetup, runOnPlatform } from "../shared/utils";
export { runOnPlatform } from "../shared/utils";
export { sharedTeardown as teardown } from "../shared/utils";

export async function setup() {
    await sharedSetup();
    await setPkiEnvironmentHooks();
}

async function setPkiEnvironmentHooks() {
    await runOnPlatform(async () => {
        pkiEnvironmentHooks = {
            async httpRequest(
                _method: HttpMethod,
                _url: string,
                _headers: Array<HttpHeader>,
                _body: Uint8Array
            ) {
                // return a HttpResponse
                return {
                    status: 200,
                    headers: [],
                    body: new Uint8Array(),
                };
            },

            async authenticate(
                _idp: string,
                _keyAuth: string,
                _acmeAud: string,
                _acquisition_snapshot: Uint8Array
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
