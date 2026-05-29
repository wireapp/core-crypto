import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { E2eiConversationState } from "@wireapp/core-crypto/browser";

const TEST_CA_PEM = `
-----BEGIN CERTIFICATE-----
MIIBkzCCAUWgAwIBAgIUHFYIFRkm33GKIOb4xLeNtkjl3TIwBQYDK2VwMDcxFTAT
BgNVBAMMDFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
AlVTMB4XDTI2MDUyODE1MzA0NFoXDTM2MDUyNTE1MzA0NFowNzEVMBMGA1UEAwwM
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwKjAF
BgMrZXADIQDa0nMgIgBZeNM2ysNUVp80zwjZNqPJt7HYK3GX7GPp9aNjMGEwHQYD
VR0OBBYEFHA0MmaaNGOTuBvdo3zzQoKFJ3p5MB8GA1UdIwQYMBaAFHA0MmaaNGOT
uBvdo3zzQoKFJ3p5MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUG
AytlcANBAJffPzL50OWnmEBo9mGBQfPVzKRIfFc8EaXox1D5VF9cC1r8nRa0hUq+
LOVS/gxNk618+PKA2bYq67MZQXCYGgk=
-----END CERTIFICATE-----
`;

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("PKI environment", () => {
    it("should be settable after mls init", async () => {
        // Get unset pki environment
        const success = await browser.execute(async () => {
            const cc = await window.helpers.ccInit({
                withBasicCredential: false,
            });

            let pkiEnv = await cc.getPkiEnvironment();

            if (pkiEnv != undefined) {
                throw new Error("Expected pkiEnv to be undefined.");
            }

            // set pki environment
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.Database.open(
                crypto.randomUUID(),
                new window.ccModule.DatabaseKey(key)
            );
            pkiEnv = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pkiEnv);
            // We cannot compare the result of getPkiEnvironment()
            // with `pkiEnv`, due to uniffi hiding everything,
            // so just make sure it's not undefined.
            if ((await cc.getPkiEnvironment()) === undefined) return false;

            await cc.setPkiEnvironment(undefined);
            return (await cc.getPkiEnvironment()) === undefined;
        });
        await expect(success).toBe(true);
    });

    it("should be settable before mls init", async () => {
        const success = await browser.execute(async () => {
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.Database.open(
                window.crypto.randomUUID(),
                new window.ccModule.DatabaseKey(key)
            );

            const cc = window.ccModule.CoreCrypto.new(database);
            let pkiEnv = await cc.getPkiEnvironment();

            if (pkiEnv != undefined) {
                throw new Error("Expected pkiEnv to be undefined.");
            }

            pkiEnv = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pkiEnv);

            return (await cc.getPkiEnvironment()) != undefined;
        });
        await expect(success).toBe(true);
    });

    it("should add a trust anchor certificate", async () => {
        const error = await browser.execute(async (certPem) => {
            const database = await window.helpers.newDatabase();
            const pkiEnvironment = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );

            try {
                await pkiEnvironment.addTrustAnchor(certPem);
                return undefined;
            } catch (error) {
                return error instanceof Error ? error.message : String(error);
            }
        }, TEST_CA_PEM);

        await expect(error).toBe(undefined);
    });

    it("should add an intermediate certificate", async () => {
        const error = await browser.execute(async (certPem) => {
            const database = await window.helpers.newDatabase();
            const pkiEnvironment = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );

            try {
                await pkiEnvironment.addIntermediateCert(certPem);
                return undefined;
            } catch (error) {
                return error instanceof Error ? error.message : String(error);
            }
        }, TEST_CA_PEM);

        await expect(error).toBe(undefined);
    });
});

describe("end to end identity", () => {
    it("should instantiate an x509 credential acquisition object", async () => {
        const acquisitionCreated = await browser.execute(async () => {
            const database = await window.helpers.newDatabase();
            const pkiEnvironment = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );

            const qualifiedClientId = window.helpers
                .newClientId(
                    "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com"
                )
                .parseQualified();
            const config =
                window.ccModule.X509CredentialAcquisitionConfiguration.new({
                    acmeDirectoryUrl: "acme.example.com/directory",
                    cipherSuite: window.defaultCipherSuite,
                    displayName: "Alice Smith",
                    clientId: qualifiedClientId,
                    handle: "alice_wire",
                    domain: "world.com",
                    team: undefined,
                    validityPeriodSecs: BigInt(3600),
                });

            const acquisition = new window.ccModule.X509CredentialAcquisition(
                pkiEnvironment,
                config
            );

            return acquisition !== undefined;
        });

        await expect(acquisitionCreated).toBe(true);
    });

    it("should instantiate an x509 credential acquisition object from credential ref", async () => {
        const acquisitionCreated = await browser.execute(async () => {
            const database = await window.helpers.newDatabase();
            const pkiEnvironment = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );

            const qualifiedClientId = window.helpers
                .newClientId(
                    "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com"
                )
                .parseQualified();
            const clientId = qualifiedClientId.clientId();
            const config =
                window.ccModule.X509CredentialAcquisitionConfiguration.new({
                    acmeDirectoryUrl: "acme.example.com/directory",
                    cipherSuite: window.defaultCipherSuite,
                    displayName: "Alice Smith",
                    clientId: qualifiedClientId,
                    handle: "alice_wire",
                    domain: "world.com",
                    team: undefined,
                    validityPeriodSecs: BigInt(3600),
                });

            const cc = await window.helpers.ccInit({
                withBasicCredential: true,
                clientId,
                database,
            });

            const [credentialRef] = await cc.findCredentials({ clientId });

            const acquisition =
                await window.ccModule.X509CredentialAcquisition.newFromCredentialRef(
                    pkiEnvironment,
                    config,
                    credentialRef!
                );

            return acquisition !== undefined;
        });

        await expect(acquisitionCreated).toBe(true);
    });

    it("should not be enabled on conversation with basic credential", async () => {
        const conversationState = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const conversationId = await window.helpers.createConversation(cc);
            return await cc.transaction(async (ctx) => {
                return await ctx.e2eiConversationState(conversationId);
            });
        });
        expect(conversationState).toBe(E2eiConversationState.NotEnabled);
    });

    it("identities can be queried by client id", async () => {
        const success = await browser.execute(async () => {
            const clientIdStr = window.crypto.randomUUID();
            const clientId = window.helpers.newClientId(clientIdStr);
            const cc = await window.helpers.ccInit({ clientId });
            const conversationId = await window.helpers.createConversation(cc);
            const identities = await cc.transaction(async (ctx) => {
                return await ctx.getDeviceIdentities(conversationId, [
                    clientId,
                ]);
            });

            return identities.pop()?.clientId === clientIdStr;
        });
        await expect(success).toBe(true);
    });

    it("identities can be queried by user id", async () => {
        const success = await browser.execute(async () => {
            const clientIdStr =
                "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com";
            const clientId = window.helpers.newClientId(clientIdStr);
            const cc = await window.helpers.ccInit({ clientId });
            const conversationId = await window.helpers.createConversation(cc);
            const identities = await cc.transaction(async (ctx) => {
                return await ctx.getUserIdentities(conversationId, [
                    "LcksJb74Tm6N12cDjFy7lQ",
                ]);
            });

            return (
                identities.values().next().value?.pop()?.clientId ===
                clientIdStr
            );
        });
        await expect(success).toBe(true);
    });
});
