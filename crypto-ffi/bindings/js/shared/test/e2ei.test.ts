import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { E2eiConversationState } from "#core-crypto";
import { expect } from "chai";

const TEST_CA_PEM = `-----BEGIN CERTIFICATE-----
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

const TEST_CA_PEM_2 = `-----BEGIN CERTIFICATE-----
MIIBgzCCATWgAwIBAgIUeN2a19U9hEAnnXPaKGG8/IBnN3EwBQYDK2VwMDcxFTAT
BgNVBAMMDFRlc3QgUm9vdCBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYT
AlVTMB4XDTI2MDgwNjEyNDI0MFoXDTM2MDgwMzEyNDI0MFowNzEVMBMGA1UEAwwM
VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCVVMwKjAF
BgMrZXADIQCcdQkyHFLytpptb0OsLfDq2GhNmIf2EYRih5jeT1SKvaNTMFEwHQYD
VR0OBBYEFIHxxlwJp4caZR40MyYvQHFuKKdWMB8GA1UdIwQYMBaAFIHxxlwJp4ca
ZR40MyYvQHFuKKdWMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA5Ssdm0IaTfSc
lQjd5t/n3C5DLK70tXC7x6Qpdhn57cNqtjxVQnL7R7yr8ZHCps1+XuZgpaEbVx//
r9IJmL6kDQ==
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
        const success = await runOnPlatform(async () => {
            const cc = await helpers.ccInit({
                withBasicCredential: false,
            });

            let pkiEnv = await cc.getPkiEnvironment();

            if (pkiEnv != undefined) {
                throw new Error("Expected pkiEnv to be undefined.");
            }

            // set pki environment
            const database = await helpers.newDatabase();
            pkiEnv = await ccModule.PkiEnvironment.create(
                pkiEnvironmentHooks,
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
        expect(success).to.equal(true);
    });

    it("should be settable before mls init", async () => {
        const success = await runOnPlatform(async () => {
            const database = await helpers.newDatabase();
            const cc = ccModule.CoreCrypto.new(database);
            let pkiEnv = await cc.getPkiEnvironment();

            if (pkiEnv != undefined) {
                throw new Error("Expected pkiEnv to be undefined.");
            }

            pkiEnv = await ccModule.PkiEnvironment.create(
                pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pkiEnv);

            return (await cc.getPkiEnvironment()) != undefined;
        });
        expect(success).to.equal(true);
    });

    it("should add multiple trust anchor certificates", async () => {
        const pems = await runOnPlatform(
            async (certPem, certPem2) => {
                const database = await helpers.newDatabase();
                const pkiEnvironment = await ccModule.PkiEnvironment.create(
                    pkiEnvironmentHooks,
                    database
                );
                await pkiEnvironment.addTrustAnchor(certPem);
                await pkiEnvironment.addTrustAnchor(certPem2);
                return await pkiEnvironment.getTrustAnchors();
            },
            TEST_CA_PEM,
            TEST_CA_PEM_2
        );

        expect(pems.length).to.equal(2);
        expect(pems[0]).to.equal(TEST_CA_PEM);
        expect(pems[1]).to.equal(TEST_CA_PEM_2);
    });

    it("should remove a trust anchor certificate", async () => {
        const pems = await runOnPlatform(
            async (certPem, certPem2) => {
                const pem2Fingerprint =
                    "03a2be6b2d86f5d1582c1ccbe98390030bc637a05a11f97092c0efb1e35142b9";

                const fingerprintBytes = new Uint8Array(
                    pem2Fingerprint
                        .match(/.{1,2}/g)!
                        .map((byte) => parseInt(byte, 16))
                );

                const database = await helpers.newDatabase();
                const pkiEnvironment = await ccModule.PkiEnvironment.create(
                    pkiEnvironmentHooks,
                    database
                );
                await pkiEnvironment.addTrustAnchor(certPem);
                await pkiEnvironment.addTrustAnchor(certPem2);
                await pkiEnvironment.removeTrustAnchor(fingerprintBytes);
                return await pkiEnvironment.getTrustAnchors();
            },
            TEST_CA_PEM,
            TEST_CA_PEM_2
        );

        expect(pems.length).to.equal(1);
        expect(pems[0]).to.equal(TEST_CA_PEM);
    });
});

describe("end to end identity", () => {
    it("should instantiate an x509 credential acquisition object", async () => {
        const acquisitionCreated = await runOnPlatform(async () => {
            const database = await helpers.newDatabase();
            const pkiEnvironment = await ccModule.PkiEnvironment.create(
                pkiEnvironmentHooks,
                database
            );

            const qualifiedClientId = helpers.newClientId();
            const config = ccModule.X509CredentialAcquisitionConfiguration.new({
                acmeDirectoryUrl: "acme.example.com/directory",
                cipherSuite: ccModule.cipherSuiteDefault(),
                displayName: "Alice Smith",
                clientId: qualifiedClientId,
                handle: "alice_wire",
                domain: "world.com",
                team: undefined,
                validityPeriodSecs: BigInt(3600),
            });

            const acquisition = new ccModule.X509CredentialAcquisition(
                pkiEnvironment,
                config
            );

            return acquisition !== undefined;
        });

        expect(acquisitionCreated).to.equal(true);
    });

    it("should instantiate an x509 credential acquisition object from credential ref", async () => {
        const acquisitionCreated = await runOnPlatform(async () => {
            const clientId = helpers.newClientId();
            const config = ccModule.X509CredentialAcquisitionConfiguration.new({
                acmeDirectoryUrl: "acme.example.com/directory",
                cipherSuite: ccModule.cipherSuiteDefault(),
                displayName: "Alice Smith",
                clientId,
                handle: "alice_wire",
                domain: "world.com",
                team: undefined,
                validityPeriodSecs: BigInt(3600),
            });

            const cc = await helpers.ccInit({
                withBasicCredential: true,
                clientId,
                withPkiEnvironment: true,
            });

            const pkiEnvironment = await cc.getPkiEnvironment();

            const [credentialRef] = await cc.findCredentials({ clientId });

            const acquisition =
                await ccModule.X509CredentialAcquisition.newFromCredentialRef(
                    pkiEnvironment!,
                    config,
                    credentialRef!
                );

            return acquisition !== undefined;
        });

        expect(acquisitionCreated).to.equal(true);
    });

    it("should not be enabled on conversation with basic credential", async () => {
        const conversationState = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const conversationId = await helpers.createConversation(cc);
            return await cc.transaction(async (ctx) => {
                return await ctx.e2eiConversationState(conversationId);
            });
        });
        expect(conversationState).to.equal(E2eiConversationState.NotEnabled);
    });

    it("identities can be queried by client id", async () => {
        const success = await runOnPlatform(async () => {
            const clientId = helpers.newClientId();
            const cc = await helpers.ccInit({ clientId });
            const conversationId = await helpers.createConversation(cc);
            const identities = await cc.transaction(async (ctx) => {
                return await ctx.getDeviceIdentities(conversationId, [
                    clientId,
                ]);
            });

            return identities.pop()?.clientId?.equals(clientId);
        });
        expect(success).to.equal(true);
    });

    it("identities can be queried by user id", async () => {
        const success = await runOnPlatform(async () => {
            const clientId = helpers.newClientId();
            const cc = await helpers.ccInit({ clientId });
            const conversationId = await helpers.createConversation(cc);
            const identities = await cc.transaction(async (ctx) => {
                return await ctx.getUserIdentities(conversationId, [
                    clientId.deserialize().userId,
                ]);
            });

            const identity = identities.values().next().value?.pop();
            return identity?.clientId?.equals(clientId);
        });
        expect(success).to.equal(true);
    });
});
