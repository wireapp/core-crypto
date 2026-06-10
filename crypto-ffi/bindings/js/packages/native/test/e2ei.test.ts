import {
    ccInit,
    createConversation,
    newClientId,
    newDatabase,
    setup,
    teardown,
    TestPkiEnvironmentHooks,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";
import {
    cipherSuiteDefault,
    CoreCrypto,
    E2eiConversationState,
    PkiEnvironment,
    X509CredentialAcquisition,
    X509CredentialAcquisitionConfiguration,
} from "@wireapp/core-crypto/native";

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
    test("should be settable after mls init", async () => {
        // Get unset pki environment
        const cc = await ccInit({
            withBasicCredential: false,
        });

        let pkiEnv = await cc.getPkiEnvironment();
        expect(pkiEnv).toBeUndefined();

        // set pki environment
        const key = new Uint8Array(32);
        crypto.getRandomValues(key);
        const database = await newDatabase();
        pkiEnv = await PkiEnvironment.create(
            new TestPkiEnvironmentHooks(),
            database
        );
        await cc.setPkiEnvironment(pkiEnv);
        // We cannot compare the result of getPkiEnvironment()
        // with `pkiEnv`, due to uniffi hiding everything,
        // so just make sure it's not undefined.
        expect(await cc.getPkiEnvironment()).toBeDefined();

        await cc.setPkiEnvironment(undefined);
        expect(await cc.getPkiEnvironment()).toBeUndefined();
    });

    test("should be settable before mls init", async () => {
        const database = await newDatabase();

        const cc = CoreCrypto.new(database);
        let pkiEnv = await cc.getPkiEnvironment();

        if (pkiEnv != undefined) {
            throw new Error("Expected pkiEnv to be undefined.");
        }

        pkiEnv = await PkiEnvironment.create(
            new TestPkiEnvironmentHooks(),
            database
        );
        await cc.setPkiEnvironment(pkiEnv);
        expect(await cc.getPkiEnvironment()).toBeDefined();
    });

    test("should add a trust anchor certificate", async () => {
        const database = await newDatabase();
        const pkiEnvironment = await PkiEnvironment.create(
            new TestPkiEnvironmentHooks(),
            database
        );
        expect(
            async () => await pkiEnvironment.addTrustAnchor(TEST_CA_PEM)
        ).not.toThrow();
    });

    test("should add an intermediate certificate", async () => {
        const database = await newDatabase();
        const pkiEnvironment = await PkiEnvironment.create(
            new TestPkiEnvironmentHooks(),
            database
        );

        expect(
            async () => await pkiEnvironment.addIntermediateCert(TEST_CA_PEM)
        ).not.toThrow();
    });
});

describe("end to end identity", () => {
    test("should instantiate an x509 credential acquisition object", async () => {
        const database = await newDatabase();
        const pkiEnvironment = await PkiEnvironment.create(
            new TestPkiEnvironmentHooks(),
            database
        );

        const qualifiedClientId = newClientId();
        const config = X509CredentialAcquisitionConfiguration.new({
            acmeDirectoryUrl: "acme.example.com/directory",
            cipherSuite: cipherSuiteDefault(),
            displayName: "Alice Smith",
            clientId: qualifiedClientId,
            handle: "alice_wire",
            domain: "world.com",
            team: undefined,
            validityPeriodSecs: BigInt(3600),
        });

        const acquisition = new X509CredentialAcquisition(
            pkiEnvironment,
            config
        );

        expect(acquisition).toBeDefined();
    });

    test("should instantiate an x509 credential acquisition object from credential ref", async () => {
        const clientId = newClientId();
        const config = X509CredentialAcquisitionConfiguration.new({
            acmeDirectoryUrl: "acme.example.com/directory",
            cipherSuite: cipherSuiteDefault(),
            displayName: "Alice Smith",
            clientId: clientId,
            handle: "alice_wire",
            domain: "world.com",
            team: undefined,
            validityPeriodSecs: BigInt(3600),
        });

        const cc = await ccInit({
            withBasicCredential: true,
            cipherSuite: cipherSuiteDefault(),
            clientId,
            withPkiEnvironment: true,
        });

        const pkiEnvironment = await cc.getPkiEnvironment();

        const [credentialRef] = await cc.findCredentials({ clientId });

        const acquisition =
            await X509CredentialAcquisition.newFromCredentialRef(
                pkiEnvironment!,
                config,
                credentialRef!
            );

        expect(acquisition).toBeDefined();
    });

    test("should not be enabled on conversation with basic credential", async () => {
        const cc = await ccInit();
        const conversationId = await createConversation(cc);
        const conversationState = await cc.transaction(async (ctx) => {
            return await ctx.e2eiConversationState(conversationId);
        });
        expect(conversationState).toBe(E2eiConversationState.NotEnabled);
    });

    test("identities can be queried by client id", async () => {
        const clientId = newClientId();
        const cc = await ccInit({ clientId });
        const conversationId = await createConversation(cc);
        const identities = await cc.transaction(async (ctx) => {
            return await ctx.getDeviceIdentities(conversationId, [clientId]);
        });

        console.log(JSON.stringify(identities));

        expect(identities.pop()?.clientId?.equals(clientId));
    });

    test("identities can be queried by user id", async () => {
        const clientId = newClientId();
        const cc = await ccInit({ clientId });
        const conversationId = await createConversation(cc);
        const identities = await cc.transaction(async (ctx) => {
            return await ctx.getUserIdentities(conversationId, [
                clientId.deserialize().userId,
            ]);
        });

        expect(
            identities.values().next().value?.pop()?.clientId?.equals(clientId)
        );
    });
});
