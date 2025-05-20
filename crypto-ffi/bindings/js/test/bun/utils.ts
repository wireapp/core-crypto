import {
    Ciphersuite,
    type CommitBundle,
    type ConversationId,
    CoreCrypto,
    CoreCryptoLogLevel,
    CredentialType,
    DatabaseKey,
    type GroupInfoBundle,
    type MlsTransport,
    type MlsTransportResponse,
    setLogger,
    setMaxLogLevel,
    initWasmModule,
} from "../../src/CoreCrypto";
import { CONV_ID as WEB_CONV_ID } from "../wdio/utils";

export { ALICE_ID, BOB_ID, SESSION_ID } from "../wdio/utils";
export const CONV_ID = new TextEncoder().encode(WEB_CONV_ID);

const CC_INSTANCES: CoreCrypto[] = [];

// Logging can be adjusted via the CC_TEST_LOG_LEVEL variable:
// 0 = no logs
// 1 = browser logs
// 2 = browser logs + CoreCrypto logs
const logLevel = Number(process.env["CC_TEST_LOG_LEVEL"] || "0");

const DEFAULT_CIPHERSUITE =
    Ciphersuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

interface DeliveryService extends MlsTransport {
    getLatestCommitBundle: () => Promise<CommitBundle>;
}

class TestDeliveryService implements DeliveryService {
    private latestCommitBundle?: CommitBundle;

    async sendCommitBundle(
        commitBundle: CommitBundle
    ): Promise<MlsTransportResponse> {
        this.latestCommitBundle = commitBundle;
        return "success";
    }

    async sendMessage(): Promise<MlsTransportResponse> {
        return "success";
    }

    async getLatestCommitBundle(): Promise<CommitBundle> {
        if (this.latestCommitBundle === undefined) {
            throw new Error("No commit bundle yet!");
        }
        return this.latestCommitBundle;
    }
}

export const DELIVERY_SERVICE = new TestDeliveryService();

export async function setup() {
    await initWasmModule();
    if (logLevel >= 2) {
        setLogger({
            log: (_level, message: string, context) => {
                console.log(message, context);
            },
        });
        setMaxLogLevel(CoreCryptoLogLevel.Debug);
    }
}

export async function teardown() {
    // Delete all core crypto instances.
    while (CC_INSTANCES.length > 0) {
        const cc = CC_INSTANCES.pop();
        if (cc === undefined) {
            continue;
        }
        cc.close();
    }
}

/**
 * Initialize a {@link CoreCrypto}
 * @param clientName The client name used to initialize.
 *
 * @returns {Promise<CoreCrypto>}
 */
export async function ccInit(clientName: string): Promise<CoreCrypto> {
    const encoder = new TextEncoder();
    const clientId = encoder.encode(clientName);

    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    const clientConfig = {
        databaseName: clientName,
        key: new DatabaseKey(key),
        ciphersuites: [DEFAULT_CIPHERSUITE],
        clientId,
    };
    const instance = await CoreCrypto.init(clientConfig);
    await instance.provideTransport(DELIVERY_SERVICE);
    return instance;
}

/**
 * Create a conversation on a {@link CoreCrypto} instance that has
 * been initialized before via {@link ccInit}.
 *
 * @param cc The {@link CoreCrypto} instance that will create the conversation.
 * @param conversationId The id that the conversation will be created with.
 *
 * @returns {Promise<void>}
 *
 */
export async function createConversation(
    cc: CoreCrypto,
    conversationId: ConversationId
): Promise<void> {
    await cc.transaction((ctx) =>
        ctx.createConversation(conversationId, CredentialType.Basic)
    );
}

/**
 * Invite {@link cc2} to a previously created conversation on the
 * instance of {@link cc1} (via {@link createConversation}).
 *
 * @param cc1 The {@link CoreCrypto} instance on which the
 * conversation was created previously.
 * @param cc2 The {@link CoreCrypto} instance that will be
 * invited.
 * @param conversationId The id of the previously created conversation.
 *
 * @returns {Promise<GroupInfoBundle>} The resulting group info.
 */
export async function invite(
    cc1: CoreCrypto,
    cc2: CoreCrypto,
    conversationId: ConversationId
): Promise<GroupInfoBundle> {
    const [kp] = await cc2.transaction((ctx) =>
        ctx.clientKeypackages(DEFAULT_CIPHERSUITE, CredentialType.Basic, 1)
    );
    await cc1.transaction((ctx) =>
        ctx.addClientsToConversation(conversationId, [kp!])
    );
    const { groupInfo, welcome } =
        await DELIVERY_SERVICE.getLatestCommitBundle();

    await cc2.transaction((ctx) => ctx.processWelcomeMessage(welcome!));

    return groupInfo;
}

/**
 * Inside a previously created conversation, {@link cc1} encrypts
 * {@link message}, sends it to {@link cc2}, who then decrypts it.
 * This procedure is then repeated vice versa.
 *
 * @param cc1 The first of the conversation.
 * @param cc2 The second member of the conversation.
 * @param conversationId The id of the conversation.
 * @param message The message encrypted, sent, and decrypted once in each
 * direction.
 *
 * @returns {Promise<(Uint8Array | null)[]>} A two-element list, containing the decrypted {@link message} by
 * {@link cc1} and {@link cc2}, in that order.
 */
export async function roundTripMessage(
    cc1: CoreCrypto,
    cc2: CoreCrypto,
    conversationId: ConversationId,
    message: Uint8Array
): Promise<(Uint8Array | null)[]> {
    const encryptedByClient1 = await cc1.transaction(async (ctx) => {
        return await ctx.encryptMessage(conversationId, message);
    });
    const decryptedByClient2 = await cc2.transaction(async (ctx) => {
        return await ctx.decryptMessage(conversationId, encryptedByClient1);
    });

    const encryptedByClient2 = await cc2.transaction(async (ctx) => {
        return await ctx.encryptMessage(conversationId, message);
    });
    const decryptedByClient1 = await cc1.transaction(async (ctx) => {
        return await ctx.decryptMessage(conversationId, encryptedByClient2);
    });

    const decryptedMessage1 =
        decryptedByClient1.message !== undefined
            ? decryptedByClient1.message
            : null;
    const decryptedMessage2 =
        decryptedByClient2.message !== undefined
            ? decryptedByClient2.message
            : null;
    return [decryptedMessage1, decryptedMessage2];
}

/**
 * Initialize a {@link CoreCrypto} instance without initializing MLS.
 * Instead, initialize proteus.
 *
 * @param clientName the client name used to initialize.
 *
 * @returns {Promise<CoreCrypto>}
 */
export async function proteusInit(clientName: string): Promise<CoreCrypto> {
    const encoder = new TextEncoder();
    const clientId = encoder.encode(clientName);

    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    const clientConfig = {
        databaseName: clientName,
        key: new DatabaseKey(key),
        clientId,
    };
    const instance = await CoreCrypto.deferredInit(clientConfig);
    await instance.provideTransport(DELIVERY_SERVICE);
    return instance;
}

/**
 * Create a proteus session on the {@link CoreCrypto} instance of
 * {@link cc1}, with the prekey of {@link cc2}.
 *
 * @param cc1 The {@link CoreCrypto} instance which will
 * create the session.
 * @param cc2 The {@link CoreCrypto} instance whose pre key will
 * be used.
 * @param sessionId The id of session that will be created.
 *
 * @returns {Promise<void>}
 */
export async function newProteusSessionFromPrekey(
    cc1: CoreCrypto,
    cc2: CoreCrypto,
    sessionId: string
): Promise<void> {
    const cc2Prekey = await cc2.transaction(async (ctx) => {
        return await ctx.proteusNewPrekey(10);
    });

    await cc1.transaction(async (ctx) => {
        return await ctx.proteusSessionFromPrekey(sessionId, cc2Prekey);
    });
}

/**
 * Create a proteus session on the {@link CoreCrypto} instance of
 * {@link client2}, from a message encrypted by {@link client1} in a session
 * created previously via {@link newProteusSessionFromPrekey}.
 *
 * @param client1 The {@link CoreCrypto} instance which used its
 * existing session to encrypt the message.
 * @param client2 The {@link CoreCrypto} instance whose session will
 * be created.
 * @param sessionId The id of session that will be created.
 * For simplicity, this must match the id of the previously created session.
 * @param message The message to encrypt and create the message from.
 *
 * @returns {Promise<string | null>} the decrypted {@link message}.
 */
export async function newProteusSessionFromMessage(
    cc1: CoreCrypto,
    cc2: CoreCrypto,
    sessionId: string,
    messageBytes: Uint8Array
): Promise<Uint8Array> {
    const encrypted = await cc1.transaction(async (ctx) => {
        return await ctx.proteusEncrypt(sessionId, messageBytes);
    });

    const decrypted = await cc2.transaction(async (ctx) => {
        return await ctx.proteusSessionFromMessage(sessionId, encrypted);
    });

    return decrypted;
}
