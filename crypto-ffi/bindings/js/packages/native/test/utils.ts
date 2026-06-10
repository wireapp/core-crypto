import { rm } from "node:fs/promises";
import assert from "node:assert";
import {
    CipherSuite,
    type CommitBundle,
    ConversationId,
    CoreCrypto,
    CoreCryptoLogLevel,
    CredentialType,
    DatabaseKey,
    type HistorySecret,
    type MlsTransportData,
    type GroupInfoBundle,
    type MlsTransport,
    setLogger,
    setMaxLogLevel,
    ClientId,
    Credential,
    Welcome,
    KeyPackage,
    HttpMethod,
    HttpHeader,
    PkiEnvironment,
    type PkiEnvironmentHooks,
} from "@wireapp/core-crypto/native";
import { Database } from "@wireapp/core-crypto/native";

// Logging can be adjusted via the CC_TEST_LOG_LEVEL variable:
// 0 = no logs
// 1 = browser logs
// 2 = browser logs + CoreCrypto logs
const logLevel = Number(process.env["CC_TEST_LOG_LEVEL"] || "0");

const DEFAULT_CIPHERSUITE =
    CipherSuite.Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519;
const SQLITE_SIDE_CAR_SUFFIXES = ["", "-journal", "-shm", "-wal"] as const;
export const DATABASE_LOCATIONS = new Set<string>();

interface DeliveryService extends MlsTransport {
    getLatestCommitBundle: () => Promise<CommitBundle>;
}

export class TestDeliveryService implements DeliveryService {
    private latestCommitBundle?: CommitBundle;

    async sendCommitBundle(commitBundle: CommitBundle): Promise<void> {
        this.latestCommitBundle = commitBundle;
    }

    async sendMessage(): Promise<void> {}

    prepareForTransport(secret: HistorySecret): Promise<MlsTransportData> {
        return Promise.resolve(secret.clientId.copyBytes());
    }

    async getLatestCommitBundle(): Promise<CommitBundle> {
        if (this.latestCommitBundle === undefined) {
            throw new Error("No commit bundle yet!");
        }
        return this.latestCommitBundle;
    }
}

export const DELIVERY_SERVICE = new TestDeliveryService();

export class TestPkiEnvironmentHooks implements PkiEnvironmentHooks {
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
    }

    async authenticate(
        _idp: string,
        _keyAuth: string,
        _acmeAud: string,
        _acquisition_snapshot: Uint8Array
    ) {
        return "dummy-id-token";
    }

    async getBackendNonce() {
        return "dummy-backend-nonce";
    }

    async fetchBackendAccessToken(_dpop: string) {
        return "dummy-backend-token";
    }
}

export async function setup() {
    if (logLevel >= 2) {
        setLogger({
            log: (_level, message: string, context) => {
                console.log(message, context);
            },
        });
        setMaxLogLevel(CoreCryptoLogLevel.Debug);
    }
}

/**
 * Open a database that gets wiped after tests run.
 */
export async function newDatabase(databaseName?: string) {
    const keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);
    const key = new DatabaseKey(keyBytes);
    const location = databaseName ?? `bun-test-db-${crypto.randomUUID()}`;

    const database = await Database.open(location, key);

    const resolvedLocation = await database.getLocation();
    assert(resolvedLocation !== undefined);
    DATABASE_LOCATIONS.add(resolvedLocation);
    return database;
}

export async function teardown() {
    const locations = [...DATABASE_LOCATIONS];
    DATABASE_LOCATIONS.clear();

    await Promise.all(
        locations.map((location) =>
            Promise.all(
                SQLITE_SIDE_CAR_SUFFIXES.map((suffix) =>
                    rm(`${location}${suffix}`, { force: true })
                )
            )
        )
    );
}

type CcInitOptions =
    | {
          withBasicCredential: false;
          clientId?: ClientId;
          database?: Database;
          deliveryService?: DeliveryService;
          withPkiEnvironment?: boolean;
      }
    | {
          withBasicCredential?: true;
          cipherSuite?: CipherSuite;
          clientId?: ClientId;
          database?: Database;
          deliveryService?: DeliveryService;
          withPkiEnvironment?: boolean;
      };

/**
 * Initialize a {@link CoreCrypto} with a database.
 * @param clientName The client name used to initialize.
 *
 * @returns {Promise<CoreCrypto>}
 */
export async function ccInit(
    options: CcInitOptions = {
        withBasicCredential: true,
        cipherSuite: DEFAULT_CIPHERSUITE,
    }
): Promise<CoreCrypto> {
    const clientId = options.clientId ?? newClientId();
    const database = options.database ?? (await newDatabase());
    const deliveryService = options.deliveryService ?? DELIVERY_SERVICE;

    const cc = CoreCrypto.new(database);

    if (options.withPkiEnvironment) {
        const pkiEnvironment = await PkiEnvironment.create(
            new TestPkiEnvironmentHooks(),
            database
        );
        await cc.setPkiEnvironment(pkiEnvironment);
    }

    // this also sets the default if undefined
    // ?? would break type narrowing of CcInitOptions
    const withBasicCredential = options.withBasicCredential !== false;

    await cc.transaction(async (ctx) => {
        await ctx.mlsInit(clientId, deliveryService);
        if (withBasicCredential) {
            const cipherSuite = options.cipherSuite ?? DEFAULT_CIPHERSUITE;
            await ctx.addCredential(Credential.basic(cipherSuite, clientId));
        }
    });
    return cc;
}

export async function generateKeyPackage(
    cc: CoreCrypto,
    cipherSuite?: CipherSuite
): Promise<KeyPackage> {
    if (cipherSuite === undefined) {
        cipherSuite = DEFAULT_CIPHERSUITE;
    }
    return await cc.transaction(async (ctx) => {
        const [credentialRef] = await cc.findCredentials({
            cipherSuite: cipherSuite,
            credentialType: CredentialType.Basic,
        });
        return await ctx.generateKeyPackage(credentialRef!);
    });
}

export function newConversationId(): ConversationId {
    const uuid = crypto.randomUUID();
    return new ConversationId(Uint8Array.from(uuid));
}

export function newClientId(): ClientId {
    const userId = crypto.randomUUID();
    const deviceIdBytes = crypto.getRandomValues(new Uint8Array(8));
    const deviceId = [...deviceIdBytes]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    return new ClientId(userId, deviceId, "wire.com");
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
    cc: CoreCrypto
): Promise<ConversationId> {
    const conversationId = newConversationId();
    const [credentialRef] = await cc.getCredentials();
    await cc.transaction(async (ctx) => {
        await ctx.createConversation(conversationId, credentialRef!);
    });
    return conversationId;
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
    conversationId: ConversationId,
    cipherSuite?: CipherSuite
): Promise<GroupInfoBundle> {
    const kp = await generateKeyPackage(cc2, cipherSuite);
    await cc1.transaction((ctx) =>
        ctx.addClientsToConversation(conversationId, [kp])
    );
    const { groupInfo, welcome } =
        await DELIVERY_SERVICE.getLatestCommitBundle();

    await cc2.transaction((ctx) =>
        ctx.processWelcomeMessage(new Welcome(welcome!.serialize()))
    );

    return groupInfo;
}

/**
 * Remove {@link cc2} from a previously created conversation on the
 * instance of {@link cc} (via {@link createConversation}).
 *
 * @param cc The {@link CoreCrypto} instance on which the
 * conversation was created previously.
 * @param clientIdToRemove The client id of the {@link CoreCrypto} instance that will be
 * removed.
 * @param conversationId The id of the previously created conversation.
 *
 * @returns {Promise<GroupInfoBundle>} The resulting group info.
 *
 * @throws Error if {@link cc} or {@link cc2} instances cannot be found.
 */
export async function remove(
    cc: CoreCrypto,
    clientIdToRemove: ClientId,
    conversationId: ConversationId
): Promise<GroupInfoBundle> {
    await cc.transaction((ctx) =>
        ctx.removeClientsFromConversation(conversationId, [clientIdToRemove])
    );
    const commitBundle = await DELIVERY_SERVICE.getLatestCommitBundle();

    return commitBundle.groupInfo;
}

/**
 * Consume the last commit message on {@link cc}
 *
 * @param cc The {@link CoreCrypto} instance on which to consume the commit.
 * @param conversationId The id of the previously created conversation.
 *
 * @returns {Promise<void>}
 *
 * @throws Error if {@link cc} instances cannot be found.
 */
export async function consumeLastestCommit(
    cc: CoreCrypto,
    conversationId: ConversationId
): Promise<void> {
    const commitBundle = await DELIVERY_SERVICE.getLatestCommitBundle();
    await cc.transaction((ctx) =>
        ctx.decryptMessage(conversationId, commitBundle.commit)
    );
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
    message: string
): Promise<string[]> {
    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);

    const encryptedByClient1 = await cc1.transaction(async (ctx) => {
        return await ctx.encryptMessage(conversationId, messageBytes);
    });
    const decryptedByClient2 = await cc2.transaction(async (ctx) => {
        return await ctx.decryptMessage(conversationId, encryptedByClient1);
    });

    const encryptedByClient2 = await cc2.transaction(async (ctx) => {
        return await ctx.encryptMessage(conversationId, messageBytes);
    });
    const decryptedByClient1 = await cc1.transaction(async (ctx) => {
        return await ctx.decryptMessage(conversationId, encryptedByClient2);
    });

    const decoder = new TextDecoder();
    const result1 = decoder.decode(decryptedByClient1.message);
    const result2 = decoder.decode(decryptedByClient2.message);

    return [result1, result2];
}

/**
 * Initialize a {@link CoreCrypto} instance without initializing MLS.
 * Instead, initialize proteus.
 *
 * @param clientName the client name used to initialize.
 *
 * @returns {Promise<CoreCrypto>}
 */
export async function proteusInit(
    clientName: string,
    databaseName?: string
): Promise<CoreCrypto> {
    const database = await newDatabase(databaseName ?? clientName);

    const instance = CoreCrypto.new(database);
    await instance.transaction(async (ctx) => {
        await ctx.proteusInit();
    });

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
