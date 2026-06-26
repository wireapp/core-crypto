import {
    type CipherSuite,
    type ClientId,
    type CommitBundle,
    type ConversationId,
    type CoreCrypto,
    type CoreCryptoLogLevel,
    type Database,
    type GroupInfoBundle,
    type HistorySecret,
    type KeyPackage,
    type MlsTransport,
    type MlsTransportData,
    type PkiEnvironmentHooks,
} from "#core-crypto";

import {
    runOnPlatform,
    sharedSetup as platformSharedSetup,
    sharedTeardown as platformSharedTeardown,
    setPlatformHelpers,
} from "#shared-utils";

export { runOnPlatform } from "#shared-utils";

type ccModuleType = typeof import("#core-crypto");

declare global {
    var ccModule: ccModuleType;
    var platformHelpers: PlatformHelpers;
    var helpers: Helpers;
    var _latestCommitBundle: CommitBundle;
    var deliveryService: DeliveryService;
    var pkiEnvironmentHooks: PkiEnvironmentHooks;
    var recordedLogs: LogEntry[];
}

interface LogEntry {
    level: number;
    message: string;
    context: string;
}

export const logLevel = Number(process.env["CC_TEST_LOG_LEVEL"] || "0");

export interface DeliveryService extends MlsTransport {
    getLatestCommitBundle: () => Promise<CommitBundle>;
}

export async function sharedSetup() {
    await platformSharedSetup();
    await setHelpers();
    // Logging can be adjusted via the CC_TEST_LOG_LEVEL variable:
    // 0 = no logs
    // 1 = browser logs
    // 2 = browser logs + CoreCrypto logs
    await setLogger();
    await setDeliveryService();
}

export async function sharedTeardown() {
    await platformSharedTeardown();
}

export type CcInitOptions =
    | {
          withBasicCredential: false;
          clientId?: ClientId;
          database?: Database;
          withPkiEnvironment?: boolean;
      }
    | {
          withBasicCredential?: true;
          cipherSuite?: CipherSuite;
          clientId?: ClientId;
          database?: Database;
          withPkiEnvironment?: boolean;
      };

export interface Helpers {
    newClientId(): ClientId;
    newConversationId(): ConversationId;
    newDatabase(): Promise<Database>;
    generateKeyPackage(
        cc: CoreCrypto,
        cipherSuite?: CipherSuite
    ): Promise<KeyPackage>;
    ccInit: (options?: CcInitOptions) => Promise<CoreCrypto>;
    recordLogs(): void;
    createConversation(cc: CoreCrypto): Promise<ConversationId>;
    invite(
        cc1: CoreCrypto,
        cc2: CoreCrypto,
        conversationId: ConversationId,
        cipherSuite?: CipherSuite
    ): Promise<GroupInfoBundle>;
    remove(
        cc: CoreCrypto,
        clientIdToRemove: ClientId,
        conversationId: ConversationId
    ): Promise<GroupInfoBundle>;
    consumeLastestCommit(
        cc: CoreCrypto,
        conversationId: ConversationId
    ): Promise<void>;
    roundTripMessage(
        cc1: CoreCrypto,
        cc2: CoreCrypto,
        conversationId: ConversationId,
        message: string
    ): Promise<(string | null)[]>;
    proteusInit(): Promise<CoreCrypto>;
    newProteusSessionFromPrekey(
        cc1: CoreCrypto,
        cc2: CoreCrypto,
        sessionId: string
    ): Promise<void>;
    newProteusSessionFromMessage(
        cc1: CoreCrypto,
        cc2: CoreCrypto,
        sessionId: string,
        message: string
    ): Promise<string | null>;
}

export interface PlatformHelpers {
    newDatabase(): Promise<Database>;
}

async function setHelpers() {
    await setPlatformHelpers();
    await runOnPlatform(() => {
        class HelpersImpl implements Helpers {
            /**
             * Construct a new ClientId
             **/
            newClientId(): ClientId {
                const uuid = crypto.randomUUID();
                const userId = new ccModule.Uuid(uuid);
                const deviceIdBytes = crypto.getRandomValues(new Uint8Array(8));
                const deviceIdString = [...deviceIdBytes]
                    .map((byte) => byte.toString(16).padStart(2, "0"))
                    .join("");
                const deviceId =
                    ccModule.DeviceId.fromHexString(deviceIdString);
                return new ccModule.ClientId(userId, deviceId, "wire.com");
            }

            /**
             * Construct a new ConversationId
             **/
            newConversationId(): ConversationId {
                const conversationIdStr = crypto.randomUUID();
                const encoder = new TextEncoder();
                return new ccModule.ConversationId(
                    encoder.encode(conversationIdStr)
                );
            }

            async newDatabase(): Promise<Database> {
                return platformHelpers.newDatabase();
            }

            async generateKeyPackage(
                cc: CoreCrypto,
                cipherSuite?: CipherSuite
            ): Promise<KeyPackage> {
                if (cipherSuite === undefined) {
                    cipherSuite = ccModule.cipherSuiteDefault();
                }
                const [credentialRef] = await cc.findCredentials({
                    cipherSuite: cipherSuite,
                    credentialType: ccModule.CredentialType.Basic,
                });
                return await cc.transaction(async (ctx) => {
                    return await ctx.generateKeyPackage(credentialRef!);
                });
            }

            /**
             * Initialize a {@link CoreCrypto} instance.
             *
             * @param clientId The ClientId used to initialize CC.
             * @param withBasicCredential When set (default), adds a basic credential to the CC instance
             * @param cipherSuite Set the cipherSuite to use, if not set the default cipherSuite will be used
             *
             * @returns {Promise<void>}
             */
            async ccInit(
                options: CcInitOptions = {
                    withBasicCredential: true,
                    cipherSuite: ccModule.cipherSuiteDefault(),
                    withPkiEnvironment: false,
                }
            ): Promise<CoreCrypto> {
                const clientId = options.clientId ?? helpers.newClientId();
                const db = options.database ?? (await helpers.newDatabase());
                const cc = ccModule.CoreCrypto.new(db);

                if (options.withPkiEnvironment) {
                    const pkiEnvironment = await ccModule.PkiEnvironment.create(
                        pkiEnvironmentHooks,
                        db
                    );
                    await cc.setPkiEnvironment(pkiEnvironment);
                }

                // this also sets the default if undefined
                // ?? would break type narrowing of CcInitOptions
                const withBasicCredential =
                    options.withBasicCredential !== false;

                await cc.transaction(async (ctx) => {
                    await ctx.mlsInit(clientId, deliveryService);
                    if (withBasicCredential) {
                        const cipherSuite =
                            options.cipherSuite ??
                            ccModule.cipherSuiteDefault();
                        await ctx.addCredential(
                            ccModule.Credential.basic(cipherSuite, clientId)
                        );
                    }
                });
                return cc;
            }

            /**
             * Records logs by setting a logger and maximum log level in the browser's context.
             * The logs are stored in a global variable `recordedLogs` for further retrieval.
             *
             * @return {void}
             */
            recordLogs(): void {
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    ccModule;
                globalThis.recordedLogs = [];

                setLogger({
                    log: (level: number, message: string, context: string) => {
                        console.log(message, context);
                        recordedLogs.push({
                            level: level,
                            message: message,
                            context: context,
                        });
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
            }

            /**
             * Create a conversation on a {@link CoreCrypto} instance that has
             * been initialized before via {@link ccInit}.
             *
             * @param cc The {@link CoreCrypto} instance has been
             * initialized with.
             * @returns {Promise<ConversationId>} The ConversationOd of the created Conversation.
             *
             * @throws Error if the instance with {@link clientName} cannot be found.
             */
            async createConversation(cc: CoreCrypto): Promise<ConversationId> {
                const conversationId = helpers.newConversationId();
                const [credentialRef] = await cc.getCredentials();
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conversationId,
                        credentialRef!
                    );
                });
                return conversationId;
            }

            /**
             * Invite {@link client2} to a previously created conversation on the
             * instance of {@link client1} (via {@link createConversation}).
             *
             * @param cc1 The {@link CoreCrypto} instance on which the
             * conversation was created previously.
             * @param cc2 The {@link CoreCrypto} instance that will be
             * invited.
             * @param conversationId The id of the previously created conversation.
             *
             * @returns {Promise<GroupInfoBundle>} The resulting group info.
             *
             * @throws Error if {@link client1} or {@link client2} instances cannot be found.
             */
            async invite(
                cc1: CoreCrypto,
                cc2: CoreCrypto,
                conversationId: ConversationId,
                cipherSuite?: CipherSuite
            ): Promise<GroupInfoBundle> {
                const kp = await helpers.generateKeyPackage(cc2, cipherSuite);
                const clients = await cc1.getClientIds(conversationId);
                console.log("clients");
                console.log(clients);

                console.log("inviting bob");
                await cc1.transaction((ctx) =>
                    ctx.addClientsToConversation(conversationId, [kp])
                );
                console.log("processing welcome");
                const commitBundle =
                    await deliveryService.getLatestCommitBundle();
                await cc2.transaction((ctx) =>
                    ctx.processWelcomeMessage(commitBundle.welcome!)
                );

                return commitBundle.groupInfo;
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
            async remove(
                cc: CoreCrypto,
                clientIdToRemove: ClientId,
                conversationId: ConversationId
            ): Promise<GroupInfoBundle> {
                await cc.transaction((ctx) =>
                    ctx.removeClientsFromConversation(conversationId, [
                        clientIdToRemove,
                    ])
                );
                const commitBundle =
                    await deliveryService.getLatestCommitBundle();

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
            async consumeLastestCommit(
                cc: CoreCrypto,
                conversationId: ConversationId
            ): Promise<void> {
                const commitBundle =
                    await deliveryService.getLatestCommitBundle();
                await cc.transaction((ctx) =>
                    ctx.decryptMessage(conversationId, commitBundle.commit)
                );
            }

            /**
             * Inside a previously created conversation, {@link client1} encrypts
             * {@link message}, sends it to {@link client2}, who then decrypts it.
             * This procedure is then repeated vice versa.
             *
             * @param cc1 The first of the conversation.
             * @param cc2 The second member of the conversation.
             * @param conversationId The id of the conversation.
             * @param message The message encrypted, sent, and decrypted once in each
             * direction.
             *
             * @returns {Promise<(string)[]>} A two-element list, containing the decrypted {@link message} by
             * {@link client1} and {@link client2}, in that order.
             */
            async roundTripMessage(
                cc1: CoreCrypto,
                cc2: CoreCrypto,
                conversationId: ConversationId,
                message: string
            ): Promise<string[]> {
                const encoder = new TextEncoder();
                const messageBytes = encoder.encode(message);

                const encryptedByClient1 = await cc1.transaction(
                    async (ctx) => {
                        return await ctx.encryptMessage(
                            conversationId,
                            messageBytes
                        );
                    }
                );
                const decryptedByClient2 = await cc2.transaction(
                    async (ctx) => {
                        return await ctx.decryptMessage(
                            conversationId,
                            encryptedByClient1
                        );
                    }
                );

                const encryptedByClient2 = await cc2.transaction(
                    async (ctx) => {
                        return await ctx.encryptMessage(
                            conversationId,
                            messageBytes
                        );
                    }
                );
                const decryptedByClient1 = await cc1.transaction(
                    async (ctx) => {
                        return await ctx.decryptMessage(
                            conversationId,
                            encryptedByClient2
                        );
                    }
                );

                const decoder = new TextDecoder();
                const result1 = decoder.decode(decryptedByClient1.message);
                const result2 = decoder.decode(decryptedByClient2.message);

                return [result1, result2];
            }

            /**
             * Initialize a {@link CoreCrypto} instance without initializing MLS.
             * Instead, initialize proteus.
             * It can be obtained inside the browser context via
             * {@link ensureCcDefined}.
             *
             * @returns {Promise<void>}
             */
            async proteusInit(): Promise<CoreCrypto> {
                const database = await this.newDatabase();
                const instance = ccModule.CoreCrypto.new(database);
                await instance.transaction((ctx) => ctx.proteusInit());
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
             *
             * @throws Error if {@link cc1} or {@link cc2} instances cannot be found.
             */
            async newProteusSessionFromPrekey(
                cc1: CoreCrypto,
                cc2: CoreCrypto,
                sessionId: string
            ): Promise<void> {
                const cc2Prekey = await cc2.transaction(async (ctx) => {
                    return await ctx.proteusNewPrekey(10);
                });

                await cc1.transaction(async (ctx) => {
                    return await ctx.proteusSessionFromPrekey(
                        sessionId,
                        cc2Prekey
                    );
                });
            }

            /**
             * Create a proteus session on the {@link CoreCrypto} instance of
             * {@link cc2}, from a message encrypted by {@link cc1} in a session
             * created previously via {@link newProteusSessionFromPrekey}.
             *
             * @param cc1 The {@link CoreCrypto} instance which used its
             * existing session to encrypt the message.
             * @param cc2 The {@link CoreCrypto} instance whose session will
             * be created.
             * @param sessionId The id of session that will be created.
             * For simplicity, this must match the id of the previously created session.
             * @param message The message to encrypt and create the message from.
             *
             * @returns {Promise<string | null>} the decrypted {@link message}.
             *
             * @throws Error if {@link cc1} or {@link cc2} instances cannot be found.
             */
            async newProteusSessionFromMessage(
                cc1: CoreCrypto,
                cc2: CoreCrypto,
                sessionId: string,
                message: string
            ): Promise<string> {
                const encoder = new TextEncoder();
                const messageBytes = encoder.encode(message);
                const encrypted = await cc1.transaction(async (ctx) => {
                    return await ctx.proteusEncrypt(sessionId, messageBytes);
                });

                const decrypted = await cc2.transaction(async (ctx) => {
                    return await ctx.proteusSessionFromMessage(
                        sessionId,
                        encrypted
                    );
                });

                const decoder = new TextDecoder();
                return decoder.decode(decrypted);
            }
        }
        globalThis.helpers = new HelpersImpl();
    });
}

async function setDeliveryService() {
    await runOnPlatform(() => {
        if (globalThis.deliveryService === undefined) {
            globalThis.deliveryService = {
                async sendCommitBundle(commitBundle: CommitBundle) {
                    globalThis._latestCommitBundle = commitBundle;
                },
                async prepareForTransport(
                    secret: HistorySecret
                ): Promise<MlsTransportData> {
                    return Promise.resolve(secret.clientId.copyBytes());
                },
                async getLatestCommitBundle() {
                    return globalThis._latestCommitBundle;
                },
            };
        }
    });
}

async function setLogger() {
    if (logLevel >= 2) {
        await runOnPlatform(() => {
            ccModule.setLogger({
                log: (
                    _level: CoreCryptoLogLevel,
                    message: string,
                    context: string | undefined
                ) => {
                    console.log(message, context);
                },
            });
            ccModule.setMaxLogLevel(ccModule.CoreCryptoLogLevel.Debug);
        });
    }
}
