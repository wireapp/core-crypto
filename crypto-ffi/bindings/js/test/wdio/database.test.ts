import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("database", () => {
    it("open previously created db works", async () => {
        await expect(
            browser.execute(async () => {
                const databaseName = crypto.randomUUID();
                const key = new Uint8Array(32);
                window.crypto.getRandomValues(key);

                await window.ccModule.openDatabase(
                    databaseName,
                    new window.ccModule.DatabaseKey(key.buffer)
                );

                const db = await window.ccModule.openDatabase(
                    databaseName,
                    new window.ccModule.DatabaseKey(key.buffer)
                );

                return { dbIsDefined: db !== undefined };
            })
        ).resolves.toMatchObject({ dbIsDefined: true });
    });

    it("can get the database location", async () => {
        await expect(
            browser.execute(async () => {
                const databaseName = crypto.randomUUID();
                const key = new Uint8Array(32);
                window.crypto.getRandomValues(key);

                const db = await window.ccModule.openDatabase(
                    databaseName,
                    new window.ccModule.DatabaseKey(key.buffer)
                );

                return {
                    locationMatches: databaseName === (await db.getLocation()),
                };
            })
        ).resolves.toMatchObject({ locationMatches: true });
    });

    it("key must have correct length", async () => {
        expect(() =>
            browser.execute(async () => {
                new window.ccModule.DatabaseKey(new Uint8Array(11).buffer);
            })
        ).rejects.toThrow();
    });

    it("key update works", async () => {
        const [pubkey1, pubkey2] = await browser.execute(async () => {
            const cipherSuite = window.defaultCipherSuite;
            const databaseName = crypto.randomUUID();

            const makeClientId = () => {
                const array = new Uint8Array([1, 2]);
                return new window.ccModule.ClientId(array.buffer);
            };

            const keyBytes = new Uint8Array(32);
            window.crypto.getRandomValues(keyBytes);
            const key = new window.ccModule.DatabaseKey(keyBytes.buffer);

            const database = await window.ccModule.openDatabase(
                databaseName,
                key
            );

            let cc = new window.ccModule.CoreCrypto(database);
            const clientId = makeClientId();
            cc.newTransaction(async (ctx) => {
                await ctx.mlsInitialize(makeClientId(), window.deliveryService);
                await ctx.addCredential(
                    window.ccModule.credentialBasic(cipherSuite, clientId)
                );
            });
            const pubkey1 = (
                await cc.newTransaction((ctx) =>
                    ctx.getFilteredCredentials({ clientId })
                )
            )[0]!.publicKey();
            cc.close();

            const newKeyBytes = new Uint8Array(32);
            window.crypto.getRandomValues(newKeyBytes);
            const newKey = new window.ccModule.DatabaseKey(newKeyBytes.buffer);

            try {
                await window.ccModule.updateDatabaseKey(
                    databaseName,
                    key,
                    newKey
                );
            } catch (e) {
                console.error("updating database key caught:", e);
                console.error(JSON.stringify(e));
                throw e;
            }

            const newDatabase = await window.ccModule.openDatabase(
                databaseName,
                newKey
            );

            cc = new window.ccModule.CoreCrypto(newDatabase);
            const pubkey2 = await cc.newTransaction(async (ctx) => {
                await ctx.mlsInitialize(clientId, window.deliveryService);
                return (
                    await ctx.getFilteredCredentials({ clientId })
                )[0]!.publicKey();
            });
            cc.close();

            return [JSON.stringify(pubkey1), JSON.stringify(pubkey2)];
        });
        expect(JSON.parse(pubkey1)).toEqual(JSON.parse(pubkey2));
    });

    it("migrating key type to bytes works", async () => {
        const stores = await import("./db-v10002003-dump.json");

        // This fetch() and subsequent browser.executeScript() download and
        // inject the idb module into the browser context. We cannot do the
        // fetch from the browser context due to permissions so we first
        // download the code and then tell the browser to execute it. This also
        // means the TS compiler has no idea about it, which is why we use
        // ts-expect-error further down.
        const response = await fetch(
            "https://cdn.jsdelivr.net/npm/idb@8/build/umd.js"
        );
        if (!response.ok)
            throw new Error(`failed to fetch script: ${response.statusText}`);

        await browser.executeScript(await response.text(), []);

        const result = await browser.execute(async (stores_) => {
            // First, we need to restore the IndexedDB database in the browser.
            const stores: { string: [] } = JSON.parse(stores_);
            const clientName = "alice";
            const version = 10002003;
            // @ts-expect-error TS2304: Cannot find name 'idb'
            const db = await idb.openDB(clientName, version, {
                // @ts-expect-error TS7006: Parameter 'db' implicitly has an 'any' type
                async upgrade(db) {
                    for (const name of Object.keys(stores)) {
                        await db.createObjectStore(name);
                    }
                },
            });

            const chunks = (s: string) =>
                Array.from({ length: s.length / 2 }, (_, i) =>
                    s.substr(i * 2, 2)
                );
            const fromHex = (s: string) =>
                Uint8Array.from(chunks(s), (byte) => parseInt(byte, 16));

            for (const [name, value] of Object.entries(stores)) {
                for (const [key, val] of Object.entries(value)) {
                    await db.put(name, val, fromHex(key));
                }
            }

            // It is important to close the database here since otherwise the migration process
            // will be stuck because we'd be holding a connection to the same database open.
            db.close();

            // Migrate the whole database to use the new key type.
            const old_key = clientName;
            const new_key = new window.ccModule.DatabaseKey(
                new Uint8Array(32).buffer
            );
            await window.ccModule.migrateDatabaseKeyTypeToBytes(
                clientName,
                old_key,
                new_key
            );

            // Reconstruct the client based on the migrated database and fetch the epoch.
            const encoder = new TextEncoder();
            const database = await window.ccModule.openDatabase(
                clientName,
                new_key
            );

            const instance = new window.ccModule.CoreCrypto(database);
            const epoch = await instance.newTransaction(async (ctx) => {
                return await ctx.conversationEpoch(
                    new window.ccModule.ConversationId(
                        encoder.encode("convId").buffer
                    )
                );
            });
            return epoch;
        }, JSON.stringify(stores));

        // If the migration succeeded, the epoch has to be 1.
        expect(result).toEqual(1n);
    });
});
