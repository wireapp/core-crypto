import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("database key", () => {
    it("must have correct length", async () => {
        expect(() =>
            browser.execute(async () => {
                new window.ccModule.DatabaseKey(new Uint8Array(11));
            })
        ).rejects.toThrow();
    });
});

describe("database", () => {
    it("key update works", async () => {
        const [pubkey1, pubkey2] = await browser.execute(async () => {
            const cipherSuite = window.defaultCipherSuite;
            const databaseName = crypto.randomUUID();

            const makeClientId = () => {
                const array = new Uint8Array([1, 2]);
                return new window.ccModule.ClientId(array);
            };

            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);

            const clientConfig = {
                databaseName: databaseName,
                key: new window.ccModule.DatabaseKey(key),
                ciphersuites: [cipherSuite],
                clientId: makeClientId(),
            };

            let cc = await window.ccModule.CoreCrypto.init(clientConfig);
            const pubkey1 = await cc.transaction((ctx) =>
                ctx.clientPublicKey(
                    cipherSuite,
                    window.ccModule.CredentialType.Basic
                )
            );
            cc.close();

            const newKey = new Uint8Array(32);
            window.crypto.getRandomValues(newKey);

            await window.ccModule.updateDatabaseKey(
                databaseName,
                new window.ccModule.DatabaseKey(key),
                new window.ccModule.DatabaseKey(newKey)
            );

            clientConfig.key = new window.ccModule.DatabaseKey(newKey);
            clientConfig.clientId = makeClientId();

            cc = await window.ccModule.CoreCrypto.init(clientConfig);
            const pubkey2 = await cc.transaction((ctx) =>
                ctx.clientPublicKey(
                    cipherSuite,
                    window.ccModule.CredentialType.Basic
                )
            );
            cc.close();

            return [JSON.stringify(pubkey1), JSON.stringify(pubkey2)];
        });
        expect(JSON.parse(pubkey1)).toEqual(JSON.parse(pubkey2));
    });
});

describe("database migration", () => {
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
            const new_key = new window.ccModule.DatabaseKey(new Uint8Array(32));
            await window.ccModule.migrateDatabaseKeyTypeToBytes(
                clientName,
                old_key,
                new_key
            );

            // Reconstruct the client based on the migrated database and fetch the epoch.
            const cipherSuite = window.defaultCipherSuite;
            const encoder = new TextEncoder();
            const clientConfig = {
                databaseName: clientName,
                key: new_key,
                wasmModule: undefined,
                ciphersuites: [cipherSuite],
                clientId: new window.ccModule.ClientId(
                    encoder.encode(clientName)
                ),
            };
            const instance =
                await window.ccModule.CoreCrypto.init(clientConfig);
            const epoch = await instance.conversationEpoch(
                new window.ccModule.ConversationId(encoder.encode("convId"))
            );
            return epoch;
        }, JSON.stringify(stores));

        // If the migration succeeded, the epoch has to be 1.
        expect(result).toEqual(1);
    });
});
