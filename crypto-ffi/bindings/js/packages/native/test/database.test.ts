import {
    CoreCryptoError,
    Database,
    DatabaseKey,
} from "@wireapp/core-crypto/native";
import {
    ccInit,
    DATABASE_LOCATIONS,
    newClientId,
    setup,
    teardown,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("database", () => {
    test("open previously created db works", async () => {
        const databaseName = crypto.randomUUID();
        const key = new Uint8Array(32);
        crypto.getRandomValues(key);

        await Database.open(databaseName, new DatabaseKey(key));

        const db = await Database.open(databaseName, new DatabaseKey(key));
        DATABASE_LOCATIONS.add(databaseName);

        expect(db).toBeDefined();
    });

    test("can get the database location", async () => {
        const databaseName = crypto.randomUUID();
        const key = new Uint8Array(32);
        crypto.getRandomValues(key);

        const db = await Database.open(databaseName, new DatabaseKey(key));
        DATABASE_LOCATIONS.add(databaseName);
        const location = await db.getLocation();
        expect(location).toBeDefined();
        expect(databaseName.toString()).toEqual(location!);
    });

    test("key must have correct length", async () => {
        expect(() => {
            new DatabaseKey(new Uint8Array(11));
        }).toThrowError(CoreCryptoError.Other);
    });

    test("key update works", async () => {
        const databaseName = crypto.randomUUID();

        const keyBytes = new Uint8Array(32);
        crypto.getRandomValues(keyBytes);
        const key = new DatabaseKey(keyBytes);

        const database = await Database.open(databaseName, key);
        DATABASE_LOCATIONS.add(databaseName);
        const clientId = newClientId();
        let cc = await ccInit({
            withBasicCredential: true,
            database,
            clientId,
        });

        const pubkey1 = (
            await cc.findCredentials({ clientId })
        )[0]!.publicKeyHash();

        const newKeyBytes = new Uint8Array(32);
        crypto.getRandomValues(newKeyBytes);
        const newKey = new DatabaseKey(newKeyBytes);

        try {
            await database.updateKey(newKey);
        } catch (e) {
            console.error("updating database key caught:", e);
            console.error(JSON.stringify(e));
            throw e;
        }

        cc = await ccInit({
            withBasicCredential: false,
            database,
            clientId,
        });
        const pubkey2 = (
            await cc.findCredentials({ clientId })
        )[0]!.publicKeyHash();

        expect(pubkey1).toEqual(pubkey2);
    });
});
