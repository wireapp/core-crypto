import { rm } from "node:fs/promises";
import assert from "node:assert";
import { DatabaseKey, Database } from "@wireapp/core-crypto/native";

import { type PlatformHelpers } from "../../../shared/shared/utils";

const SQLITE_SIDE_CAR_SUFFIXES = ["", "-journal", "-shm", "-wal"] as const;
export const DATABASE_LOCATIONS = new Set<string>();

export async function sharedSetup() {
    globalThis.ccModule = await import("@wireapp/core-crypto/native");
}

export async function sharedTeardown() {
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

export async function setPlatformHelpers() {
    globalThis.platformHelpers = new PlatformHelpersImpl();
}

class PlatformHelpersImpl implements PlatformHelpers {
    /**
     * Open a database that gets wiped after tests run.
     */
    async newDatabase(location?: string, key?: DatabaseKey) {
        const finalKey = key ?? helpers.newDatabaseKey();
        const finalLocation = location ?? crypto.randomUUID();

        const database = await Database.open(finalLocation, finalKey);

        const resolvedLocation = await database.getLocation();
        assert(resolvedLocation !== undefined);
        DATABASE_LOCATIONS.add(resolvedLocation);
        return database;
    }
}

export async function runOnPlatform<Args extends unknown[], T>(
    script: (...args: Args) => T | Promise<T>,
    ...args: Args
): Promise<T> {
    return await script(...args);
}
