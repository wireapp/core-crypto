import { Cryptobox } from "@wireapp/cryptobox";
import { IndexedDBEngine } from "@wireapp/store-engine-dexie";

const TABLES: string[] = ["keys", "prekeys", "sessions"];

async function createCryptobox(storeName: string): Promise<Cryptobox> {
    const store = new IndexedDBEngine();
    const dexie = await store.init(storeName, true);
    const stores: { [tableName: string]: string } = TABLES.reduce((acc, tableName) => {
        acc[tableName] = "";
        return acc;
    }, {} as { [tableName: string]: string });
    dexie.version(1).stores(stores);
    const cbox = new Cryptobox(store);
    await cbox.create();
    return cbox;
}

(window as any).createCryptobox = createCryptobox;
export { createCryptobox };

