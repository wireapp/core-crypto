// OPFS synchronous access handles only exist in dedicated workers. This worker owns them and performs raw file
// operations; SQLite stays on the calling thread, which suspends through JSPI until each reply arrives.

function workerMain() {
    class OpfsFiles {
        #root;
        #handles = new Map();
        #nextId = 1;

        async init(directory) {
            let root = await navigator.storage.getDirectory();
            for (const part of directory.split("/")) {
                root = await root.getDirectoryHandle(part, { create: true });
            }
            this.#root = root;
        }

        async exists(name) {
            try {
                await this.#root.getFileHandle(name);
                return true;
            } catch (error) {
                if (error.name === "NotFoundError") return false;
                throw error;
            }
        }

        async open(name, create) {
            const file = await this.#root.getFileHandle(name, { create });
            this.#handles.set(this.#nextId, await file.createSyncAccessHandle());
            return this.#nextId++;
        }

        remove(name) {
            return this.#root.removeEntry(name);
        }

        read(id, offset, length) {
            const buffer = new Uint8Array(length);
            return buffer.subarray(0, this.#handle(id).read(buffer, { at: offset }));
        }

        write(id, offset, bytes) {
            const handle = this.#handle(id);
            let written = 0;
            while (written < bytes.byteLength) {
                const count = handle.write(bytes.subarray(written), { at: offset + written });
                if (count === 0) throw new Error("zero-byte OPFS write");
                written += count;
            }
        }

        truncate(id, length) {
            this.#handle(id).truncate(length);
        }

        size(id) {
            return this.#handle(id).getSize();
        }

        flush(id) {
            this.#handle(id).flush();
        }

        close(id) {
            const handle = this.#handle(id);
            this.#handles.delete(id);
            handle.close();
        }

        #handle(id) {
            const handle = this.#handles.get(id);
            if (!handle) throw new Error(`unknown OPFS file id: ${id}`);
            return handle;
        }
    }

    const files = new OpfsFiles();
    // Requests are sequential from the caller's side; this queue only guards against interleaving `await`s.
    let queue = Promise.resolve();

    self.onmessage = ({ data: { seq, op, args } }) => {
        queue = queue.then(async () => {
            try {
                // Own prototype methods only, so that names like `toString` aren't callable.
                if (op === "constructor" || !Object.hasOwn(OpfsFiles.prototype, op)) {
                    throw new Error(`unknown OPFS worker operation: ${op}`);
                }
                const value = await files[op](...args);
                self.postMessage({ seq, value }, value instanceof Uint8Array ? [value.buffer] : []);
            } catch (error) {
                self.postMessage({ seq, error: { name: error.name, message: error.message } });
            }
        });
    };
}

let worker;
let nextSeq = 0;
const pending = new Map();

function rpc(op, args, transfer = []) {
    return new Promise((resolve, reject) => {
        const seq = nextSeq++;
        worker.postMessage({ seq, op, args }, transfer);
        pending.set(seq, { resolve, reject });
    });
}

function failAll(error) {
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
}

export async function start(directory) {
    if (
        !globalThis.navigator?.storage?.getDirectory ||
        !WebAssembly.Suspending ||
        !WebAssembly.promising
    ) {
        throw new Error("OPFS and JSPI are required");
    }
    // Inlined as a blob so that bundlers don't need to serve a separate worker asset.
    const url = URL.createObjectURL(new Blob([`(${workerMain})();`], { type: "text/javascript" }));
    try {
        worker = new Worker(url);
    } finally {
        URL.revokeObjectURL(url);
    }
    worker.onmessage = ({ data: { seq, value, error } }) => {
        const call = pending.get(seq);
        pending.delete(seq);
        if (error) call.reject(new DOMException(error.message, error.name));
        else call.resolve(value);
    };
    worker.onerror = (event) => failAll(new Error(event.message || "OPFS worker failed"));
    worker.onmessageerror = () => failAll(new Error("OPFS worker message could not be decoded"));
    try {
        await rpc("init", [directory]);
    } catch (error) {
        // The next open retries with a fresh worker; don't leak this one.
        worker.terminate();
        worker = undefined;
        throw error;
    }
}

export const exists = (name) => rpc("exists", [name]);
export const open = (name, create) => rpc("open", [name, create]);
export const remove = (name) => rpc("remove", [name]);
export const read = (id, offset, length) => rpc("read", [id, offset, length]);
export const write = (id, offset, bytes) => rpc("write", [id, offset, bytes], [bytes.buffer]);
export const truncate = (id, length) => rpc("truncate", [id, length]);
export const size = (id) => rpc("size", [id]);
export const flush = (id) => rpc("flush", [id]);
export const close = (id) => rpc("close", [id]);

// Runs deferred SQLite cleanup through a fresh JSPI entry.
export function scheduleCleanup(exports) {
    Promise.resolve()
        .then(() => WebAssembly.promising(exports.core_crypto_keystore_sqlite_cleanup)())
        .catch((error) => console.error("SQLite cleanup failed", error));
}
