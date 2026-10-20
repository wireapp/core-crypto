// @ts-check

// OPFS synchronous access handles only exist in dedicated workers. This worker owns them and performs raw file
// operations; SQLite stays on the calling thread, which suspends through JSPI until each reply arrives.

/**
 * @typedef {object} WorkerRequest
 * @property {number} seq
 * @property {string} op
 * @property {unknown[]} args
 */

/**
 * @typedef {object} WorkerReply
 * @property {number} seq
 * @property {unknown} [value]
 * @property {{ name: string, message: string }} [error]
 */

function workerMain() {
    class OpfsFiles {
        /** @type {FileSystemDirectoryHandle | undefined} */
        #root;
        /** @type {Map<number, FileSystemSyncAccessHandle>} */
        #handles = new Map();
        #nextId = 1;

        /** @param {string} directory */
        async init(directory) {
            let root = await navigator.storage.getDirectory();
            for (const part of directory.split("/")) {
                root = await root.getDirectoryHandle(part, { create: true });
            }
            this.#root = root;
        }

        /** @param {string} name */
        async exists(name) {
            try {
                await this.#dir().getFileHandle(name);
                return true;
            } catch (error) {
                if (error instanceof DOMException && error.name === "NotFoundError") return false;
                throw error;
            }
        }

        /**
         * @param {string} name
         * @param {boolean} create
         */
        async open(name, create) {
            const file = await this.#dir().getFileHandle(name, { create });
            this.#handles.set(this.#nextId, await file.createSyncAccessHandle());
            return this.#nextId++;
        }

        /** @param {string} name */
        remove(name) {
            return this.#dir().removeEntry(name);
        }

        /**
         * @param {number} id
         * @param {number} offset
         * @param {number} length
         */
        read(id, offset, length) {
            const buffer = new Uint8Array(length);
            return buffer.subarray(0, this.#handle(id).read(buffer, { at: offset }));
        }

        /**
         * @param {number} id
         * @param {number} offset
         * @param {Uint8Array} bytes
         */
        write(id, offset, bytes) {
            const handle = this.#handle(id);
            let written = 0;
            while (written < bytes.byteLength) {
                const count = handle.write(bytes.subarray(written), { at: offset + written });
                if (count === 0) throw new Error("zero-byte OPFS write");
                written += count;
            }
        }

        /**
         * @param {number} id
         * @param {number} length
         */
        truncate(id, length) {
            this.#handle(id).truncate(length);
        }

        /** @param {number} id */
        size(id) {
            return this.#handle(id).getSize();
        }

        /** @param {number} id */
        flush(id) {
            this.#handle(id).flush();
        }

        /** @param {number} id */
        close(id) {
            const handle = this.#handle(id);
            this.#handles.delete(id);
            handle.close();
        }

        #dir() {
            if (!this.#root) throw new Error("OPFS worker not initialized");
            return this.#root;
        }

        /** @param {number} id */
        #handle(id) {
            const handle = this.#handles.get(id);
            if (!handle) throw new Error(`unknown OPFS file id: ${id}`);
            return handle;
        }
    }

    const files = new OpfsFiles();
    // Callers send one request at a time, but they can give up on a call (e.g. on worker error) and send the next
    // one before this side has finished. The queue keeps operations in arrival order regardless.
    let queue = Promise.resolve();

    /** @param {MessageEvent<WorkerRequest>} event */
    self.onmessage = ({ data: { seq, op, args } }) => {
        queue = queue
            .then(async () => {
                try {
                    // Own prototype methods only, so that names like `toString` aren't callable.
                    if (op === "constructor" || !Object.hasOwn(OpfsFiles.prototype, op)) {
                        throw new Error(`unknown OPFS worker operation: ${op}`);
                    }
                    // The check above makes `op` one of the methods; TypeScript can't follow it.
                    const method = /** @type {(...args: unknown[]) => unknown} */ (
                        files[/** @type {keyof OpfsFiles} */ (op)]
                    );
                    const value = await method.apply(files, args);
                    self.postMessage(
                        /** @satisfies {WorkerReply} */ ({ seq, value }),
                        value instanceof Uint8Array ? [value.buffer] : [],
                    );
                } catch (error) {
                    const { name, message } = error instanceof Error ? error : new Error(String(error));
                    self.postMessage(/** @satisfies {WorkerReply} */ ({ seq, error: { name, message } }));
                }
            })
            // A rejected queue would skip every later operation.
            .catch((error) => {
                console.error("OPFS worker failed to reply", error);
                // Plain strings should survive `postMessage` where the original reply didn't, so the caller gets an
                // error instead of waiting for its timeout.
                try {
                    self.postMessage(
                        /** @satisfies {WorkerReply} */ ({
                            seq,
                            error: { name: "Error", message: `OPFS worker failed to reply: ${error}` },
                        }),
                    );
                } catch {
                    // Nothing left to try; the caller's timeout will fire.
                }
            });
    };
}

/**
 * The JSPI parts of the `WebAssembly` namespace, which TypeScript doesn't declare yet. `start` checks that they exist.
 *
 * @type {typeof WebAssembly & {
 *     Suspending: unknown,
 *     promising: (f: Function) => () => Promise<unknown>,
 * }}
 */
const Wasm = /** @type {any} */ (WebAssembly);

/** @type {Worker | undefined} */
let worker;
let nextSeq = 0;

// Callers hold `SqliteGuard` and block on each reply, so at most one call is in flight. A caller that times out
// abandons its call before making the next one.
/** @type {{ seq: number, resolve: (value: unknown) => void, reject: (reason: unknown) => void } | undefined} */
let inflight;

/**
 * @param {string} op
 * @param {unknown[]} args
 * @param {Transferable[]} [transfer]
 * @returns {Promise<unknown>}
 */
function rpc(op, args, transfer = []) {
    // Throwing in the executor rejects the promise, so the error reaches Rust as a `VfsError`.
    return new Promise((resolve, reject) => {
        if (inflight !== undefined)
            throw new Error(`OPFS worker call overlaps call ${inflight.seq}`);
        if (worker === undefined) throw new Error("OPFS worker not started");
        const seq = nextSeq++;
        worker.postMessage(/** @satisfies {WorkerRequest} */ ({ seq, op, args }), transfer);
        inflight = { seq, resolve, reject };
    });
}

/** @param {Error} error */
function fail(error) {
    inflight?.reject(error);
    inflight = undefined;
}

/** @param {string} directory */
export async function start(directory) {
    if (
        !globalThis.navigator?.storage?.getDirectory ||
        !Wasm.Suspending ||
        !Wasm.promising
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
    /** @param {MessageEvent<WorkerReply>} event */
    worker.onmessage = ({ data: { seq, value, error } }) => {
        // A reply can outlive its call, e.g. once `fail` has rejected it. The sequence number keeps it from
        // settling a later call.
        if (inflight?.seq !== seq) return;
        const call = inflight;
        inflight = undefined;
        if (error) call.reject(new DOMException(error.message, error.name));
        else call.resolve(value);
    };
    worker.onerror = (event) => fail(new Error(event.message || "OPFS worker failed"));
    worker.onmessageerror = () => fail(new Error("OPFS worker message could not be decoded"));
    try {
        await rpc("init", [directory]);
    } catch (error) {
        // The next open retries with a fresh worker; don't leak this one.
        worker.terminate();
        worker = undefined;
        throw error;
    }
}

// Gives up on the in-flight call, e.g. after a timeout. Its late reply is then ignored.
export function abandon() {
    fail(new DOMException("OPFS worker did not reply in time", "TimeoutError"));
}

/** @param {string} name */
export const exists = (name) => rpc("exists", [name]);
/**
 * @param {string} name
 * @param {boolean} create
 */
export const open = (name, create) => rpc("open", [name, create]);
/** @param {string} name */
export const remove = (name) => rpc("remove", [name]);
/**
 * @param {number} id
 * @param {number} offset
 * @param {number} length
 */
export const read = (id, offset, length) => rpc("read", [id, offset, length]);
/**
 * @param {number} id
 * @param {number} offset
 * @param {Uint8Array<ArrayBuffer>} bytes
 */
export const write = (id, offset, bytes) => rpc("write", [id, offset, bytes], [bytes.buffer]);
/**
 * @param {number} id
 * @param {number} length
 */
export const truncate = (id, length) => rpc("truncate", [id, length]);
/** @param {number} id */
export const size = (id) => rpc("size", [id]);
/** @param {number} id */
export const flush = (id) => rpc("flush", [id]);
/** @param {number} id */
export const close = (id) => rpc("close", [id]);

/**
 * Runs deferred SQLite cleanup through a fresh JSPI entry.
 *
 * @param {{ core_crypto_keystore_sqlite_cleanup: Function }} exports
 */
export function scheduleCleanup(exports) {
    Promise.resolve()
        .then(() => Wasm.promising(exports.core_crypto_keystore_sqlite_cleanup)())
        .catch((error) => console.error("SQLite cleanup failed", error));
}
