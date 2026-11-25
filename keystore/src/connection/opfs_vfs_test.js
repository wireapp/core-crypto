// The wasm test uses a real worker and OPFS, but drops one reply so the startup deadline and retry are deterministic.
let nativeWorkerConstructor;
let firstWorkerReplySuppressed = false;
let startupTestWorkers = [];

export function suppress_first_worker_init_reply() {
    nativeWorkerConstructor = globalThis.Worker;
    firstWorkerReplySuppressed = false;
    startupTestWorkers = [];
    globalThis.Worker = class extends nativeWorkerConstructor {
        constructor(...constructorArguments) {
            super(...constructorArguments);
            const nativeWorker = this;
            startupTestWorkers.push(nativeWorker);
            return new Proxy(nativeWorker, {
                get(target, propertyName) {
                    const property = Reflect.get(target, propertyName, target);
                    return typeof property === "function" ? property.bind(target) : property;
                },
                set(target, propertyName, propertyValue) {
                    if (propertyName === "onmessage") {
                        target.onmessage = function suppressFirstWorkerReply(event) {
                            if (!firstWorkerReplySuppressed) {
                                firstWorkerReplySuppressed = true;
                                return;
                            }
                            propertyValue.call(target, event);
                        };
                        return true;
                    }
                    return Reflect.set(target, propertyName, propertyValue, target);
                },
            });
        }
    };
}

export function first_worker_init_reply_was_suppressed() {
    return firstWorkerReplySuppressed;
}

export function restore_worker_constructor() {
    if (nativeWorkerConstructor !== undefined) {
        globalThis.Worker = nativeWorkerConstructor;
    }
    for (const startupTestWorker of startupTestWorkers) {
        startupTestWorker.terminate();
    }
    startupTestWorkers = [];
    nativeWorkerConstructor = undefined;
}
