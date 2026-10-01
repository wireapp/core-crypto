// Fixture-only instrumentation of the inline OPFS worker. This file is never
// part of the keystore or VFS package.
const NativeBlob = globalThis.Blob;
const NativeWorker = globalThis.Worker;
let activeWorker;
let faultFired = false;
let queuedFault;

const bootstrap = `
let testFault;
self.addEventListener('message', event => {
    if (!event.data?.__coreCryptoTestFault) return;
    testFault = event.data.__coreCryptoTestFault;
    event.stopImmediatePropagation();
}, true);
const createAccessHandle = FileSystemFileHandle.prototype.createSyncAccessHandle;
FileSystemFileHandle.prototype.createSyncAccessHandle = async function (...args) {
    const fileName = this.name;
    const handle = await createAccessHandle.apply(this, args);
    const call = (method, values) => {
        if (testFault?.name === fileName && testFault.method === method &&
            (testFault.length === undefined || testFault.length === values[0])) {
            testFault = undefined;
            self.postMessage({ __coreCryptoTestFaultFired: true });
            throw new DOMException('injected worker access-handle failure', 'UnknownError');
        }
        return handle[method](...values);
    };
    return {
        getSize: (...values) => call('getSize', values),
        read: (...values) => call('read', values),
        write: (...values) => call('write', values),
        truncate: (...values) => call('truncate', values),
        flush: (...values) => call('flush', values),
        close: (...values) => call('close', values),
    };
};
`;

globalThis.Blob = class FixtureBlob extends NativeBlob {
    constructor(parts, options) {
        if (options?.type === 'text/javascript' && parts.length === 1 &&
            typeof parts[0] === 'string' && parts[0].includes('workerMain')) {
            super([bootstrap, parts[0]], options);
        } else {
            super(parts, options);
        }
    }
};

globalThis.Worker = class FixtureWorker extends NativeWorker {
    constructor(...args) {
        super(...args);
        activeWorker = this;
        if (queuedFault) {
            this.postMessage({ __coreCryptoTestFault: queuedFault });
            queuedFault = undefined;
        }
        this.addEventListener('message', event => {
            if (event.data?.__coreCryptoTestFaultFired) faultFired = true;
        });
    }
};

globalThis.__coreCryptoWorkerFault = {
    arm(name, method, length) {
        faultFired = false;
        queuedFault = { name, method, length };
        if (activeWorker) {
            activeWorker.postMessage({ __coreCryptoTestFault: queuedFault });
            queuedFault = undefined;
        }
    },
    fired() { return faultFired; },
    clear() {
        queuedFault = undefined;
        activeWorker?.postMessage({ __coreCryptoTestFault: undefined });
    },
};
