import { setup as sharedSetup } from "../../../shared/benches/utils";
import { sharedTeardown as tinybenchTeardown } from "../shared/utils";

export async function setup() {
    await sharedSetup();
    if (globalThis.tinybench === undefined) {
        globalThis.tinybench = await import("tinybench");
    }

    if (globalThis.tinybenchTeardown === undefined) {
        globalThis.tinybenchTeardown = tinybenchTeardown;
    }
}

export async function teardown() {}
