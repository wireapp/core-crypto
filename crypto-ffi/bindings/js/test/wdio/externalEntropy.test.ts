import { browser, expect } from "@wdio/globals";
import { ALICE_ID, ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("external entropy", () => {
    it("should match with set seed", async () => {
        // Test vectors 1 and 2 from
        // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
        const vector1 = Uint32Array.from([
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd,
            0x1aed8da0, 0xccef36a8, 0xc70d778b, 0x7c5941da, 0x8d485751,
            0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815, 0x69b687c3,
            0x8665eeb2,
        ]);
        const vector2 = Uint32Array.from([
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb,
            0x6965e348, 0x3e53c612, 0xed7aee32, 0x7621b729, 0x434ee69c,
            0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51, 0x1f0ae1ac,
            0x6f4d794b,
        ]);

        await ccInit(ALICE_ID);

        const [result1, result2] = await browser.execute(
            async (clientName, length1, length2) => {
                const cc = window.ensureCcDefined(clientName);
                // Null byte seed
                const seed = new Uint8Array(32);
                await cc.reseedRng(seed);

                const produced1 = await cc.randomBytes(length1);
                const produced2 = await cc.randomBytes(length2);
                return [Array.from(produced1), Array.from(produced2)];
            },
            ALICE_ID,
            vector1.length * vector1.BYTES_PER_ELEMENT,
            vector2.length * vector2.BYTES_PER_ELEMENT
        );

        const resultByteVector1 = new Uint8Array(result1);
        const resultByteVector2 = new Uint8Array(result2);

        // Use a DataView to solve endianness issues
        const resultVector1 = new Uint32Array(resultByteVector1.buffer);
        const resultVector2 = new Uint32Array(resultByteVector2.buffer);

        expect(resultVector1).toStrictEqual(vector1);
        expect(resultVector2).toStrictEqual(vector2);
    });
});
