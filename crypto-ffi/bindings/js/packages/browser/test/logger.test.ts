import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("logger", () => {
    type BrowserLog = {
        level: string;
        message: string;
        source: string;
        timestamp: number;
    };

    it("when throwing errors they're reported as errors", async () => {
        const expectedErrorMessage = "expected test error in logger test";
        await browser.execute(async (expectedErrorMessage) => {
            const cc = await helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } = ccModule;

            setLogger({
                log: (_level, _message, _context) => {
                    throw Error(expectedErrorMessage);
                },
            });
            setMaxLogLevel(CoreCryptoLogLevel.Debug);
            await helpers.createConversation(cc);
        }, expectedErrorMessage);

        const logs = (await browser.getLogs("browser")) as BrowserLog[];
        console.log(JSON.stringify(logs));
        const errorLogs = logs.filter((log) => {
            return (
                log.message.includes(expectedErrorMessage) &&
                log.source === "console-api"
            );
        });

        expect(errorLogs.length).toBeGreaterThan(0);
        expect(errorLogs[0]!.message).toEqual(
            expect.stringContaining(expectedErrorMessage)
        );
    });
});
