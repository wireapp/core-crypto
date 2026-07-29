import { setup, teardown } from "../../../shared/test/utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";
import { getPage } from "../shared/utils";
import type { ConsoleMessage } from "puppeteer";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("logger", () => {
    it("when throwing errors they're reported as errors", async () => {
        const page = getPage();
        type BrowserLog = {
            level: string;
            message: string;
        };
        const handler = (msg: ConsoleMessage) => {
            browserLogs.push({
                level: msg.type(),
                message: msg.text(),
            });
        };

        const browserLogs: BrowserLog[] = [];
        page.on("console", handler);
        try {
            const expectedErrorMessage = "expected test error in logger test";
            await page.evaluate(async (expectedErrorMessage) => {
                const cc = await helpers.ccInit();
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    ccModule;

                setLogger({
                    log: (_level, _message, _context) => {
                        throw Error(expectedErrorMessage);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                await helpers.createConversation(cc);
            }, expectedErrorMessage);

            const errorLogs = browserLogs.filter((log) => {
                return log.message.includes(expectedErrorMessage);
            });

            expect(errorLogs.length).to.be.greaterThan(0);
            expect(errorLogs[0]!.message).to.contain(expectedErrorMessage);
        } finally {
            page.off("console", handler);
        }
    });
});
