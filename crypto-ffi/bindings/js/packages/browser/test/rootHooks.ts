import { setupBrowser, teardownBrowser } from "../shared/utils";

export const mochaHooks = {
    async beforeAll() {
        await setupBrowser();
    },

    async afterAll() {
        await teardownBrowser();
    },
};
