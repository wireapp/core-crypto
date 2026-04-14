import { config as baseConfig } from "../test/wdio.test.conf.ts";

export const config: WebdriverIO.Config = {
    ...baseConfig,
    specs: ["./*.bench.ts"],
    mochaOpts: {
        ...baseConfig.mochaOpts,
        timeout: 1_800_000, // 30 min
    },
    waitforTimeout: 1_800_000, // 30 min
    services: [
        [
            "static-server",
            {
                port: 3000,
                folders: [
                    { mount: "/", path: "./out/browser" },
                    { mount: "/html", path: "./html" },
                    {
                        mount: "/node_modules/tinybench",
                        path: "./node_modules/tinybench",
                    },
                ],
            },
        ],
    ],
};
