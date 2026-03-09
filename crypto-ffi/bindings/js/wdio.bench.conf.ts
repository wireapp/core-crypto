import { config as baseConfig } from "./wdio.test.conf.ts";

export const config: WebdriverIO.Config = {
    ...baseConfig,
    specs: ["./benches/*.bench.ts"],
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
                    { mount: "/", path: "./out" },
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
