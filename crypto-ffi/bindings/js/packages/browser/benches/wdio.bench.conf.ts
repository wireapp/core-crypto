import { config as baseConfig } from "../test/wdio.test.conf.ts";

const chromePath = process.env["CHROME_PATH"];
const chromedriverPath = process.env["CHROMEDRIVER_PATH"];

const withBrowserPaths = (
    capabilities: WebdriverIO.Capabilities
): WebdriverIO.Capabilities => {
    const browserBenchCapability = { ...capabilities };

    if (chromePath !== undefined) {
        browserBenchCapability["goog:chromeOptions"] = {
            ...browserBenchCapability["goog:chromeOptions"],
            binary: chromePath,
        };
    }

    if (chromedriverPath !== undefined) {
        browserBenchCapability["wdio:chromedriverOptions"] = {
            ...browserBenchCapability["wdio:chromedriverOptions"],
            binary: chromedriverPath,
        };
    }

    return browserBenchCapability;
};

const capabilities = baseConfig.capabilities.map(withBrowserPaths);

export const config: WebdriverIO.Config = {
    ...baseConfig,
    specs: ["./*.bench.ts"],
    capabilities,
    mochaOpts: {
        ...baseConfig.mochaOpts,
        timeout: 3_600_000, // 1 hr
    },
    waitforTimeout: 3_600_000, // 1 hr
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
