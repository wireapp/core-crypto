import { tmpdir } from "os";
import fs from "fs/promises";
import path from "path";
import logger from "@wdio/logger";

const STATIC_SERVER_URL = "http://localhost:3000/";
const log = logger("wdio.conf.ts");

// This file is imported both by the main wdio process and the worker process(es).
// Since only the main wdio process needs to create the static path for static-server
// service, only create the temporary directory if we're not a worker.
let staticPath;
if (process.env.WDIO_WORKER_ID === undefined) {
    staticPath = await fs.mkdtemp(
        path.join(tmpdir(), "core-crypto-wdio-test-")
    );
    log.info("Created temporary dir for tests:", staticPath);
}

export const config: WebdriverIO.Config = {
    //
    // ====================
    // Runner Configuration
    // ====================
    // WebdriverIO supports running e2e tests as well as unit and component tests.
    runner: "local",
    path: "/",
    tsConfigPath: "./tsconfig.json",

    //
    // ==================
    // Specify Test Files
    // ==================
    // Define which test specs should run. The pattern is relative to the directory
    // of the configuration file being run.
    //
    // The specs are defined as an array of spec files (optionally using wildcards
    // that will be expanded). The test for each spec file will be run in a separate
    // worker process. In order to have a group of spec files run in the same worker
    // process simply enclose them in an array within the specs array.
    //
    // The path of the spec files will be resolved relative from the directory of
    //  the config file unless it's absolute.
    //
    specs: ["./test/**/*.test.ts"],
    // Patterns to exclude.
    exclude: [
        // 'path/to/excluded/files'
    ],
    //
    // ============
    // Capabilities
    // ============
    // Define your capabilities here. WebdriverIO can run multiple capabilities at the same
    // time. Depending on the number of capabilities, WebdriverIO launches several test
    // sessions. Within your capabilities you can overwrite the spec and exclude options in
    // order to group specific specs to a specific capability.
    //
    // First, you can define how many instances should be started at the same time. Let's
    // say you have 3 different capabilities (Chrome, Firefox, and Safari) and you have
    // set maxInstances to 1; wdio will spawn 3 processes. Therefore, if you have 10 spec
    // files and you set maxInstances to 10, all spec files will get tested at the same time
    // and 30 processes will get spawned. The property handles how many capabilities
    // from the same test should run tests.
    //
    maxInstances: 10,
    //
    // If you have trouble getting all important capabilities together, check out the
    // Sauce Labs platform configurator - a great tool to configure your capabilities:
    // https://saucelabs.com/platform/platform-configurator
    //
    capabilities: [
        {
            browserName: "chrome", // or "firefox"
            "goog:chromeOptions": { args: ["--headless", "--disable-gpu"] },
            // @ts-expect-error TS2353: Object literal may only specify known properties, and "goog:loggingPrefs" does not exist in type RequestedStandaloneCapabilities
            "goog:loggingPrefs": {
                browser: "ALL",
                performance: "ALL",
            },
        },
    ],

    //
    // ===================
    // Test Configurations
    // ===================
    // Define all options that are relevant for the WebdriverIO instance here
    //
    // Level of logging verbosity: trace | debug | info | warn | error | silent
    // logLevel: "warn",
    logLevel: "info",
    //
    // Set specific log levels per logger
    // loggers:
    // - webdriver, webdriverio
    // - @wdio/browserstack-service, @wdio/lighthouse-service, @wdio/sauce-service
    // - @wdio/mocha-framework, @wdio/jasmine-framework
    // - @wdio/local-runner
    // - @wdio/sumologic-reporter
    // - @wdio/cli, @wdio/config, @wdio/utils
    // Level of logging verbosity: trace | debug | info | warn | error | silent
    // logLevels: {
    //     webdriver: 'info',
    //     '@wdio/appium-service': 'info'
    // },
    //
    // If you only want to run your tests until a specific amount of tests have failed use
    // bail (default is 0 - don't bail, run all tests).
    bail: 0,
    //
    // Set a base URL in order to shorten url command calls. If your `url` parameter starts
    // with `/`, the base url gets prepended, not including the path portion of your baseUrl.
    // If your `url` parameter starts without a scheme or `/` (like `some/path`), the base url
    // gets prepended directly.
    baseUrl: STATIC_SERVER_URL,
    //
    // Default timeout for all waitFor* commands.
    waitforTimeout: 10000,
    //
    // Default timeout in milliseconds for request
    // if browser driver or grid doesn't send response
    connectionRetryTimeout: 120000,
    //
    // Default request retries count
    connectionRetryCount: 3,
    //
    // Test runner services
    // Services take over a specific job you don't want to take care of. They enhance
    // your test setup with almost no effort. Unlike plugins, they don't add new
    // commands. Instead, they hook themselves up into the test process.
    services: [
        [
            "static-server",
            {
                folders: [{ mount: "/", path: staticPath }],
                port: 3000,
            },
        ],
    ],
    //
    // Framework you want to run your specs with.
    // The following are supported: Mocha, Jasmine, and Cucumber
    // see also: https://webdriver.io/docs/frameworks
    //
    // Make sure you have the wdio adapter package for the specific framework installed
    // before running any tests.
    framework: "mocha",

    //
    // The number of times to retry the entire specfile when it fails as a whole
    // specFileRetries: 1,
    //
    // Delay in seconds between the spec file retry attempts
    // specFileRetriesDelay: 0,
    //
    // Whether or not retried spec files should be retried immediately or deferred to the end of the queue
    // specFileRetriesDeferred: false,
    //
    // Test reporter for stdout.
    // The only one supported by default is 'dot'
    // see also: https://webdriver.io/docs/dot-reporter
    reporters: [
        [
            "spec",
            {
                addConsoleLogs: true,
            },
        ],
    ],

    // Options to be passed to Mocha.
    // See the full list at http://mochajs.org/
    mochaOpts: {
        ui: "bdd",
        timeout: 60000,
    },

    async onPrepare() {
        const dir = process.cwd();

        async function copyFile(src, destdir) {
            const destName = path.join(destdir, path.basename(src));
            await fs.copyFile(src, destName);
        }

        await copyFile(path.join(dir, "test", "index.html"), staticPath);
        await copyFile(path.join(dir, "src", "corecrypto.js"), staticPath);
        await copyFile(
            path.join(dir, "src", "core-crypto-ffi_bg.wasm"),
            staticPath
        );
        log.info("Copied files to", staticPath);
    },

    async onComplete() {
        await fs.rm(staticPath, { recursive: true, force: true });
        log.info("Cleaning up temporary dir:", staticPath);
    },
};
