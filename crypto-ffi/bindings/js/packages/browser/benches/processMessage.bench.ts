import { describe } from "mocha";
import { runBenchmark } from "./utils";
import { setupProcessMessageBench } from "../../../shared/benches/processMessage";

describe("benchmark", () => {
    it(`Process Message`, async () => {
        await runBenchmark(setupProcessMessageBench);
    });
});
