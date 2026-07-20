import { describe } from "mocha";
import { runBenchmark } from "./utils";
import { setupJoinGroupBench } from "../../../shared/benches/joinGroup";

describe("benchmark", () => {
    it(`Join Group`, async () => {
        await runBenchmark(setupJoinGroupBench);
    });
});
