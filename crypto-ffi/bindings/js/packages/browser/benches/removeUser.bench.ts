import { describe } from "mocha";
import { runBenchmark } from "./utils";
import { setupRemoveUserBench } from "../../../shared/benches/removeUser";

describe("benchmark", () => {
    it(`Remove User`, async () => {
        await runBenchmark(setupRemoveUserBench);
    });
});
