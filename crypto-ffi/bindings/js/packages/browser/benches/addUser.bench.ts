import { describe } from "mocha";
import { runBenchmark } from "./utils";
import { setupAddUserBench } from "../../../shared/benches/addUser";

describe("benchmark", () => {
    it(`Add User`, async () => {
        await runBenchmark(setupAddUserBench);
    });
});
