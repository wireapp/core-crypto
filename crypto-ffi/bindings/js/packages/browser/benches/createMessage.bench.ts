import { describe } from "mocha";
import { runBenchmark } from "./utils";
import { setupCreateMessageBench } from "../../../shared/benches/createMessage";

describe("benchmark", () => {
    it(`Create Message`, async () => {
        await runBenchmark(setupCreateMessageBench);
    });
});
