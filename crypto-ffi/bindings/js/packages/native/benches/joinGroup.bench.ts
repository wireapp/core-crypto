import { setupJoinGroupBench } from "../../../shared/benches/joinGroup";
import { runBenchmark } from "./utils";

async function run() {
    await runBenchmark(setupJoinGroupBench);
}

await run();
