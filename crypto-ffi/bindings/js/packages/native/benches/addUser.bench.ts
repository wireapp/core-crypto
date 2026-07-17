import { setupAddUserBench } from "../../../shared/benches/addUser";
import { runBenchmark } from "./utils";

async function run() {
    await runBenchmark(setupAddUserBench);
}

await run();
