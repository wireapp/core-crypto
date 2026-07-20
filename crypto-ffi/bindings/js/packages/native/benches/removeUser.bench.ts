import { runBenchmark } from "./utils";
import { setupRemoveUserBench } from "../../../shared/benches/removeUser";

async function run() {
    await runBenchmark(setupRemoveUserBench);
}

await run();
