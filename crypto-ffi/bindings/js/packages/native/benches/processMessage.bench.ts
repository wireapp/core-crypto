import { runBenchmark } from "./utils";
import { setupProcessMessageBench } from "../../../shared/benches/processMessage";

async function run() {
    await runBenchmark(setupProcessMessageBench);
}

await run();
