import { runBenchmark } from "./utils";
import { setupCreateMessageBench } from "../../../shared/benches/createMessage";

async function run() {
    await runBenchmark(setupCreateMessageBench);
}

await run();
