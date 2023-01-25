import { setup as setupDevServer } from "jest-dev-server";

export default async function globalSetup() {
  await setupDevServer({
    command: "npm run test:http-server",
    launchTimeout: 5000,
    host: "127.0.0.1",
    port: 3000,
    protocol: "http",
    usedPortAction: "kill",
  });
}
