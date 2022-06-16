import { setup as setupDevServer } from "jest-dev-server";

export default async function globalSetup() {
  await setupDevServer({
    command: "npx http-server platforms/web -g -p 3000",
    launchTimeout: 5000,
    port: 3000,
  });
}
