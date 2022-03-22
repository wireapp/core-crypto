import html from "@rollup/plugin-html";
import config from "./rollup.config";

config.plugins.push(html());

export default config;
