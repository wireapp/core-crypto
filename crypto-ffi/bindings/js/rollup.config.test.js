import html from "@rollup/plugin-html";
import config from "./rollup.config.js";

config.plugins.push(html());

export default config;
