import { globalIgnores } from "eslint/config";
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-plugin-prettier/recommended";
import { configs as wdioConfig } from "eslint-plugin-wdio";

export default tseslint.config(
    globalIgnores(["src/*.js", "src/*.d.ts"]),
    eslint.configs.recommended,
    tseslint.configs.recommended,
    prettier,
    wdioConfig["flat/recommended"]
);
