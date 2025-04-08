import { globalIgnores } from "eslint/config";
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-plugin-prettier/recommended";
import { configs as wdioConfig } from "eslint-plugin-wdio";

export default tseslint.config(
    globalIgnores(["src/*.js", "src/*.d.ts", "wasm/core-crypto-ffi.js"]),
    eslint.configs.recommended,
    tseslint.configs.recommended,
    prettier,
    wdioConfig["flat/recommended"],
    {
        rules: {
            "@typescript-eslint/no-unused-vars": [
                "error",
                {
                    // ignore vars, errors, etc which begin with an underscore
                    args: "all",
                    argsIgnorePattern: "^_",
                    caughtErrors: "all",
                    caughtErrorsIgnorePattern: "^_",
                    destructuredArrayIgnorePattern: "^_",
                    varsIgnorePattern: "^_",
                    // ignore `...rest` params when destructuring
                    ignoreRestSiblings: true,
                },
            ],
        },
    }
);
