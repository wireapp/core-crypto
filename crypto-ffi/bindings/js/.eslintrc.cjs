module.exports = {
    ignorePatterns: [
        "*/*.js",
        "*/*.d.ts"
    ],
    parser: "@typescript-eslint/parser",
    extends: [
        "plugin:@typescript-eslint/recommended",
        "prettier",
        "plugin:wdio/recommended",
    ],
    parserOptions: {
        sourceType: "module",
    },
    rules: {
        "prettier/prettier": "error",
    },
    plugins: ["@typescript-eslint", "prettier", "wdio"],
};
