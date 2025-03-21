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
        "@typescript-eslint/no-namespace": "off" // namespaces for static methods on arbitrary types are awesome!
    },
    plugins: ["@typescript-eslint", "prettier", "wdio"],
};
