// /** @type {import('ts-jest').InitialOptionsTsJest} */
export default {
  // preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/test"],
  moduleDirectories: ["node_modules"],
  globalSetup: "<rootDir>/test/setup.js",
  globalTeardown: "<rootDir>/test/teardown.js",
};
