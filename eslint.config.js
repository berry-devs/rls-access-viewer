import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default [
  {
    // Build output and generated viewer files
    ignores: ["dist/", "out/"]
  },
  {
    // Node.js ESM CLI: no browser globals
    files: ["**/*.ts", "**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.node
      }
    }
  },
  // Base configurations
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // Custom rules
    rules: {
      "@typescript-eslint/no-unused-expressions": [
        "error",
        {
          allowShortCircuit: true,
          allowTernary: true,
          allowTaggedTemplates: true
        }
      ]
    }
  }
];
