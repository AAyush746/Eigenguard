// Flat ESLint config.
//
// Version note: the plugin exports are checked against what is actually
// installed, because the documented `.configs.flat.*` paths only existed in the
// v4 line and made this file throw at load time on v5.
import js from "@eslint/js"
import globals from "globals"
import reactHooks from "eslint-plugin-react-hooks"
import reactRefresh from "eslint-plugin-react-refresh"
import tseslint from "typescript-eslint"
import { defineConfig, globalIgnores } from "eslint/config"

export default defineConfig([
  globalIgnores(["dist", "node_modules"]),
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs["recommended-latest"],
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    rules: {
      // Underscore-prefixed names mark deliberate discards.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // Config files themselves run in Node, not the browser.
    files: ["*.config.{js,cjs,ts}", "vite.config.ts"],
    languageOptions: { globals: globals.node },
  },
])