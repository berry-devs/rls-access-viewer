import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    cli: "src/cli.ts"
  },
  format: ["esm"],
  platform: "node",
  target: "node22",
  clean: true,
  splitting: true,
  sourcemap: false
});
