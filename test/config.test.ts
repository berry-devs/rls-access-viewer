import assert from "node:assert/strict";
import { basename } from "node:path";
import { describe, it } from "node:test";
import { CONFIG_FILE_NAME, defaultConfigPath, loadConfig } from "../src/model/config.ts";

describe("default config lookup", () => {
  it("resolves the bundled config under the current name", () => {
    assert.equal(basename(defaultConfigPath()), CONFIG_FILE_NAME);
    assert.ok(loadConfig().tags.length > 0);
  });
});
