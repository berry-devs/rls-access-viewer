import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { REDACTED, redactDeep, redactString } from "../src/model/redact.ts";
import { pgUrl } from "./fixtures.ts";

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSJ9.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU";

describe("redactString", () => {
  const cases: [string, string][] = [
    ["connection string", pgUrl({ user: "postgres", password: "postgres", port: 54322 })],
    ["postgres scheme", "postgres://user@db.internal/app"],
    [
      "user:pass@ in any scheme",
      pgUrl({ scheme: "https", user: "admin", password: "hunter2", host: "example.com", db: "hook" })
    ],
    ["JWT", JWT],
    ["sk- key", "sk-proj-abcdefghijklmnopqrstuvwxyz0123"],
    ["new Supabase key", "sb_secret_abcdefghijklmnop"],
    ["AWS access key", "AKIAIOSFODNN7EXAMPLE"],
    ["long hex", "a3f1c9e0b2d4f6a8c0e2b4d6f8a0c2e4f6a8b0c2"]
  ];
  for (const [label, secret] of cases) {
    it(`redacts a ${label}`, () => {
      const out = redactString(`select net.http_post('${secret}', headers := '{}')`);
      assert.ok(!out.includes(secret), out);
      assert.ok(out.includes(REDACTED));
    });
  }

  it("leaves UUIDs, short hex and ordinary SQL alone", () => {
    const sql =
      "SELECT '3f2504e0-4f89-11d3-9a0c-0305e82c3301'::uuid, 'deadbeef', auth.uid() FROM https_log WHERE url = 'https://example.com/path'";
    assert.equal(redactString(sql), sql);
  });
});

describe("redactDeep", () => {
  it("redacts every string in nested objects and arrays without mutating the input", () => {
    const input = { a: [JWT, { b: `x ${JWT}` }], n: 1, t: true, z: null };
    const out = redactDeep(input);
    assert.deepEqual(out, { a: [REDACTED, { b: `x ${REDACTED}` }], n: 1, t: true, z: null });
    assert.equal(input.a[0], JWT);
  });
});
