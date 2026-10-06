import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { assembleDocument, bucketsAccess, type RawCatalog, type RawStorageCatalog } from "../src/extract/index.ts";
import { storageBucketsQuery } from "../src/extract/queries.ts";
import { compileTags, loadConfig } from "../src/model/config.ts";
import { loadRulesSchema, validate } from "../src/model/schema.ts";
import { bucketScope, buildBucketCell, policyScopes, unknownBucketReferences } from "../src/model/storage.ts";
import type { BucketInfo, FunctionInfo, RulesDocument, TableRules } from "../src/model/types.ts";
import { assertRulesDocument } from "../src/model/validate.ts";
import { anchorId, formatBytes, renderHtml } from "../src/render/html.ts";
import { def, doc, policy, table } from "./fixtures.ts";

const tags = compileTags(loadConfig());

const bucket = (id: string, extra: Partial<BucketInfo> = {}): BucketInfo => ({
  id,
  name: id,
  public: false,
  fileSizeLimit: null,
  allowedMimeTypes: null,
  ...extra
});

const TEAM =
  "((storage.foldername(name))[1])::uuid IN ( SELECT get_team_ids_for_roles(ARRAY['admin'::team_role]) AS get_team_ids_for_roles)";

/** Cuts the Storage cell of a bucket / operation. */
function storageCell(html: string, bucketId: string, op: string): string {
  const id = `id="${anchorId("s", bucketId, op)}"`;
  const start = html.indexOf(id);
  assert.ok(start >= 0, `storage cell ${bucketId}/${op} not found`);
  return html.slice(start, html.indexOf("</section>", start));
}

function storageTab(html: string): string {
  const start = html.indexOf('<section id="tab-storage"');
  assert.ok(start >= 0);
  return html.slice(start, html.indexOf('<section id="tab-meta"', start));
}

describe("bucketScope", () => {
  it("reads bucket_id = '…' on either side, with or without a cast", () => {
    assert.deepEqual(bucketScope("(bucket_id = 'docs'::text)"), { kind: "buckets", ids: ["docs"] });
    assert.deepEqual(bucketScope("('docs'::text = objects.bucket_id)"), { kind: "buckets", ids: ["docs"] });
    assert.deepEqual(bucketScope("bucket_id = 'it''s'"), { kind: "buckets", ids: ["it's"] });
  });

  it("reads IN lists in both the pg_get_expr (= ANY (ARRAY[…])) and the written form", () => {
    assert.deepEqual(bucketScope("(bucket_id = ANY (ARRAY['a'::text, 'b'::text]))"), {
      kind: "buckets",
      ids: ["a", "b"]
    });
    assert.deepEqual(bucketScope("bucket_id IN ('a', 'b')"), { kind: "buckets", ids: ["a", "b"] });
  });

  it("intersects bucket conditions joined by AND and unions those joined by OR", () => {
    assert.deepEqual(bucketScope(`((bucket_id = 'docs'::text) AND ${TEAM})`), { kind: "buckets", ids: ["docs"] });
    assert.deepEqual(bucketScope("((bucket_id = ANY (ARRAY['a'::text, 'b'::text])) AND (bucket_id = 'b'::text))"), {
      kind: "buckets",
      ids: ["b"]
    });
    assert.deepEqual(bucketScope("((bucket_id = 'a'::text) OR (bucket_id = 'b'::text))"), {
      kind: "buckets",
      ids: ["a", "b"]
    });
  });

  it("treats an expression without a bucket condition, or an OR branch without one, as every bucket", () => {
    assert.deepEqual(bucketScope(TEAM), { kind: "all" });
    assert.deepEqual(bucketScope("((bucket_id = 'a'::text) OR (owner = auth.uid()))"), { kind: "all" });
  });

  it("flags bucket_id used in a form it does not read, including expressions it cannot split", () => {
    assert.deepEqual(bucketScope("(bucket_id <> 'secret'::text)"), { kind: "unrecognized" });
    assert.deepEqual(bucketScope("(lower(bucket_id) = 'a'::text)"), { kind: "unrecognized" });
    assert.deepEqual(bucketScope("((bucket_id = 'a'::text) AND (x = 1)"), { kind: "unrecognized" });
  });
});

describe("bucket cells", () => {
  const objects = table({
    name: "objects",
    policies: [
      policy({ name: "docs read", command: "SELECT", using: `((bucket_id = 'docs'::text) AND ${TEAM})` }),
      policy({ name: "docs write", command: "ALL", using: "(bucket_id = 'docs'::text)" }),
      policy({ name: "own objects", command: "SELECT", using: "(owner = auth.uid())" }),
      policy({
        name: "mfa",
        command: "ALL",
        permissive: false,
        using: "((auth.jwt() ->> 'aal'::text) = 'aal2'::text)"
      }),
      policy({
        name: "move",
        command: "UPDATE",
        using: "(bucket_id = 'docs'::text)",
        withCheck: "(bucket_id = 'archive'::text)"
      })
    ]
  });
  const d = doc({
    storage: {
      buckets: [bucket("docs"), bucket("archive"), bucket("empty")],
      bucketsReadable: true,
      bucketsFiltered: false,
      objects
    }
  });

  it("assigns bucket-specific policies to their bucket and expands cmd=ALL into every operation", () => {
    for (const op of ["SELECT", "INSERT", "UPDATE", "DELETE"] as const) {
      const names = buildBucketCell(d, objects, "docs", op).policies.map((cp) => cp.policy.name);
      assert.ok(names.includes("docs write"), op);
      assert.ok(
        buildBucketCell(d, objects, "docs", op).policies.find((cp) => cp.policy.name === "docs write")?.fromAll
      );
      assert.ok(!buildBucketCell(d, objects, "empty", op).policies.some((cp) => cp.policy.name === "docs write"), op);
    }
  });

  it("spreads policies without a bucket condition to every bucket and lists them as shared", () => {
    for (const id of ["docs", "archive", "empty"]) {
      const cell = buildBucketCell(d, objects, id, "SELECT");
      assert.ok(
        cell.policies.some((cp) => cp.policy.name === "own objects"),
        id
      );
      assert.deepEqual(
        cell.sharedPolicies.map((p) => p.name),
        ["own objects", "mfa"].filter((n) => cell.policies.some((cp) => cp.policy.name === n))
      );
    }
  });

  it("composes like a table cell: RESTRICTIVE ANDed, default deny, service_role bypassing RLS", () => {
    const empty = buildBucketCell(d, objects, "empty", "INSERT");
    const auth = empty.roles.find((r) => r.role === "authenticated");
    assert.equal(auth?.deniedByDefault, true);
    assert.deepEqual(
      auth?.restrictive.map((cp) => cp.policy.name),
      ["mfa"]
    );
    assert.equal(empty.roles.find((r) => r.role === "service_role")?.bypassRls, true);
    assert.equal(
      buildBucketCell(d, objects, "docs", "SELECT").roles.find((r) => r.role === "authenticated")?.deniedByDefault,
      false
    );
  });

  it("shows an UPDATE policy in both the bucket of its USING and the bucket of its WITH CHECK", () => {
    assert.ok(buildBucketCell(d, objects, "docs", "UPDATE").policies.some((cp) => cp.policy.name === "move"));
    const archive = buildBucketCell(d, objects, "archive", "UPDATE").policies.find((cp) => cp.policy.name === "move");
    assert.equal(archive?.using, "(bucket_id = 'docs'::text)");
    assert.equal(archive?.withCheck, "(bucket_id = 'archive'::text)");
    assert.deepEqual(policyScopes(objects, "UPDATE").find((p) => p.policy.name === "move")?.scope, {
      kind: "buckets",
      ids: ["docs", "archive"]
    });
  });

  it("reports policies naming buckets that do not exist", () => {
    const withTypo = table({
      name: "objects",
      policies: [policy({ name: "typo", command: "SELECT", using: "(bucket_id = 'dcos'::text)" })]
    });
    assert.deepEqual(unknownBucketReferences(withTypo, [bucket("docs")]), [{ policy: "typo", bucket: "dcos" }]);
  });
});

describe("Storage tab", () => {
  const helper: FunctionInfo = {
    name: "get_team_ids_for_roles",
    identityArguments: "roles team_role[]",
    returns: "SETOF uuid",
    kind: "function",
    language: "plpgsql",
    volatility: "STABLE",
    securityDefiner: false,
    searchPath: "",
    executableBy: { anon: false, authenticated: true },
    definition: def(
      "get_team_ids_for_roles",
      "\nBEGIN\n  IF auth.uid() IS NULL THEN\n    RAISE EXCEPTION 'not signed in';\n  END IF;\n  RETURN;\nEND;"
    )
  };
  const evil = "<img src=x onerror=alert(1)>";
  const objects: TableRules = table({
    name: "objects",
    policies: [
      policy({ name: "docs read", command: "SELECT", using: `((bucket_id = 'docs'::text) AND ${TEAM})` }),
      policy({ name: "shared", command: "SELECT", using: "(owner = auth.uid())" }),
      policy({ name: "odd", command: "DELETE", using: "((bucket_id = 'docs'::text) AND (x = 1)" }),
      policy({ name: evil, command: "INSERT", withCheck: `(bucket_id = '${evil}'::text)` })
    ]
  });
  const fixture: RulesDocument = doc({
    functions: [helper],
    storage: {
      buckets: [
        bucket("docs", { fileSizeLimit: 52_428_800, allowedMimeTypes: ["application/pdf"] }),
        bucket("avatars", { public: true }),
        bucket(evil)
      ],
      bucketsReadable: true,
      bucketsFiltered: false,
      objects
    }
  });
  const html = renderHtml(fixture, { tags });
  const tab = storageTab(html);

  it("adds a Storage tab with a bucket × operation matrix linking to every cell", () => {
    assert.ok(html.includes('<a href="#tab-storage" data-tab="tab-storage">Storage</a>'));
    for (const id of ["docs", "avatars", evil]) {
      for (const op of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
        assert.ok(tab.includes(`href="#${anchorId("s", id, op)}"`), `${id}/${op}`);
        storageCell(html, id, op);
      }
    }
  });

  it("shows bucket settings and warns about public buckets", () => {
    assert.ok(tab.includes("52428800 bytes (50 MiB)"));
    assert.ok(tab.includes("<code>application/pdf</code>"));
    assert.ok(tab.includes('<span class="badge danger">public</span>'));
    assert.ok(tab.includes("1 public bucket(s)"));
    assert.ok(html.includes("Public storage buckets: 1"));
  });

  it("marks shared policies in every bucket and keeps bucket-specific ones in their bucket", () => {
    const docs = storageCell(html, "docs", "SELECT");
    assert.ok(docs.includes("docs read"));
    assert.ok(docs.includes("Shared by every bucket (no bucket condition): shared"));
    const avatars = storageCell(html, "avatars", "SELECT");
    assert.ok(!avatars.includes("docs read"));
    assert.ok(avatars.includes('title="No bucket condition: applies to every bucket">all buckets</span>'));
    assert.ok(storageCell(html, "avatars", "INSERT").includes("denied by default"));
  });

  it("shows the functions called by Storage policies", () => {
    const docs = storageCell(html, "docs", "SELECT");
    assert.ok(docs.includes("<h4>Functions called by these policies</h4>"));
    assert.ok(docs.includes("not signed in"));
  });

  it("falls back to the original SQL and every bucket for an expression it cannot split", () => {
    const del = storageCell(html, "avatars", "DELETE");
    assert.ok(del.includes("could not split; original SQL"));
    assert.ok(del.includes("(bucket condition not recognized)"));
  });

  it("escapes bucket ids, names and policy names", () => {
    assert.ok(!html.includes(evil));
    assert.ok(tab.includes("&lt;img src=x onerror=alert(1)&gt;"));
  });

  it("lists the buckets named by policies when storage.buckets was not readable", () => {
    const out = renderHtml(
      { ...fixture, storage: { buckets: [], bucketsReadable: false, bucketsFiltered: false, objects } },
      { tags }
    );
    const t = storageTab(out);
    assert.ok(t.includes("could not read storage.buckets"));
    assert.ok(storageCell(out, "docs", "SELECT").includes("Bucket settings unknown"));
    assert.ok(!t.includes("Bucket settings</h3>"));
  });

  it("explains a missing storage section and validates documents with and without it", () => {
    const without = renderHtml(doc(), { tags });
    assert.ok(storageTab(without).includes("Storage was not extracted"));
    assert.ok(!without.includes("Public storage buckets"));
    assert.deepEqual(validate(loadRulesSchema(), fixture), []);
    assertRulesDocument(JSON.parse(JSON.stringify(fixture)));
    assertRulesDocument(JSON.parse(JSON.stringify(doc())));
  });
});

describe("Storage extraction", () => {
  const base: RawCatalog = {
    schema: "public",
    serverVersion: "17.6",
    now: new Date("2026-10-01T00:00:00Z"),
    roles: [{ name: "authenticated", bypass_rls: false, superuser: false }],
    tables: [],
    columns: [],
    policies: [],
    triggers: [],
    constraints: [],
    tableGrants: [],
    columnGrants: [],
    views: [],
    functions: [],
    extensionOwnedFunctions: 0,
    extensionOwnedRelations: 0,
    eventTriggers: []
  };
  const storage: RawStorageCatalog = {
    tables: [{ name: "objects", relkind: "r", rls_enabled: true, rls_forced: false, is_partition: false }],
    columns: [],
    policies: [
      {
        table_name: "objects",
        name: "docs read",
        cmd: "r",
        permissive: true,
        roles: ["storage_reader"],
        using_expr: "(bucket_id = 'docs'::text)",
        with_check_expr: null
      }
    ],
    triggers: [],
    constraints: [],
    tableGrants: [],
    columnGrants: [],
    roles: [{ name: "storage_reader", bypass_rls: false, superuser: false }],
    buckets: [
      { id: "docs", name: "docs", public: true, file_size_limit: "52428800", allowed_mime_types: ["application/pdf"] },
      { id: "any", name: "any", public: false, file_size_limit: null, allowed_mime_types: null }
    ],
    bucketsReadable: true,
    bucketsFiltered: false
  };

  it("maps buckets, storage.objects rules and roles named only in Storage policies", () => {
    const d = assembleDocument({ ...base, storage });
    assert.deepEqual(d.storage?.buckets, [
      { id: "docs", name: "docs", public: true, fileSizeLimit: 52_428_800, allowedMimeTypes: ["application/pdf"] },
      { id: "any", name: "any", public: false, fileSizeLimit: null, allowedMimeTypes: null }
    ]);
    assert.equal(d.storage?.objects?.policies[0]?.command, "SELECT");
    assert.ok(d.roles.some((r) => r.name === "storage_reader"));
    assert.deepEqual(validate(loadRulesSchema(), d), []);
  });

  it("keeps extracting without bucket settings when they are not readable", () => {
    const d = assembleDocument({
      ...base,
      storage: { ...storage, buckets: [], bucketsReadable: false, bucketsFiltered: false }
    });
    assert.equal(d.storage?.bucketsReadable, false);
    assert.deepEqual(d.storage?.buckets, []);
    assert.deepEqual(validate(loadRulesSchema(), d), []);
  });

  it("omits storage when the schema does not exist", () => {
    assert.equal(assembleDocument(base).storage, undefined);
  });

  it("selects only the bucket settings columns, as NULL when a column does not exist", () => {
    const sql = storageBucketsQuery(new Set(["id", "name", "public", "owner"]));
    assert.equal(
      sql,
      "SELECT b.id, b.name, b.public, NULL AS file_size_limit, NULL AS allowed_mime_types FROM storage.buckets b ORDER BY b.id"
    );
    assert.ok(!sql.includes("owner"));
  });
});

describe("formatBytes", () => {
  it("keeps the exact byte count and adds a binary unit", () => {
    assert.equal(formatBytes(512), "512 bytes");
    assert.equal(formatBytes(1536), "1536 bytes (1.5 KiB)");
    assert.equal(formatBytes(52_428_800), "52428800 bytes (50 MiB)");
  });
});

describe("RESTRICTIVE policies scoped to a bucket", () => {
  const objects = table({
    name: "objects",
    policies: [
      policy({ name: "anyone reads", command: "SELECT", using: "(owner = auth.uid())" }),
      policy({ name: "docs only", command: "SELECT", permissive: false, using: "(bucket_id = 'docs'::text)" })
    ]
  });
  const d = doc({
    storage: { buckets: [bucket("docs"), bucket("archive")], bucketsReadable: true, bucketsFiltered: false, objects }
  });

  it("keeps the policy in the cells of other buckets and denies there, never showing them as allowed", () => {
    const archive = buildBucketCell(d, objects, "archive", "SELECT");
    const auth = archive.roles.find((r) => r.role === "authenticated");
    assert.deepEqual(
      auth?.restrictive.map((cp) => cp.policy.name),
      ["docs only"]
    );
    assert.equal(auth?.deniedByDefault, true);
    assert.deepEqual(auth?.deniedByRestrictive, ["docs only"]);
    assert.deepEqual(archive.sharedPolicies, [
      { name: "anyone reads", reason: "all" },
      { name: "docs only", reason: "outOfBucket" }
    ]);
    assert.equal(archive.roles.find((r) => r.role === "service_role")?.deniedByDefault, false);
  });

  it("leaves the bucket it names as a normal RESTRICTIVE AND", () => {
    const docs = buildBucketCell(d, objects, "docs", "SELECT");
    const auth = docs.roles.find((r) => r.role === "authenticated");
    assert.equal(auth?.deniedByDefault, false);
    assert.equal(auth?.deniedByRestrictive, undefined);
    assert.ok(!docs.sharedPolicies.some((p) => p.reason === "outOfBucket"));
  });

  it("shows the denial in the matrix, the cell and the role panel", () => {
    const html = renderHtml(d, { tags });
    const tab = storageTab(html);
    const matrix = tab.slice(tab.indexOf("<h3>Buckets × operations"));
    const matrixRow = matrix.slice(matrix.indexOf(`href="#${anchorId("b", "archive")}">archive</a>`));
    assert.ok(matrixRow.slice(0, matrixRow.indexOf("</tr>")).includes('<span class="badge danger">deny</span>'));
    const cell = storageCell(html, "archive", "SELECT");
    assert.ok(cell.includes(">always false in this bucket</span>"));
    assert.ok(cell.includes("RESTRICTIVE policies scoped to other buckets are always false here"));
    assert.ok(
      cell.includes("RESTRICTIVE docs only is scoped to other buckets and always false for objects in this bucket")
    );
  });
});

describe("roles named only by another bucket's policy", () => {
  it("shows the role as denied by default in the other buckets", () => {
    const objects = table({
      name: "objects",
      policies: [
        policy({
          name: "reader docs",
          command: "SELECT",
          roles: ["storage_reader"],
          using: "(bucket_id = 'docs'::text)"
        })
      ]
    });
    const d = doc({
      roles: [...doc().roles, { name: "storage_reader", bypassRls: false, superuser: false }],
      storage: { buckets: [bucket("docs"), bucket("archive")], bucketsReadable: true, bucketsFiltered: false, objects }
    });
    const archive = buildBucketCell(d, objects, "archive", "SELECT").roles.find((r) => r.role === "storage_reader");
    assert.equal(archive?.deniedByDefault, true);
    assert.deepEqual(archive?.permissive, []);
    assert.equal(
      buildBucketCell(d, objects, "docs", "SELECT").roles.find((r) => r.role === "storage_reader")?.deniedByDefault,
      false
    );
  });
});

describe("policies naming buckets missing from storage.buckets", () => {
  const objects = table({
    name: "objects",
    policies: [policy({ name: "hidden", command: "SELECT", using: "(bucket_id = 'secret'::text)" })]
  });
  const render = (bucketsFiltered: boolean) =>
    storageTab(
      renderHtml(doc({ storage: { buckets: [bucket("docs")], bucketsReadable: true, bucketsFiltered, objects } }), {
        tags
      })
    );

  it("calls them not visible when row security filtered the buckets, and nonexistent otherwise", () => {
    assert.ok(render(true).includes("Policies naming buckets that are not visible to the extracting role: hidden"));
    assert.ok(!render(true).includes("Policies naming buckets that do not exist"));
    assert.ok(render(false).includes("Policies naming buckets that do not exist: hidden"));
  });
});

describe("bucketsAccess", () => {
  const columns = ["id", "name", "public", "file_size_limit", "allowed_mime_types"].map((name) => ({
    name,
    readable: true
  }));

  it("is unreadable when row security applies and no SELECT policy lets the role see rows", () => {
    assert.deepEqual(bucketsAccess(columns, { rls_active: true, has_select_policy: false }), {
      readable: false,
      filtered: false
    });
  });

  it("is readable but possibly filtered when a SELECT policy applies to the role", () => {
    assert.deepEqual(bucketsAccess(columns, { rls_active: true, has_select_policy: true }), {
      readable: true,
      filtered: true
    });
  });

  it("is fully readable when row security does not apply (BYPASSRLS, owner, superuser)", () => {
    assert.deepEqual(bucketsAccess(columns, { rls_active: false, has_select_policy: false }), {
      readable: true,
      filtered: false
    });
  });

  it("is unreadable without the column privileges", () => {
    const noMime = columns.map((c) => (c.name === "allowed_mime_types" ? { ...c, readable: false } : c));
    assert.equal(bucketsAccess(noMime, { rls_active: false, has_select_policy: false }).readable, false);
    assert.equal(bucketsAccess([], undefined).readable, false);
  });

  it("tells the viewer that the listed buckets may be a subset even when storage.objects does not exist", () => {
    const html = renderHtml(
      doc({ storage: { buckets: [bucket("docs")], bucketsReadable: true, bucketsFiltered: true, objects: null } }),
      { tags }
    );
    const tab = storageTab(html);
    assert.ok(tab.includes("storage.objects does not exist"));
    assert.ok(tab.includes("only the buckets visible to the extracting role are listed"));
  });

  it("tells the viewer that the listed buckets may be a subset", () => {
    const html = renderHtml(
      doc({
        storage: {
          buckets: [bucket("docs")],
          bucketsReadable: true,
          bucketsFiltered: true,
          objects: table({ name: "objects" })
        }
      }),
      { tags }
    );
    assert.ok(storageTab(html).includes("only the buckets visible to the extracting role are listed"));
  });
});
