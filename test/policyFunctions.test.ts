import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { compileTags, loadConfig } from "../src/model/config.ts";
import { functionsCalledInExpression } from "../src/model/plpgsql.ts";
import type { FunctionInfo } from "../src/model/types.ts";
import { anchorId, renderHtml } from "../src/render/html.ts";
import { def, doc, policy, table } from "./fixtures.ts";

const tags = compileTags(loadConfig());

function fn(name: string, definition: string, extra: Partial<FunctionInfo> = {}): FunctionInfo {
  return {
    name,
    identityArguments: "",
    returns: "boolean",
    kind: "function",
    language: "plpgsql",
    volatility: "STABLE",
    securityDefiner: false,
    searchPath: "",
    executableBy: { anon: false, authenticated: true },
    definition,
    ...extra
  };
}

/** Wraps a SQL function body the way pg_get_functiondef prints it. */
const sqlDef = (name: string, body: string) => `CREATE OR REPLACE FUNCTION public.${name}(_id uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE
AS $function$
${body}
$function$
`;

/** Cuts the cell section of a table / operation. */
function cell(html: string, tableName: string, op: string): string {
  const id = `id="${anchorId("c", tableName, op)}"`;
  const start = html.indexOf(id);
  assert.ok(start >= 0, `cell ${tableName}/${op} not found`);
  return html.slice(start, html.indexOf("</section>", start));
}

/** Cuts the "Functions called by these policies" block of a cell ("" when absent). */
function calledBlock(cellHtml: string): string {
  const start = cellHtml.indexOf("<h4>Functions called by these policies</h4>");
  if (start < 0) return "";
  return cellHtml.slice(start, cellHtml.indexOf("<h4>Effective rule per role</h4>", start));
}

const count = (s: string, needle: string) => s.split(needle).length - 1;

describe("functions called from policy expressions", () => {
  const functions = [
    fn(
      "is_owner",
      sqlDef("is_owner", "  SELECT EXISTS (SELECT 1 FROM public.items WHERE id = _id AND owner_id = auth.uid());"),
      { language: "sql", identityArguments: "_id uuid", comment: "Whether the caller owns the item." }
    ),
    fn(
      "can_edit",
      def(
        "can_edit",
        `
BEGIN
  IF NOT public.is_owner(_id) THEN
    RAISE EXCEPTION 'only the owner can edit';
  END IF;
  RETURN true;
END;`
      ),
      { identityArguments: "_id uuid" }
    ),
    // ping / pong call each other: the recursion must stop at the cycle guard
    fn("ping", def("ping", "\nBEGIN\n  RETURN public.pong();\nEND;")),
    fn(
      "pong",
      def("pong", "\nBEGIN\n  IF true THEN RAISE EXCEPTION 'pong failed'; END IF;\n  RETURN public.ping();\nEND;")
    ),
    fn("broken_fn", def("broken_fn", "\nBEGIN\n  IF x THEN\n    RAISE EXCEPTION 'never closed';\nEND;"))
  ];
  const html = renderHtml(
    doc({
      tables: [
        table({
          name: "items",
          policies: [
            policy({ name: "owner reads", command: "SELECT", using: "is_owner(id)" }),
            policy({
              name: "owner reads too",
              command: "SELECT",
              using: "(public.is_owner(id) AND (deleted IS FALSE))"
            }),
            policy({ name: "editor inserts", command: "INSERT", withCheck: "can_edit(id)" }),
            policy({ name: "editor updates", command: "UPDATE", using: "is_owner(id)", withCheck: "can_edit(id)" })
          ]
        }),
        table({
          name: "games",
          policies: [policy({ name: "recursive", command: "SELECT", using: "ping()" })]
        }),
        table({
          name: "noise",
          policies: [
            policy({
              name: "builtins only",
              command: "SELECT",
              using:
                "((created_by = auth.uid()) AND (coalesce(flag, false) = true) AND (extensions.is_owner(id)) AND (note <> 'is_owner(id)'::text))"
            })
          ]
        }),
        table({
          name: "odd",
          policies: [
            policy({ name: "unterminated", command: "SELECT", using: "(is_owner(id) AND (note = 'oops)" }),
            policy({ name: "unanalyzable", command: "DELETE", using: "broken_fn()" })
          ]
        })
      ],
      functions
    }),
    { tags }
  );

  it("shows a SQL helper's rules, comment and folded body in the cell, once per cell", () => {
    const block = calledBlock(cell(html, "items", "SELECT"));
    assert.equal(count(block, '<details class="pfn">'), 1);
    assert.ok(block.includes(`href="#${anchorId("fn", "is_owner", "0")}"`));
    assert.ok(block.includes("used by owner reads (USING), owner reads too (USING)"));
    assert.ok(block.includes("Whether the caller owns the item."));
    assert.ok(block.includes("Full definition of is_owner()"));
  });

  it("shows a PL/pgSQL helper's guards and links to its detail instead of folding its body", () => {
    const block = calledBlock(cell(html, "items", "INSERT"));
    assert.ok(block.includes("only the owner can edit"));
    assert.ok(block.includes("used by editor inserts (WITH CHECK)"));
    assert.ok(!block.includes("Full definition of can_edit()"));
    assert.ok(block.includes(`Full definition: <a href="#${anchorId("fn", "can_edit", "1")}">can_edit()</a>`));
    // The SQL helper it calls is reached through the call tree, with its body
    assert.ok(block.includes("via"));
    assert.ok(block.includes("Full definition of is_owner()"));
  });

  it("lists only the expressions the operation evaluates", () => {
    const insert = calledBlock(cell(html, "items", "INSERT"));
    assert.ok(!insert.includes("owner reads"));
    const update = calledBlock(cell(html, "items", "UPDATE"));
    assert.ok(update.includes("editor updates (USING)"));
    assert.ok(update.includes("editor updates (WITH CHECK)"));
    // DELETE has no policy here, so nothing is listed
    assert.equal(calledBlock(cell(html, "items", "DELETE")), "");
  });

  it("stops recursive calls at the cycle guard", () => {
    const block = calledBlock(cell(html, "games", "SELECT"));
    assert.ok(block.includes("pong failed"));
    assert.ok(block.includes("truncated:"));
    assert.ok(block.includes("(cycle)"));
  });

  it("leaves out auth.uid(), built-ins, other schemas and names inside string literals", () => {
    assert.equal(calledBlock(cell(html, "noise", "SELECT")), "");
  });

  it("keeps the page intact when an expression or a body cannot be read", () => {
    const select = cell(html, "odd", "SELECT");
    assert.equal(calledBlock(select), "");
    assert.ok(select.includes("(note = &#39;oops)"));
    const del = calledBlock(cell(html, "odd", "DELETE"));
    assert.ok(del.includes("failed"));
    assert.ok(del.includes("Full definition of broken_fn()"));
    assert.ok(html.trimEnd().endsWith("</html>"));
  });

  it("escapes markup from function comments and policy names", () => {
    const evil = "<img src=x onerror=alert(1)>";
    const out = renderHtml(
      doc({
        tables: [table({ name: "t", policies: [policy({ name: evil, command: "SELECT", using: "is_owner(id)" })] })],
        functions: [{ ...(functions[0] as FunctionInfo), comment: evil }]
      }),
      { tags }
    );
    assert.ok(!out.includes(evil));
    assert.ok(calledBlock(cell(out, "t", "SELECT")).includes("&lt;img src=x onerror=alert(1)&gt;"));
  });
});

describe("functionsCalledInExpression", () => {
  const known = new Set(["is_owner", "get_ids"]);

  it("returns bare and target-schema-qualified calls of known functions", () => {
    assert.deepEqual(
      functionsCalledInExpression("(public.is_owner(id) OR (x IN ( SELECT get_ids() AS get_ids)))", "public", known),
      ["get_ids", "is_owner"]
    );
  });

  it("ignores other schemas, unknown names and string literals", () => {
    assert.deepEqual(
      functionsCalledInExpression(
        "((auth.uid() = owner) AND lower(n) = 'is_owner(x)' AND auth.is_owner(1))",
        "public",
        known
      ),
      []
    );
  });

  it("returns no calls instead of throwing on an unterminated literal", () => {
    assert.deepEqual(functionsCalledInExpression("is_owner(id) AND n = 'oops", "public", known), []);
  });
});
