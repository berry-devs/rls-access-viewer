import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { compileTags, loadConfig } from "../src/model/config.ts";
import type { FunctionInfo, RulesDocument } from "../src/model/types.ts";
import { MAX_INLINE_BODY_LINES } from "../src/render/functionRules.ts";
import { anchorId, renderHtml } from "../src/render/html.ts";
import { def, doc, policy, table } from "./fixtures.ts";

const tags = compileTags(loadConfig());

function fn(name: string, body: string): FunctionInfo {
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
    definition: def(name, body)
  };
}

/** Cuts a cell section by id. */
function section(html: string, id: string): string {
  const start = html.indexOf(`id="${id}"`);
  assert.ok(start >= 0, `${id} not found`);
  return html.slice(start, html.indexOf("</section>", start));
}

/** The folded block of one function in a cell's "Functions called by these policies". */
function functionBlock(cellHtml: string, name: string): string {
  const marker = `">${name}()</a>`;
  const at = cellHtml.indexOf(marker, cellHtml.indexOf("<h4>Functions called by these policies</h4>"));
  assert.ok(at >= 0, `${name} block not found`);
  const start = cellHtml.lastIndexOf('<details class="pfn">', at);
  // Nested <details> are inside, so cut up to the next block or the end of the list
  const next = cellHtml.indexOf('<details class="pfn">', at);
  const end = next >= 0 ? next : cellHtml.indexOf("<h4>Effective rule per role</h4>", at);
  return cellHtml.slice(start, end);
}

const fullDefinitionOf = (name: string) => `<summary>Full definition of ${name}()</summary>`;

describe("bodies of PL/pgSQL functions without findings in policy cells", () => {
  const longBody = `\nBEGIN\n${Array.from({ length: MAX_INLINE_BODY_LINES }, (_, i) => `  -- line ${i}`).join("\n")}\n  RETURN true;\nEND;`;
  const html = renderHtml(
    doc({
      tables: [
        table({
          name: "items",
          policies: [
            policy({
              name: "read",
              command: "SELECT",
              using: "(quiet_short(id) AND quiet_long(id) AND sql_helper(id) AND guarded(id))"
            })
          ]
        })
      ],
      functions: [
        fn("quiet_short", "\nBEGIN\n  RETURN EXISTS (SELECT 1 FROM public.items WHERE x = '<b>');\nEND;"),
        fn("quiet_long", longBody),
        {
          ...fn("sql_helper", ""),
          language: "sql",
          definition:
            "CREATE OR REPLACE FUNCTION public.sql_helper(_id uuid)\n RETURNS boolean\n LANGUAGE sql\nAS $function$\n  SELECT true;\n$function$\n"
        },
        fn(
          "guarded",
          "\nBEGIN\n  IF auth.uid() IS NULL THEN\n    RAISE EXCEPTION 'not signed in';\n  END IF;\n  RETURN public.sql_helper(1);\nEND;"
        )
      ]
    }),
    { tags }
  );
  const cell = section(html, anchorId("c", "items", "SELECT"));

  it("folds in the body of a short function whose analysis found nothing, and says to review it", () => {
    const block = functionBlock(cell, "quiet_short");
    assert.ok(block.includes(fullDefinitionOf("quiet_short")));
    assert.ok(block.includes("No structural conditions were detected by the analysis; review the body below."));
    assert.ok(!block.includes("No guards, early returns"));
    assert.ok(block.includes("&#39;&lt;b&gt;&#39;"));
  });

  it(`links instead of folding a body longer than ${MAX_INLINE_BODY_LINES} lines`, () => {
    const block = functionBlock(cell, "quiet_long");
    assert.ok(!block.includes(fullDefinitionOf("quiet_long")));
    assert.ok(block.includes("No structural conditions were detected by the analysis; see the full definition."));
    assert.ok(block.includes(`Full definition: <a href="#${anchorId("fn", "quiet_long", "1")}">quiet_long()</a>`));
  });

  it("keeps a function with findings summarized without its body", () => {
    const block = functionBlock(cell, "guarded");
    assert.ok(block.includes("not signed in"));
    assert.ok(!block.includes(fullDefinitionOf("guarded")));
    assert.ok(!block.includes("No structural conditions"));
  });

  it("folds each body in at most once per cell, even when it is also reached through another function", () => {
    assert.ok(functionBlock(cell, "guarded").includes("via"));
    assert.equal(cell.split(fullDefinitionOf("sql_helper")).length - 1, 1);
    assert.equal(cell.split(fullDefinitionOf("quiet_short")).length - 1, 1);
  });
});

describe("WITH CHECK written identically to USING", () => {
  const expr = "(owner = auth.uid())";
  const fixture: RulesDocument = doc({
    tables: [
      table({
        name: "items",
        policies: [
          policy({ name: "same", command: "UPDATE", using: expr, withCheck: expr }),
          policy({ name: "different", command: "UPDATE", using: expr, withCheck: "(owner = auth.uid() AND (x > 1))" }),
          policy({ name: "omitted", command: "UPDATE", using: expr })
        ]
      })
    ]
  });
  const cell = section(renderHtml(fixture, { tags }), anchorId("c", "items", "UPDATE"));
  const row = (name: string) => {
    const policies = cell.slice(0, cell.indexOf("</table>"));
    const start = policies.indexOf(`<td>${name}`);
    assert.ok(start >= 0, name);
    return policies.slice(start, policies.indexOf("</tr>", start));
  };
  const cells = (r: string) => r.split("<td>").slice(1);

  it("shows only a 'same as USING' badge in the WITH CHECK column", () => {
    const [, , , usingCol, checkCol] = cells(row("same"));
    assert.ok(usingCol?.includes("owner"));
    assert.ok(checkCol?.includes(">same as USING</span>"));
    assert.ok(!checkCol?.includes("owner"));
  });

  it("shows both expressions when they differ", () => {
    const [, , , , checkCol] = cells(row("different"));
    assert.ok(checkCol?.includes("x"));
    assert.ok(!checkCol?.includes("same as USING"));
  });

  it("keeps the reuse note, not the badge, when WITH CHECK is omitted", () => {
    const [, , , , checkCol] = cells(row("omitted"));
    assert.ok(checkCol?.includes("No WITH CHECK: the USING expression is reused"));
    assert.ok(!checkCol?.includes("same as USING"));
  });

  it("leaves the per-role composition unchanged", () => {
    const roles = cell.slice(cell.indexOf("<h4>Effective rule per role</h4>"));
    assert.ok(!roles.includes("same as USING"));
  });
});
