import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { calledFunctions, highlightSql, leaves, parseCondition } from "../src/render/sql.ts";

describe("parseCondition (AND / OR splitting)", () => {
  it("splits top-level AND into one condition each", () => {
    const n = parseCondition(
      "((employee_id = auth.uid()) AND (deleted IS FALSE) AND (status = 'enabled'::employee_status))"
    );
    assert.equal(n.kind, "and");
    assert.deepEqual(leaves(n), [
      "employee_id = auth.uid()",
      "deleted IS FALSE",
      "status = 'enabled'::employee_status"
    ]);
  });

  it("keeps a nested OR as a child group", () => {
    const n = parseCondition("((a = 1) AND ((b = 2) OR (c = 3)))");
    assert.equal(n.kind, "and");
    if (n.kind !== "and") return;
    assert.equal(n.children[1]?.kind, "or");
    assert.deepEqual(leaves(n), ["a = 1", "b = 2", "c = 3"]);
  });

  it("binds AND tighter than OR in unparenthesized mixes (splits on OR first)", () => {
    const n = parseCondition("a = 1 AND b = 2 OR c = 3");
    assert.equal(n.kind, "or");
    if (n.kind !== "or") return;
    assert.equal(n.children[0]?.kind, "and");
  });

  it("does not split on AND / OR inside strings, subqueries or function arguments", () => {
    const n = parseCondition(
      "((name = 'A AND B') AND (team_id IN ( SELECT get_team_ids_for_roles(ARRAY['admin'::team_role]) AS x WHERE (p OR q))))"
    );
    assert.equal(n.kind, "and");
    if (n.kind !== "and") return;
    assert.equal(n.children.length, 2);
    assert.equal(n.children[0]?.kind, "leaf");
    assert.equal(n.children[1]?.kind, "leaf");
  });

  it("keeps the parentheses of a scalar subquery ( SELECT ... )", () => {
    const n = parseCondition("( SELECT mfa_verified() AS mfa_verified)");
    assert.deepEqual(n, { kind: "leaf", sql: "( SELECT mfa_verified() AS mfa_verified)" });
  });

  it("does not treat the AND of BETWEEN a AND b or inside CASE ... END as a logical operator", () => {
    const n = parseCondition("((x BETWEEN 1 AND 5) AND (CASE WHEN a AND b THEN true ELSE false END))");
    assert.equal(n.kind, "and");
    assert.deepEqual(leaves(n), ["x BETWEEN 1 AND 5", "CASE WHEN a AND b THEN true ELSE false END"]);
    const between = parseCondition("x BETWEEN 1 AND 5 AND y = 2");
    assert.deepEqual(leaves(between), ["x BETWEEN 1 AND 5", "y = 2"]);
  });

  it("returns a single condition as a leaf", () => {
    assert.deepEqual(parseCondition("true"), { kind: "leaf", sql: "true" });
  });

  it("returns unbalanced parentheses or quotes as raw original SQL", () => {
    for (const bad of ["((a = 1) AND (b = 2)", "(a = 'x) AND (b = 1)", "a = 1) AND (b = 2", "CASE WHEN a THEN b"]) {
      assert.deepEqual(parseCondition(bad), { kind: "raw", sql: bad }, bad);
    }
  });

  it("returns raw when splitting would produce an empty operand (e.g. AND AND)", () => {
    const n = parseCondition("a = 1 AND AND b = 2");
    assert.equal(n.kind, "raw");
  });
});

describe("highlightSql", () => {
  it("escapes HTML in the input", () => {
    const html = highlightSql("name = '<script>alert(1)</script>' AND \"x<y\" = 1");
    assert.ok(!html.includes("<script>"));
    assert.ok(html.includes("&lt;script&gt;"));
    assert.ok(html.includes("&quot;x&lt;y&quot;"));
  });

  it("links known functions but not keywords", () => {
    const html = highlightSql("x IN ( SELECT get_ids() ) AND auth.uid() = y AND coalesce(a, b)", (n) =>
      n === "get_ids" ? "#fn--get_ids--0" : null
    );
    assert.ok(html.includes('<a class="f" href="#fn--get_ids--0">get_ids</a>'));
    assert.ok(html.includes('<span class="f">auth.uid</span>'));
    assert.ok(!html.includes(">coalesce</a>"));
  });

  it("escapes input it cannot tokenize", () => {
    assert.equal(highlightSql("'<b>"), "&#39;&lt;b&gt;");
  });
});

describe("calledFunctions", () => {
  it("lists called functions including the schema qualifier", () => {
    assert.deepEqual(calledFunctions("auth.uid() = x AND is_member(team) AND (a IN ( SELECT 1 ))"), [
      "auth.uid",
      "is_member"
    ]);
  });
});
