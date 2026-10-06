import { readFileSync } from "node:fs";
import pg from "pg";
import { connectsOnlyToLoopback } from "../../../src/extract/connection.ts";

// Loads ci.sql into DATABASE_URL for the CI integration workflow. Uses pg rather than psql so that the runner
// needs no PostgreSQL client, and applies the same loopback rule as the tests before running any DDL.
const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is not set");
if (!connectsOnlyToLoopback(url, process.env)) throw new Error("DATABASE_URL points at a non-loopback host");

const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  await client.query(readFileSync(new URL("ci.sql", import.meta.url), "utf8"));
} finally {
  await client.end();
}
