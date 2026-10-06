/**
 * Catalog queries. $1 is always the target schema name.
 * Only pg_catalog is read; table rows are never touched, with one exception: the settings columns of
 * storage.buckets (see storageBucketsQuery / STORAGE_BUCKET_SETTINGS), which are configuration rather than user data.
 */

// $1::regnamespace parses $1 as an identifier and folds unquoted upper case, so compare nspname instead
const SCHEMA_OID = "(SELECT oid FROM pg_namespace WHERE nspname = $1)";

/** Objects owned by an extension (pgroonga etc.) have a pg_depend row with deptype='e'. */
const NOT_EXTENSION_OWNED = (classid: string, oidExpr: string) => `NOT EXISTS (
  SELECT 1 FROM pg_depend d
  WHERE d.classid = '${classid}'::regclass AND d.objid = ${oidExpr} AND d.deptype = 'e'
)`;

export const SQL_SERVER_VERSION = `SELECT current_setting('server_version') AS version`;

export const SQL_ROLES = `
SELECT r.rolname AS name, r.rolbypassrls AS bypass_rls, r.rolsuper AS superuser
FROM pg_roles r
WHERE r.rolname IN ('anon', 'authenticated', 'service_role')
   OR r.oid IN (
     SELECT unnest(p.polroles) FROM pg_policy p
     JOIN pg_class c ON c.oid = p.polrelid
     WHERE c.relnamespace = ${SCHEMA_OID}
   )
ORDER BY 1`;

export const SQL_TABLES = `
SELECT c.oid, c.relname AS name, c.relkind AS relkind, c.relispartition AS is_partition,
       c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced
FROM pg_class c
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('r', 'p')
  AND ${NOT_EXTENSION_OWNED("pg_class", "c.oid")}
ORDER BY c.relname`;

export const SQL_EXTENSION_OWNED_RELATIONS = `
SELECT count(*)::int AS count
FROM pg_class c
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('r', 'p', 'v', 'm')
  AND NOT ${NOT_EXTENSION_OWNED("pg_class", "c.oid")}`;

export const SQL_COLUMNS = `
SELECT c.relname AS table_name, a.attname AS name, format_type(a.atttypid, a.atttypmod) AS type,
       a.attnotnull AS not_null, pg_get_expr(ad.adbin, ad.adrelid) AS default_expr,
       a.attidentity AS identity, a.attgenerated AS generated
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('r', 'p')
  AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum`;

export const SQL_POLICIES = `
SELECT c.relname AS table_name, p.polname AS name, p.polcmd AS cmd, p.polpermissive AS permissive,
       ARRAY(
         SELECT CASE WHEN r = 0 THEN 'public' ELSE pg_get_userbyid(r) END
         FROM unnest(p.polroles) AS r ORDER BY 1
       )::text[] AS roles,
       pg_get_expr(p.polqual, p.polrelid) AS using_expr,
       pg_get_expr(p.polwithcheck, p.polrelid) AS with_check_expr
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
WHERE c.relnamespace = ${SCHEMA_OID}
ORDER BY c.relname, p.polname`;

// ARRAY(...) of names yields name[], which the pg driver does not parse into an array, so cast to text[]
// WHEN is cut out of pg_get_triggerdef because pg_get_expr(tgqual) can fail on OLD/NEW references
export const SQL_TRIGGERS = `
SELECT c.relname AS table_name, t.tgname AS name, t.tgtype::int AS tgtype, t.tgenabled AS enabled,
       (t.tgconstraint <> 0) AS is_constraint,
       pg_get_triggerdef(t.oid) AS definition,
       ARRAY(
         SELECT a.attname FROM unnest(t.tgattr::int2[]) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = t.tgrelid AND a.attnum = k.attnum
         ORDER BY k.ord
       )::text[] AS update_columns,
       fn.nspname AS function_schema, f.proname AS function_name, f.prosecdef AS function_secdef
FROM pg_trigger t
JOIN pg_class c ON c.oid = t.tgrelid
JOIN pg_proc f ON f.oid = t.tgfoid
JOIN pg_namespace fn ON fn.oid = f.pronamespace
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('r', 'p')
  AND NOT t.tgisinternal
ORDER BY c.relname, t.tgname`;

// Constraints of tables in the schema, plus foreign keys from other schemas that reference it
export const SQL_CONSTRAINTS = `
SELECT con.conname AS name, con.contype AS contype,
       cn.nspname AS table_schema, c.relname AS table_name,
       pg_get_constraintdef(con.oid) AS definition,
       ARRAY(
         SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
         ORDER BY k.ord
       )::text[] AS columns,
       rn.nspname AS ref_schema, rc.relname AS ref_table,
       ARRAY(
         SELECT a.attname FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum
         ORDER BY k.ord
       )::text[] AS ref_columns,
       con.confdeltype AS on_delete, con.confupdtype AS on_update
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace cn ON cn.oid = c.relnamespace
LEFT JOIN pg_class rc ON rc.oid = con.confrelid
LEFT JOIN pg_namespace rn ON rn.oid = rc.relnamespace
WHERE con.contype IN ('p', 'u', 'c', 'f', 'x')
  AND con.conrelid <> 0
  AND (c.relnamespace = ${SCHEMA_OID}
       OR (con.contype = 'f' AND rc.relnamespace = ${SCHEMA_OID}))
ORDER BY cn.nspname, c.relname, con.conname`;

// information_schema privilege views are filtered by the querying role's memberships, so expand the ACLs directly
export const SQL_TABLE_GRANTS = `
SELECT c.relname AS table_name,
       CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END AS grantee,
       g.privilege_type AS privilege
FROM pg_class c
CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) AS g
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('r', 'p', 'v', 'm')
  AND g.grantee <> c.relowner
ORDER BY 1, 2, 3`;

export const SQL_COLUMN_GRANTS = `
SELECT c.relname AS table_name, a.attname AS column_name,
       CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(g.grantee) END AS grantee,
       g.privilege_type AS privilege
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
CROSS JOIN LATERAL aclexplode(a.attacl) AS g
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('r', 'p', 'v', 'm')
  AND a.attacl IS NOT NULL AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY 1, 3, 4, 2`;

export const SQL_VIEWS = `
SELECT c.relname AS name, c.relkind AS relkind,
       coalesce(
         (SELECT option_value::boolean FROM pg_options_to_table(c.reloptions) WHERE option_name = 'security_invoker'),
         false
       ) AS security_invoker,
       coalesce(
         (SELECT option_value::boolean FROM pg_options_to_table(c.reloptions) WHERE option_name = 'security_barrier'),
         false
       ) AS security_barrier,
       pg_get_viewdef(c.oid, true) AS definition,
       ARRAY(
         SELECT DISTINCT rn.nspname || '.' || rc.relname
         FROM pg_rewrite r
         JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
                         AND d.refclassid = 'pg_class'::regclass
         JOIN pg_class rc ON rc.oid = d.refobjid
         JOIN pg_namespace rn ON rn.oid = rc.relnamespace
         WHERE r.ev_class = c.oid AND rc.oid <> c.oid AND rc.relkind IN ('r', 'p', 'v', 'm', 'f')
         ORDER BY 1
       )::text[] AS base_relations
FROM pg_class c
WHERE c.relnamespace = ${SCHEMA_OID}
  AND c.relkind IN ('v', 'm')
  AND ${NOT_EXTENSION_OWNED("pg_class", "c.oid")}
ORDER BY c.relname`;

// pg_get_functiondef raises for aggregates, hence the prokind filter
export const SQL_FUNCTIONS = `
SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS identity_arguments,
       coalesce(pg_get_function_result(p.oid), '') AS returns,
       p.prokind AS prokind, l.lanname AS language, p.provolatile AS volatility,
       p.prosecdef AS security_definer,
       (SELECT substr(cfg, length('search_path=') + 1) FROM unnest(p.proconfig) AS cfg
        WHERE cfg LIKE 'search_path=%' LIMIT 1) AS search_path,
       EXISTS (
         SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) AS g
         WHERE g.privilege_type = 'EXECUTE'
           AND (g.grantee = 0 OR g.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'anon'))
       ) AS anon_execute,
       EXISTS (
         SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) AS g
         WHERE g.privilege_type = 'EXECUTE'
           AND (g.grantee = 0 OR g.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'authenticated'))
       ) AS authenticated_execute,
       CASE WHEN p.prokind IN ('f', 'p') THEN pg_get_functiondef(p.oid) END AS definition,
       obj_description(p.oid, 'pg_proc') AS comment
FROM pg_proc p
JOIN pg_language l ON l.oid = p.prolang
WHERE p.pronamespace = ${SCHEMA_OID}
  AND ${NOT_EXTENSION_OWNED("pg_proc", "p.oid")}
ORDER BY p.proname, 2`;

export const SQL_EXTENSION_OWNED_FUNCTIONS = `
SELECT count(*)::int AS count
FROM pg_proc p
WHERE p.pronamespace = ${SCHEMA_OID}
  AND NOT ${NOT_EXTENSION_OWNED("pg_proc", "p.oid")}`;

// Event triggers installed by the Supabase platform (pgrst_ddl_watch etc.) are owned by supabase_admin
export const SQL_EVENT_TRIGGERS = `
SELECT e.evtname AS name, pg_get_userbyid(e.evtowner) AS owner,
       EXISTS (
         SELECT 1 FROM pg_depend d
         WHERE d.classid = 'pg_event_trigger'::regclass AND d.objid = e.oid AND d.deptype = 'e'
       ) AS extension_owned
FROM pg_event_trigger e
ORDER BY 1`;

/** Columns of storage.buckets that exist in this Storage version (older versions lack the limit columns). */
export const SQL_STORAGE_BUCKET_COLUMNS = `
SELECT a.attname AS name,
       (has_schema_privilege(c.relnamespace, 'USAGE') AND has_column_privilege(c.oid, a.attnum, 'SELECT')) AS readable
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'storage')
  AND c.relname = 'buckets'
  AND a.attnum > 0 AND NOT a.attisdropped`;

/**
 * Whether row security filters storage.buckets for the current role, and whether a PERMISSIVE SELECT policy applies
 * to it. storage.buckets has RLS enabled, so column privileges alone return no rows without such a policy.
 */
export const SQL_STORAGE_BUCKET_ACCESS = `
SELECT row_security_active(c.oid) AS rls_active,
       EXISTS (
         SELECT 1 FROM pg_policy p
         WHERE p.polrelid = c.oid AND p.polpermissive AND p.polcmd IN ('r', '*')
           AND (0 = ANY (p.polroles)
                OR EXISTS (SELECT 1 FROM unnest(p.polroles) AS r(oid) WHERE pg_has_role(current_user, r.oid, 'USAGE')))
       ) AS has_select_policy
FROM pg_class c
WHERE c.relnamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'storage')
  AND c.relname = 'buckets'`;

/** Settings read from storage.buckets; nothing else of the row (owner etc.) is selected. */
export const STORAGE_BUCKET_SETTINGS = ["id", "name", "public", "file_size_limit", "allowed_mime_types"] as const;

/**
 * Bucket settings. Only names from STORAGE_BUCKET_SETTINGS are interpolated; a column missing in this version is
 * selected as NULL.
 */
export function storageBucketsQuery(existing: ReadonlySet<string>): string {
  const cols = STORAGE_BUCKET_SETTINGS.map((c) => (existing.has(c) ? `b.${c}` : `NULL AS ${c}`));
  return `SELECT ${cols.join(", ")} FROM storage.buckets b ORDER BY b.id`;
}
