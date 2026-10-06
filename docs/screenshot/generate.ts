// Writes docs/screenshot/rules.json, the sample behind docs/images/viewer.png. The schema is fictional (profiles /
// posts / comments and two Storage buckets) so that the screenshot never shows a real project's rules.
// To regenerate the screenshot (never use a real project's data):
//   node --import tsx docs/screenshot/generate.ts
//   pnpm build
//   node dist/cli.js render --in docs/screenshot/rules.json --out out/screenshot/index.html
// then capture out/screenshot/index.html in a browser with the light theme, about 1440 px wide, showing the matrix
// and the details of one cell, and save it as docs/images/viewer.png.
import { writeFileSync } from "node:fs";
import type { ColumnInfo, Constraint, FunctionInfo, Grant, TableRules } from "../../src/model/types.ts";
import { defaultGrants, doc, policy, table, trigger } from "../../test/fixtures.ts";

const UID = "( SELECT auth.uid() AS uid)";

function column(name: string, type: string, extra: Partial<ColumnInfo> = {}): ColumnInfo {
  return { name, type, notNull: false, default: null, identity: null, generated: false, ...extra };
}

function fk(
  name: string,
  columns: string[],
  target: string,
  onDelete: "CASCADE" | "SET NULL",
  schema = "public"
): Constraint {
  return {
    kind: "foreign",
    name,
    columns,
    references: { schema, table: target, columns: ["id"] },
    onDelete,
    onUpdate: "NO ACTION",
    definition: `FOREIGN KEY (${columns.join(", ")}) REFERENCES ${schema === "public" ? "" : `${schema}.`}${target}(id) ON DELETE ${onDelete}`
  };
}

function pk(tableName: string): Constraint {
  return { kind: "primary", name: `${tableName}_pkey`, columns: ["id"], definition: "PRIMARY KEY (id)" };
}

/** Default Supabase grants without the listed privileges for anon. */
function grantsWithoutAnon(...privileges: string[]): Grant[] {
  return defaultGrants().filter((g) => !(g.grantee === "anon" && privileges.includes(g.privilege)));
}

function fn(f: Partial<FunctionInfo> & Pick<FunctionInfo, "name" | "definition">): FunctionInfo {
  return {
    identityArguments: "",
    returns: "trigger",
    kind: "function",
    language: "plpgsql",
    volatility: "VOLATILE",
    securityDefiner: false,
    searchPath: '""',
    executableBy: { anon: false, authenticated: true },
    comment: null,
    ...f
  };
}

const profiles: TableRules = table({
  name: "profiles",
  columns: [
    column("id", "uuid", { notNull: true }),
    column("username", "text", { notNull: true }),
    column("avatar_url", "text"),
    column("banned", "boolean", { notNull: true, default: "false" })
  ],
  constraints: [pk("profiles"), fk("profiles_id_fkey", ["id"], "users", "CASCADE", "auth")],
  policies: [
    policy({ name: "Profiles are viewable by everyone", command: "SELECT", roles: ["public"], using: "true" }),
    policy({
      name: "Users update their own profile",
      command: "UPDATE",
      using: `(${UID} = id)`,
      withCheck: `(${UID} = id)`
    })
  ],
  grants: grantsWithoutAnon("INSERT", "UPDATE", "DELETE", "TRUNCATE")
});

const posts: TableRules = table({
  name: "posts",
  columns: [
    column("id", "bigint", { notNull: true, identity: "ALWAYS" }),
    column("author_id", "uuid", { notNull: true, default: "auth.uid()" }),
    column("title", "text", { notNull: true }),
    column("body", "text"),
    column("published", "boolean", { notNull: true, default: "false" }),
    column("comment_count", "integer", { notNull: true, default: "0" })
  ],
  constraints: [pk("posts"), fk("posts_author_id_fkey", ["author_id"], "profiles", "CASCADE")],
  policies: [
    policy({
      name: "Published posts are readable",
      command: "SELECT",
      roles: ["anon", "authenticated"],
      using: "(published = true)"
    }),
    policy({
      name: "Authors manage their posts",
      command: "ALL",
      using: `(${UID} = author_id)`,
      withCheck: `(${UID} = author_id)`
    }),
    policy({
      name: "Banned users cannot write",
      command: "ALL",
      permissive: false,
      using: `(NOT is_banned(${UID}))`,
      withCheck: `(NOT is_banned(${UID}))`
    })
  ],
  triggers: [
    trigger({
      name: "posts_validate",
      events: ["INSERT", "UPDATE"],
      function: { schema: "public", name: "validate_post", securityDefiner: false },
      definition:
        "CREATE TRIGGER posts_validate BEFORE INSERT OR UPDATE ON public.posts FOR EACH ROW EXECUTE FUNCTION validate_post()"
    })
  ],
  grants: grantsWithoutAnon("INSERT", "UPDATE", "DELETE", "TRUNCATE")
});

const comments: TableRules = table({
  name: "comments",
  columns: [
    column("id", "bigint", { notNull: true, identity: "ALWAYS" }),
    column("post_id", "bigint", { notNull: true }),
    column("author_id", "uuid", { default: "auth.uid()" }),
    column("body", "text", { notNull: true })
  ],
  constraints: [
    pk("comments"),
    fk("comments_post_id_fkey", ["post_id"], "posts", "CASCADE"),
    fk("comments_author_id_fkey", ["author_id"], "profiles", "SET NULL")
  ],
  policies: [
    policy({
      name: "Comments on published posts are readable",
      command: "SELECT",
      roles: ["anon", "authenticated"],
      using: "(EXISTS ( SELECT 1\n   FROM posts p\n  WHERE ((p.id = comments.post_id) AND p.published)))"
    }),
    policy({ name: "Users comment as themselves", command: "INSERT", withCheck: `(${UID} = author_id)` }),
    policy({ name: "Users delete their comments", command: "DELETE", using: `(${UID} = author_id)` })
  ],
  triggers: [
    trigger({
      name: "comments_count",
      timing: "AFTER",
      events: ["INSERT", "DELETE"],
      function: { schema: "public", name: "update_comment_count", securityDefiner: true },
      definition:
        "CREATE TRIGGER comments_count AFTER INSERT OR DELETE ON public.comments FOR EACH ROW EXECUTE FUNCTION update_comment_count()"
    })
  ],
  grants: grantsWithoutAnon("INSERT", "UPDATE", "DELETE", "TRUNCATE")
});

const functions: FunctionInfo[] = [
  fn({
    name: "is_banned",
    identityArguments: "uid uuid",
    returns: "boolean",
    language: "sql",
    volatility: "STABLE",
    securityDefiner: true,
    definition: `CREATE OR REPLACE FUNCTION public.is_banned(uid uuid)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  SELECT coalesce((SELECT banned FROM public.profiles WHERE id = uid), false)
$function$
`
  }),
  fn({
    name: "validate_post",
    definition: `CREATE OR REPLACE FUNCTION public.validate_post()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
BEGIN
  -- Titles are shown in lists, so keep them short
  IF length(NEW.title) > 200 THEN
    RAISE EXCEPTION 'title is too long' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'UPDATE' AND NEW.author_id IS DISTINCT FROM OLD.author_id THEN
    RAISE EXCEPTION 'author_id cannot be changed';
  END IF;
  RETURN NEW;
END;
$function$
`
  }),
  fn({
    name: "update_comment_count",
    securityDefiner: true,
    definition: `CREATE OR REPLACE FUNCTION public.update_comment_count()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    UPDATE public.posts SET comment_count = comment_count + 1 WHERE id = NEW.post_id;
  ELSE
    UPDATE public.posts SET comment_count = comment_count - 1 WHERE id = OLD.post_id;
  END IF;
  RETURN NULL;
END;
$function$
`
  })
];

const storageObjects: TableRules = table({
  name: "objects",
  columns: [
    column("id", "uuid", { notNull: true }),
    column("bucket_id", "text"),
    column("name", "text"),
    column("owner_id", "text")
  ],
  policies: [
    policy({
      name: "Avatar images are publicly accessible",
      command: "SELECT",
      roles: ["public"],
      using: "(bucket_id = 'avatars'::text)"
    }),
    policy({
      name: "Users upload their own avatar",
      command: "INSERT",
      withCheck: `((bucket_id = 'avatars'::text) AND ((storage.foldername(name))[1] = (${UID})::text))`
    }),
    policy({
      name: "Users read their attachments",
      command: "SELECT",
      using: `((bucket_id = 'attachments'::text) AND (owner_id = (${UID})::text))`
    })
  ]
});

const rules = doc({
  generatedAt: "2026-10-05T00:00:00.000Z",
  roles: [
    { name: "anon", bypassRls: false, superuser: false },
    { name: "authenticated", bypassRls: false, superuser: false },
    { name: "service_role", bypassRls: true, superuser: false }
  ],
  tables: [profiles, posts, comments],
  views: [
    {
      name: "published_posts",
      kind: "view",
      securityInvoker: true,
      securityBarrier: false,
      definition: " SELECT id, author_id, title\n   FROM posts\n  WHERE published;",
      baseRelations: [{ schema: "public", name: "posts" }],
      grants: defaultGrants()
    }
  ],
  functions,
  storage: {
    buckets: [
      {
        id: "avatars",
        name: "avatars",
        public: true,
        fileSizeLimit: 1048576,
        allowedMimeTypes: ["image/png", "image/jpeg"]
      },
      { id: "attachments", name: "attachments", public: false, fileSizeLimit: null, allowedMimeTypes: null }
    ],
    bucketsReadable: true,
    bucketsFiltered: false,
    objects: storageObjects
  }
});

writeFileSync(new URL("rules.json", import.meta.url), `${JSON.stringify(rules, null, 2)}\n`);
