# Security Policy

## Supported versions

While the package is at 0.x, only the latest minor release receives security fixes. Upgrade to it before reporting
an issue found in an older release.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability** (private vulnerability reporting). Do not open a public issue, pull request or discussion
for a suspected vulnerability.

Include, where possible:

- the affected package version and Node.js version;
- the command and options used, and a minimal schema or `rules.json` that reproduces the problem;
- what you expected and what happened.

Do not include real connection strings, passwords, keys or data from a production database in the report.

Reports are handled on a best-effort basis. We will try to acknowledge a report and keep you informed of the progress
of a fix, but cannot promise a specific response time.

## Scope

rls-access-viewer is read-only and describes what the database catalog says; it does not validate or simulate
policies, so a policy that the viewer displays correctly but that is itself insecure is not a vulnerability in this
tool. Examples of issues that are in scope:

- secrets in a recognized format (e.g. JWTs, `sb_secret_…` keys) that are not redacted in `rules.json`, the generated
  HTML or log output;
- catalog-derived strings (names, definitions, function bodies) that are not escaped in the generated HTML, or ways to
  bypass its Content Security Policy or make it load external resources;
- ways to make the CLI connect to a non-loopback host without `--allow-remote`, or to print a connection string;
- `extract` running anything other than read-only catalog queries, or leaving its `READ ONLY` transaction.
