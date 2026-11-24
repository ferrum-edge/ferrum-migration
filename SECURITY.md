# Security policy

## Reporting

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" (security advisories) on this repository. Do not open a public
issue, and do not include real credentials, production configs or logs in any report.
Reproduce with synthetic data instead.

## Scope and guarantees

`ferrum-migration` is an offline translator. By design it:

* performs no network I/O, database access, subprocess execution or deployment;
* reads exactly one input file (or stdin) and never follows includes or file references;
* bounds input size, structure size, depth, YAML aliases, documents, tokens and routes;
* rejects YAML duplicate keys, merge keys and non-safe tags;
* never prints input values in diagnostics (quoted spans are withheld, exception texts are
  not echoed);
* writes plaintext credentials only with `--include-secrets`, into `0600` files in a `0700`
  directory, and never into reports or `ferrum.conf`;
* never reuses stored credential values (password hashes, Kong `_transform: false`
  credentials) as credentials, and never copies static values of credential-like headers or
  query parameters;
* never emits disabled backend TLS verification (there is no opt-out);
* refuses (fails closed) rather than opening routes or downgrading auth, policy or TLS.

Bugs that break any of these properties are security issues. So is a translation that is
**less strict** than the source without an error-level caveat in the report.

## Handling generated output

Treat output generated with `--include-secrets` like the source secrets: keep it private,
never commit it, and delete it after importing into Ferrum. A `.gitignore` containing `*` is
written next to it as a guard.
