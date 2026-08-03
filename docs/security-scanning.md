# Security scanning

This repository has **no GitHub Advanced Security licence**. The native secret
scanning API returns:

```text
Repository does not have GitHub Advanced Security enabled.
```

That is a hard block we cannot lift from inside the codebase. `.github/workflows/security.yml`
provides equivalent coverage using tooling that runs on a standard Actions runner.

## Jobs

| Job | Tool | What it catches |
| --- | --- | --- |
| Secret scan | `gitleaks` over full history | Credentials committed in any reachable commit, not just `HEAD` |
| Dependency audit (Python) | `pip-audit --strict` | Known advisories in the resolved Python tree, including unfixable ones |
| Dependency audit (Node) | `npm audit --audit-level=high` | Known advisories in the frontend tree |

## Why full history

`actions/checkout` defaults to a shallow clone. A shallow scan reads the working
tree only, so a credential that was deleted in a later commit still reports clean
while remaining fully retrievable from the published history.

Deleting a secret from `HEAD` does not revoke it. Only rotation revokes it.
History rewriting reduces retrievability; it does not undo disclosure.

The workflow therefore sets `fetch-depth: 0`.

## Why `--redact`

Actions logs are a disclosure channel in their own right. A scanner configured to
print the matched value republishes the credential it just found, in a log that
outlives the branch. Every finding is redacted; the file, commit, and line are
reported, the value is not.

## Why the rules are narrowed

This is a threat-intelligence platform. It legitimately stores strings shaped like
credentials: file hashes, indicator values, CPE URIs, vendor identifiers. Left
unconfigured, a generic entropy scanner fires on the pinned OTX/KEV/NVD corpus and
produces a wall of false positives.

The allowlist in `.gitleaks.toml` exists so the job stays credible. A scan that
everyone learns to ignore is worse than no scan, because it also carries a green
badge. The allowlist covers `frontend/src/data/raw/**` (published advisories),
binary assets, and environment indirection patterns such as `os.environ`.

It does **not** allowlist any real credential, and it must never be extended to
silence a true finding. The correct response to a true finding is rotation.

## What this does not prove

- **A green secret scan does not mean no credential ever leaked.** It means none
  matches the configured rules. A credential in an unusual format, or in a repo
  this workflow does not run against, is invisible to it.
- **`npm audit` here is not reproducible.** No `frontend/package-lock.json` is
  committed, so each run resolves a fresh tree. The audited tree is not
  necessarily the tree any developer has locally. Commit a lockfile and this
  becomes deterministic.
- **A dependency audit reports known advisories only.** It says nothing about
  unreported vulnerabilities, and nothing at all about our own code.
- **This workflow does not scan the sibling data repository.** See below.

## Known outstanding exposure

A Ransomware.live API key is committed in plaintext in the sibling repository
`stmarya/NogoSecV3.1.1`, in multiple files under `API_Testing/OTX/`, and is present
on the current default branch head, not merely in old history.

Remediation order matters and cannot be reordered:

1. **Rotate the key at the provider.** Until this happens nothing else helps. The
   key must be assumed compromised: the repository is published, and the value has
   been retrievable for the entire life of those commits.
2. Remove the literal from the working tree and read it from the environment.
3. Rewrite history to reduce retrievability.
4. Keep a scanner in front of the repository so it cannot recur.

Steps 2–4 are tracked in that repository. Step 1 requires provider credentials and
can only be done by the key owner.
