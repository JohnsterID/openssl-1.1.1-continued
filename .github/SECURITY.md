# Security policy

| Ref | Status |
|---|---|
| the current `1.1.1*-carry` branch (the default branch, now `1.1.1zi-carry`) and the newest `carry/*` tag | fixes accepted |
| older `carry/*` tags and older `1.1.1*-carry` branches | not updated; move to the newest tag |
| `OpenSSL_1_1_1-continued`, `tarball/*` | OpenSSL's code as released; never changed here |
| `tools` | the import and watch tooling; fixes accepted |

## Where to report

- **OpenSSL's own 1.1.1 code** (anything that is not a carried fix listed in the README): the OpenSSL
  Project, `openssl-security@openssl.org`.
- **A carried fix, or the version text and packaging changes made here:** privately, through the Security
  tab ("Report a vulnerability"). Please don't open a public issue for an undisclosed vulnerability.
  Most carried fixes are backports of public OpenSSL commits, so a flaw in one may also affect OpenSSL's
  supported branches: please tell OpenSSL too.
- **Anything without security impact** (build failures, wrong results, documentation): an issue.

A confirmed problem in a carried fix is fixed by a commit on the current `1.1.1*-carry` branch and a new
`carry/*` tag, with a GitHub security advisory where it helps users. When OpenSSL's own 1.1.1 source for a
carried fix becomes public, OpenSSL's code replaces the backport. This is a one-person, best-effort project.
