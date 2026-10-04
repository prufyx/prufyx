# Security policy

## Supported versions

Prufyx is an early alpha. This repository is published under
AGPL-3.0-only (see [LICENSE](LICENSE)), but no tagged, versioned, or signed
release has been published from it — there is no GitHub Release and no
version tag. A source preview is not a published supported release. Once a
tagged Community alpha is published, security fixes are provided for the
latest published alpha when practical; older published alphas are
unsupported.

| Version | Supported |
| --- | --- |
| Current untagged source preview | No published support commitment |
| Latest published Community alpha | Yes, when practical |
| Earlier published alphas | No |

## Report a vulnerability privately

Use either private channel:

- open a private security advisory in the
  [GitHub repository](https://github.com/prufyx/prufyx/security/advisories/new);
- email [hello@prufyx.com](mailto:hello@prufyx.com).

Include the affected version or commit, impact, and a minimal reproduction.
Do not open a public issue. Do not send credentials, Kubernetes Secrets,
production snapshots, raw customer objects, or other sensitive data. The
maintainer will arrange a safer transfer method if more evidence is needed.

The project does not promise a response-time or remediation SLA during alpha.
Spas Atanasov will coordinate disclosure after the impact and fix are
understood.

Examples, synthetic fixtures, documentation, roadmap items, and scoped
`PASS` results are not production security controls or whole-upgrade safety
claims.


## Key management

[Key management](cli/docs/key-management.md) lists every signing key and
pinned digest the code defines, where each public part is pinned, and the
rotation, loss and compromise procedures. No production key or trust root is
pinned in this repository today.
