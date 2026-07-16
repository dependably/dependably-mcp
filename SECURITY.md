# Security Policy

## Supported versions

Only the latest published release of `dependably-mcp` receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately instead, either via:

- **GitHub private vulnerability reporting** — [Security → Report a vulnerability](https://github.com/dependably/dependably-mcp/security/advisories/new) on this repository, or
- **Email** — mikehiland@gmail.com with `[dependably-mcp security]` in the subject.

Include what you can: affected version, a reproduction or proof of concept, and impact as you understand it. You'll get an acknowledgement within a few days, and a fix or mitigation plan before any public disclosure is coordinated with you.

## Scope notes

- This MCP server holds a **Dependably Personal Access Token** (`DEPENDABLY_TOKEN`) and talks to your Dependably instance on your behalf. Anything that could leak that token, escalate what it can do, or read local files outside `DEPENDABLY_IMPORT_ROOT` is squarely in scope.
- Vulnerabilities in the Dependably server itself belong to [dependably-community](https://github.com/dependably/dependably-community) — report them there.
