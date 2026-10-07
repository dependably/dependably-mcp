# Security Policy

## Supported versions

Only the latest published release of `dependably-mcp` receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report it privately instead, through GitHub's [private vulnerability reporting](https://github.com/dependably/dependably-mcp/security/advisories/new) on this repository, or by email to support@dependably.ca with `[dependably-mcp security]` in the subject.

Include what you can: affected version, a reproduction or proof of concept, and impact as you understand it. You'll get an acknowledgement within a few days, and a fix or mitigation plan before any public disclosure is coordinated with you.

## Scope notes

- This server holds a Dependably personal access token (`DEPENDABLY_TOKEN`) and talks to your instance on your behalf. Anything that could leak that token, extend what it can do, make the server read local files, or put an unintended command into the text the setup tools return is in scope.
- Report vulnerabilities in the Dependably server itself to [dependably-community](https://github.com/dependably/dependably-community).
