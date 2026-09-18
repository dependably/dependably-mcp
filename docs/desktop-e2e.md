# Claude Desktop install runbook

Manual end-to-end check of the extension bundle, run once per release on macOS and Windows
before the bundle is attached to a release or submitted to the directory. Automated coverage
stops at `npm run bundle:verify` (manifest valid, bundle packs, server boots from the unpacked
bundle); everything below is what only a real Claude Desktop can show.

Record the outcome in `docs/listing.md` §6.

## Before you start

- Claude Desktop 0.10 or later. Note the version (Claude → About).
- A reachable Dependably instance at v0.3.0 or later. Locally that is the `dependably-community`
  compose stack at `http://demo.localhost:8080`; check `curl -s http://demo.localhost:8080/health`.
- A personal access token minted in that instance's UI under Tokens with `read:packages` and
  `read:audit`, which covers every tool the server registers.
- The bundle for the version under test:

  ```bash
  npm ci && npm run bundle:verify
  shasum -a 256 -c dist-mcpb/dependably-<version>.mcpb.sha256
  ```

## Steps

1. **Install.** Double-click `dist-mcpb/dependably-<version>.mcpb`, or drag it onto
   Settings → Extensions. Expected: Claude Desktop shows the Dependably card with the icon,
   description and the config dialog. No terminal, no JSON editing.

2. **Configure with the dialog only.** Fill in the URL and token. Leave the timeout at its
   default, and leave the CA bundle empty. Expected: the extension turns on and 18 tools appear
   under the Dependably entry in the tools list.

3. **Blank optional fields are really unset.** Ask: "Which Dependably tools do you have?"
   Expected: 18 tools and no error. If the server fails to start, the host may have substituted
   something other than an empty string for the blank CA bundle; capture the value from the
   server's stderr (Settings → Extensions → Dependably → logs) and open an issue.

4. **Read tools return data.** Ask "Is the registry ready?" (`readiness_check`), then "List our
   packages" (`list_packages`), then "Which packages have known vulnerabilities?"
   (`list_vulnerabilities`).
   Expected: real data from the instance, no permission prompt for any read tool.

5. **The five listing prompts.** Run the prompts in `docs/listing.md` §2 verbatim. Expected: each
   one completes with data from the instance; prompt 4 returns a fenced shell command and does not
   run anything.

6. **Bad URL is a readable error.** Edit the extension settings: change the URL to
   `https://nope.example.invalid`, save, ask for `list_packages`. Expected: the tool result reads
   `… failed: getaddrinfo ENOTFOUND … Could not resolve "nope.example.invalid". Check
   DEPENDABLY_BASE_URL …`, not a stack trace and not a bare `fetch failed`. Restore the URL.

7. **Private CA (only if you have one).** Point the instance URL at a host with a certificate
   from an internal CA. Expected without the CA bundle: a TLS error that names
   `NODE_EXTRA_CA_CERTS` and says never to disable verification. Set the CA bundle file in the
   dialog. Expected: `list_packages` succeeds.

8. **Upgrade in place.** Install the next bundle version over the current one. Expected: the
    settings, including the token, survive; the tool list reflects the new version.

9. **Uninstall.** Remove the extension. Expected: the token is gone from the keychain
    (macOS: Keychain Access, search "Claude"; Windows: Credential Manager).

## Windows notes

- The bundle is the same file; Claude Desktop ships its own Node runtime on both platforms.
- The CA bundle picker must return a native path; the TLS check
  is the one most likely to differ (drive letters, case-insensitive paths). It is enforced with
  `realpath` on both ends, so a symlinked or differently cased path inside the folder should
  still be accepted, and anything outside refused.
- Check the token lands in Credential Manager, not in a plain-text config file.

## What to record

Claude Desktop version, OS and version, bundle version and SHA-256, instance version, which
steps passed, and the exact text of any error that did not match the expectation above.
