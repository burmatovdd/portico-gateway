# Read-only scan portal integration

Construct `adminauth.NewPortal(publicURL, configuredStrixRoles, pool, vault,
sessionManager, identityProvider)` with the exact configured Strix role strings.
Run `Migrate` as for the admin auth server (the pending flow table is shared).
Register the OIDC redirect `publicURL + "/portal/callback"` at the identity provider.
The portal uses separate `__Host-portico-portal` and
`__Host-portico-portal-login` cookies, a separate CSRF domain, and separate AEAD
associated data for pending login flows. The existing admin constructor and its
callback/cookies remain unchanged. Session access tokens stay server-side.

Construct `scanportal.New(portalAuth, upstreamProxy, serviceName)` and mount it at
`/portal/`. The fixed configured service must expose GET operations `getStatus`
(with required `scan_id` path parameter), `listReports`, and `getReportManifest`
(with required `scan_id` path parameter). No client may select the upstream service
or URL. The manifest API response is `{scan_id, manifest: {scan_id, artifacts}}`.

Routes:

- `/portal/`: recent available scans from `listReports`, limited to 50 when supported.
- `/portal/login`, `/portal/callback`, POST `/portal/logout`: isolated browser OIDC.
- `/portal/scans/{scan_id}`: HTML status card; authorizes ownership upstream first.
- `/portal/api/scans/{scan_id}`: projected JSON status; raw backend errors omitted.
- `/portal/api/scans/{scan_id}/artifacts`: only allowlisted filenames, no object keys.
- `/portal/scans/{scan_id}/report?format=html|markdown|pdf`: controlled source report attachment. Add `language=ru` for a separately published Russian edition.
- `/portal/scans/{scan_id}/evidence?name=...`: allowlisted published artifact attachment.
- `/portal/portal.js`, `/portal/portal.css`: embedded same-origin assets.

The API receives the currently authenticated user's access token and remains
responsible for scan ownership/admin access checks. File downloads first check
ownership via `getStatus`, then call the fixed HTTPS service origin directly,
without redirects, with a 30-second deadline and a 16 MiB body cap. Download APIs
must independently authorize ownership. Filenames/MIME types are controlled by the
portal; upstream headers are not forwarded. HTML attachments have a sandbox CSP.

The browser polls every five seconds, serializes requests, retries transient
failures at 5/10/20/30-second intervals, and stops on terminal status or denied
status access. Updates use `textContent`. No language-model request is involved.
Heartbeat age is displayed separately from the latest operational event. An event
is not proof that useful analysis occurred; absent ETA remains unknown. The
artifact list is loaded initially and again when the scan becomes terminal.

Run `go test ./internal/adminauth ./internal/scanportal` and
`node --test internal/scanportal/portal.test.js`. PostgreSQL OAuth flow tests require
`PORTICO_TEST_DATABASE_URL` pointing to an isolated test database. They verify that
admin callbacks cannot consume portal login flows and that portal callback cookies
and redirect paths are distinct.
