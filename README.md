# m365-capability-probe

A small command-line tool that takes one Entra app registration — tenant ID, client ID, client
secret — and reports **what that app can actually reach in Microsoft 365**, rather than what its
permission list appears to promise.

It answers two questions:

1. **Does the app see the same thing as itself and as a person?** The same file is read twice in a
   single run: once with an app-only token, once on behalf of a signed-in user. The two answers are
   printed next to each other.
2. **What exactly came back when it could not?** Refusals are recorded as measurements, with the
   error code the identity provider or Graph actually returned. A `403` is a result here, not a bug
   report.

Everything goes through `HttpClient` directly. No Graph SDK: the value of this tool is that a reader
can see which URL was called with which headers and re-issue it by hand, which an SDK hides. It also
keeps one code path for Graph and for any SharePoint REST call added later.

## What it is not

It does not decrypt protected files, walk a whole site, measure throughput, or track deltas. It does
not try to make failing calls succeed. Several of the things it measures are *expected* to fail, and
a run where they start succeeding is a finding in the other direction.

## Requirements

- .NET 10 SDK
- An Entra app registration in the tenant you want to look at
- A SharePoint site with at least one file in a document library
- A non-administrator account that can see that site, for the delegated leg

## App registration setup

Grant and admin-consent these API permissions:

| API | Permission | Type |
| --- | --- | --- |
| Microsoft Graph | `Sites.Read.All` | Application |
| Microsoft Graph | `Sites.Read.All` | Delegated |
| SharePoint | `Sites.Read.All` | Application |

Deliberately **do not** grant anything for Azure Rights Management, and **do not** grant SharePoint
`Sites.Read.All` as a *delegated* permission. Both gaps are what the `auth` subcommand measures;
filling them in makes the tool report less, not more.

Under **Authentication**, set *Allow public client flows* to **Yes**. The delegated leg uses the
device code flow, which is a public-client flow and does not use the client secret at all — the
secret is only used by the app-only leg.

## Configuration

Six keys:

| Key | Meaning |
| --- | --- |
| `TenantId` | Directory (tenant) ID |
| `ClientId` | Application (client) ID |
| `ClientSecret` | Client secret |
| `SiteUrl` | `https://<host>/sites/<name>` |
| `FilePath` | Library-relative path, e.g. `/Shared Documents/test.docx` |
| `DelegatedUserHint` | Sign-in name to use for the delegated leg |

They are read from five layers, and **a later layer wins**:

1. `src/CapabilityProbe.Cli/appsettings.json` — committed, keys present, values empty. It exists to
   document the schema, not to hold values.
2. `appsettings.local.json` — git-ignored, next to `appsettings.json`.
3. **user-secrets** — the intended home for `ClientSecret`.
4. Environment variables prefixed `PROBE_`, e.g. `PROBE_ClientSecret`.
5. Command line, e.g. `--ClientSecret=...`.

Recommended setup:

```bash
cd src/CapabilityProbe.Cli
dotnet user-secrets set "TenantId"          "<tenant guid>"
dotnet user-secrets set "ClientId"          "<client guid>"
dotnet user-secrets set "ClientSecret"      "<secret value>"
dotnet user-secrets set "SiteUrl"           "https://contoso.sharepoint.com/sites/probe"
dotnet user-secrets set "FilePath"          "/Shared Documents/test.docx"
dotnet user-secrets set "DelegatedUserHint" "reader@contoso.com"
```

The tool validates configuration before it does anything else. Missing keys are listed by name,
together with the subcommand each one blocks, and the run stops — no exception, no partial probe:

```
Missing or invalid keys:
  ClientSecret       missing - client secret; keep it in user-secrets, not in a committed file
                     blocks: auth, access
  FilePath           missing - library-relative path, e.g. /Shared Documents/test.docx
                     blocks: access

Subcommand readiness:
  auth     ready
  access   needs FilePath
```

## Running

```bash
dotnet run --project src/CapabilityProbe.Cli -- auth
dotnet run --project src/CapabilityProbe.Cli -- access
```

Any key can be overridden per run:

```bash
dotnet run --project src/CapabilityProbe.Cli -- access --FilePath="/Shared Documents/other.docx"
```

Both subcommands print a table and write the same content to `reports/<command>-<timestamp>.json`.

### `auth`

Requests a token for three audiences in two modes and reports all six outcomes. No token is used to
call anything; this subcommand only measures what the app holds.

| audience | scope |
| --- | --- |
| Graph | `https://graph.microsoft.com/.default` |
| SharePoint | `https://<host of SiteUrl>/.default` |
| Azure RMS | `https://aadrm.com/.default` |

The SharePoint scope is built from the host name in `SiteUrl`, so the tool carries no built-in
tenant list.

With the setup above, the expected shape is:

| audience | app-only | delegated |
| --- | --- | --- |
| Graph | holds `Sites.Read.All` | holds `Sites.Read.All` |
| SharePoint | holds `Sites.Read.All` | holds `Sites.Read.All` — **see below** |
| Azure RMS | **holds nothing** | **holds nothing** — nothing granted |

A cell that lands somewhere else is marked `[!]`.

Two of those cells are worth dwelling on, because neither is what the permissions blade predicts.

**SharePoint / delegated holds a permission that was never granted to it.** The app registration has
no SharePoint *delegated* permission at all — only the application one. Yet the delegated leg comes
back with a token whose `aud` is `00000003-0000-0ff1-ce00-000000000000` (SharePoint Online) carrying
`scp: Sites.Read.All User.Read` — an exact mirror of the app's *Microsoft Graph* delegated grants.
Consenting to Graph's `Sites.Read.All` reaches SharePoint as well. Nothing on the API permissions
screen says so; it only shows up by taking a token and looking inside it.

**Azure RMS / app-only is issued a token that can do nothing.** No RMS permission is granted in either
direction. The delegated leg is refused outright with `AADSTS65001`, but the app-only leg succeeds —
and returns a token with no `roles` and no `scp`. The two legs disagree because `.default` means
different things to each: for a signed-in person it means "every scope already consented", and zero
consented scopes is an error; for client credentials it means "every app role assigned", and zero
assigned roles is simply an empty token.

**A token being issued is not the same as the app being able to do anything.** Entra hands out tokens
for resources an app was granted nothing for — client credentials against a resource with no assigned
app roles still succeeds, as long as that resource's service principal exists in the tenant — and the
token comes back carrying no roles and no scopes. It is a valid token that every call refuses. Judging
by issuance alone would report such an app as reaching a resource it cannot touch, which is precisely
the mistake this tool exists to prevent.

So each cell reports both halves: whether a token came back, and what it carries. The report reads the
`roles` and `scp` claims out of the token's payload and prints them. Those claims are **read, not
verified**: this tool is not the audience of any of these tokens and makes no trust decision based on
them, so a signature check would answer a question nobody here is asking. No token-handling library is
pulled in for it.

Refused cells carry the error code verbatim, because the code is the only thing that separates *"this
app was not granted that"* from *"that resource does not exist in this tenant"* — both of which look
identical as a failed token request.

Timings say `cached` when the credential answered from its own in-memory cache rather than asking the
issuer, so a cache hit is not misread as a very fast network round trip.

Delegated sign-in is a device code flow. The code, the sign-in URL and the configured
`DelegatedUserHint` are all printed before the prompt; signing in with an administrator account
instead of the intended reader silently invalidates the comparison, so the account to use is on
screen. Sign-in happens once, against Graph, and the other audiences are then requested silently, so
an unconsented audience comes back as a refusal instead of parking the run on a second prompt.

### `access`

Reads one file's permission list twice — app-only and delegated — **in a single execution**, so that
both halves describe the same moment. Each leg walks the same three calls:

```
GET /v1.0/sites/{host}:{server-relative-path}          -> site ID
GET /v1.0/sites/{site-id}/drive/root:/{file-path}      -> item ID
GET /v1.0/sites/{site-id}/drive/items/{item-id}/permissions
```

Each path lookup is resolved to an ID before the next URL is built. Graph's path addressing uses a
single colon segment, and a URL that chains two of them is rejected with a `400`.

Per mode the report records the HTTP status of each call, the number of permission entries, the
kinds of principal that appeared in them (`user`, `group`, `siteGroup`, `application`, `link:…`), and
the elapsed milliseconds. The full list of calls — URL, status, timing, Graph error code — is
printed as its own table.

With a delegated user who is only a *visitor* on the site, both legs resolve the site and the file.
The difference shows up in the last call, and it does not show up as a refusal:

```
| mode      | site   | item   | permissions | entries | principal kinds                            |
| app-only  | 200 OK | 200 OK | 200 OK      | 4       | sharePointGroup, siteGroup, siteUser, user |
| delegated | 200 OK | 200 OK | 200 OK      | 0       | -                                          |
```

**Graph does not refuse the delegated caller. It answers `200 OK` with an empty collection.** The
permission entries are filtered to what the caller may see, and a caller who may see none is told
"success, nothing here" — for the same item, at the same moment, that the app-only leg sees four
entries for.

That is worth more than a `403` would have been, because it is the harder mistake to catch: nothing in
the status code separates *"this file is shared with nobody"* from *"this file's sharing is not yours
to see"*. Code that reads the delegated answer alone and concludes the file is unshared gets the
opposite of the truth. Running both legs together, in one execution, is what makes the gap visible.

The delegated token's elapsed time includes the wait for a person to complete the device code sign-in,
and the report says so rather than presenting a minute and a half as service latency.

## Reading the output

Every row of the report carries three things:

- **claim** — what was asserted before the run, including claims of refusal
- **observed** — what came back
- **verdict** — `Ok`, `Failed`, or `NotRun`

`Ok` means the observation matched the claim. For a claim of refusal, `Ok` is a `403`.

`NotRun` exists so that *"we never got far enough to look"* has a value of its own: if the site never
resolved, the permission read did not quietly pass — it did not happen. A blank cell reads as a pass;
`NotRun` cannot.

Exit codes: `0` every claim held, `1` a claim was contradicted, `2` something never ran, `64` bad
usage, `78` incomplete configuration, `130` cancelled.

## Layout

```
src/CapabilityProbe.Cli/
  Program.cs          subcommand dispatch
  appsettings.json    key names, empty values
  Configuration/      ProbeOptions, ProbeOptionsLoader
  Auth/               ProbeMode, ProbeAudience, ScopeResolver, ITokenSource,
                      AppOnlyTokenSource, DelegatedTokenSource, AuthErrorCode, TokenClaims
  Http/               ProbeHttpClient — returns status and body, never throws on a response
  Probes/             AuthProbe, AccessProbe
  Reporting/          Verdict, Observation, ProbeReport, ConsoleReportWriter, JsonReportWriter
```

## Secrets

Nothing secret is tracked. `appsettings.local.json`, `reports/` and `*.pfx` are git-ignored, tokens
are held in memory only, and the recorded request headers show the bearer token's length rather than
its value.

## License

MIT — see [LICENSE](LICENSE).
