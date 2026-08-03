# Findings

What running this probe against a real tenant turned up, and why each result mattered enough to change
the tool.

**These are observations, not documentation.** They come from one Microsoft 365 tenant, one app
registration, one site and one file, on 2026-08-03. Every one of them contradicted a reasonable
prediction made from the app's API permissions screen, which is the whole reason they are written down
— but a single tenant is a single tenant. Re-run the probe against your own before relying on any of
this. Tenant, site and account names below are placeholders.

Throughout, a distinction is worth holding onto: **what was measured** and **what explains it** are
separate. The measurements are reproducible. The explanations are the reading that best fits them, and
where a mechanism was not verified, it says so.

## The setup that produced them

One app registration, with admin consent granted for exactly this:

| API | Permission | Type |
| --- | --- | --- |
| Microsoft Graph | `Sites.Read.All` | Application |
| Microsoft Graph | `Sites.Read.All` | Delegated |
| Microsoft Graph | `User.Read` | Delegated |
| SharePoint | `Sites.Read.All` | Application |

Nothing else. In particular: **no SharePoint delegated permission, and nothing at all for Azure Rights
Management** — those two gaps are what findings 1 and 2 are about.

*Allow public client flows* is enabled, for the device code leg. The person signing in for that leg is
a **visitor** on the test site and holds no administrative role. The file is a single Word document
sitting at the root of the site's default document library.

Both subcommands were run twice: once to observe, once to confirm after the tool was corrected.

---

## Finding 1 — Consent granted to Microsoft Graph reaches SharePoint

### Predicted

The app has no SharePoint *delegated* permission. A delegated token request for the SharePoint resource
should therefore be refused, the same way the Azure RMS one is.

### Observed

It succeeds, and the token is real:

| | value |
| --- | --- |
| `aud` | `00000003-0000-0ff1-ce00-000000000000` |
| `scp` | `Sites.Read.All User.Read` |

`00000003-0000-0ff1-ce00-000000000000` is the first-party application ID of SharePoint Online, so this
is a genuine SharePoint-audience token and not the Graph token handed back by mistake. It took a
network round trip and carries its own expiry, independent of the Graph token acquired moments earlier.

The `scp` value is the part worth staring at. `Sites.Read.All User.Read` is an **exact mirror of the
app's Microsoft Graph delegated grants** — both of them, in the same order, and nothing else.

For contrast, in the same run, on the same credential:

| audience | mode | result |
| --- | --- | --- |
| SharePoint | delegated | token, `scp: Sites.Read.All User.Read` |
| Azure RMS | delegated | refused, `AADSTS65001` |

Azure RMS has no Graph counterpart consented, and it is refused. SharePoint does, and it is not.

### What this means

Consenting to Microsoft Graph's delegated `Sites.Read.All` produced delegated access to the SharePoint
resource as well. **Nothing on the API permissions screen says so.** Reading that screen and concluding
"this app cannot act against SharePoint on a user's behalf" is wrong, and no amount of further reading
of that screen would reveal it. It only surfaces by requesting a token and looking inside.

### Not verified

- **The mechanism.** Pre-authorization of Graph on the SharePoint resource, scope matching by name
  across first-party resources, and a tenant-wide grant created as a side effect of admin consent
  would all produce this. Which one is at work here was not determined, and the probe does not need to
  know in order to report the outcome.
- **Whether the token works.** The `scp` claim says `Sites.Read.All`; nothing here calls SharePoint
  REST with the token to confirm the resource honours it. Actually issuing that call is the obvious
  next thing to measure, and is deliberately outside this tool's scope.
- **The application direction.** The app has SharePoint's own `Sites.Read.All` granted explicitly, so
  this run cannot say whether Graph's *application* permission would flow through the same way. It
  would take an app registration without the SharePoint application grant to find out.

### Encoded as

`AuthProbe.ExpectsPermission` expects a permission for `(SharePoint, Delegated)`. Removing the Graph
delegated grant should flip that cell to `[!]`, which is the regression the expectation is kept for.

---

## Finding 2 — Client credentials issues tokens that carry nothing

### Predicted

No Azure RMS permission is granted in either direction, so both legs should be refused.

### Observed

The two legs disagree:

| mode | result |
| --- | --- |
| delegated | refused, `AADSTS65001` — *"The user or administrator has not consented to use the application"* |
| app-only | **token issued**, `aud: https://aadrm.com`, no `roles`, no `scp` |

A valid token, for the right audience, carrying no permission of any kind.

### What this means

`.default` means something different to each flow, and zero is where they part company:

| flow | `.default` means | with zero granted |
| --- | --- | --- |
| delegated | every scope already consented for this resource | error — `AADSTS65001` |
| client credentials | every app role assigned for this resource | a token with no `roles` |

So for client credentials, a token request succeeding says only that **the resource's service principal
exists in the tenant**. It says nothing about whether the app may do anything with it. Azure RMS is
provisioned alongside Microsoft 365, so its service principal is present, and the request succeeds.

This is the trap the whole tool exists to avoid walking into. A capability probe that reports "token
issued" as a success reports this app as reaching Azure RMS. It reaches nothing there: every call made
with that token will be refused by the resource.

### Not verified

That an actual Azure RMS API call with this token is refused. It follows from an empty `roles` claim,
but it was not measured — the tool acquires tokens for this audience and does not use them.

### Encoded as

`auth` no longer judges on token issuance. It reads the `roles` and `scp` claims out of each issued
token and judges on whether **anything was granted**. With that change, this cell reports what it
should have all along: `token, but nothing granted`, and the expectation of no usable permission holds.

The claims are **read, not verified**. This tool is not the audience of any of these tokens and makes
no trust decision based on one, so checking a signature would answer a question nobody is asking. No
token-handling library is pulled in for it.

---

## Finding 3 — A permission list you may not see comes back as an empty success

### Predicted

The signed-in person is a visitor. Reading an item's permission list is not a visitor's business, so
the delegated leg should be refused with `403`.

### Observed

Not refused. Same file, same moment, one execution:

| mode | site | item | permissions | entries | principal kinds |
| --- | --- | --- | --- | --- | --- |
| app-only | `200 OK` | `200 OK` | `200 OK` | **4** | `sharePointGroup, siteGroup, siteUser, user` |
| delegated | `200 OK` | `200 OK` | `200 OK` | **0** | — |

All six calls succeeded. Graph answers the delegated caller `200 OK` with an empty collection: the
permission entries are filtered to what that caller may see, and a caller who may see none is told
*"success, nothing here."*

### What this means

**The status code cannot tell these two situations apart:**

- this file is shared with nobody
- this file's sharing is not yours to see

Both are `200 OK` with `"value": []`. Code that reads the delegated answer on its own and concludes the
file is unshared gets the exact opposite of the truth — here, four principals have access.

This is worse than a `403` would have been. A refusal is loud, and an unhandled refusal usually stops
the caller. An empty success is quiet, it flows straight into whatever comes next, and it looks like
information.

It is also the same hazard the tool guards against internally with `Verdict.NotRun` — *"we never got
far enough to look"* must not be storable as a blank that reads like a pass — except here it is Graph's
own response shape doing the conflating, one layer further out.

Two things make it visible at all. Both legs run in **one execution**, so the two answers describe the
same item at the same moment and can be set against each other; had they been separate runs, the
difference could always be explained away as something having changed in between. And the entry **count
is recorded separately from the status**, so `200 OK / 4` and `200 OK / 0` do not collapse into one
another.

### Not verified

Whether a delegated caller with more site permission — a member or owner rather than a visitor — sees a
non-empty list. That would confirm filtering is by the caller's rights rather than something else about
the request, and it only takes running `access` again with a different sign-in.

### Encoded as

The delegated claim is about what is revealed, not about the HTTP status: *"the permission list does not
reveal the file's permission entries."* A `403` and a `200` with zero entries both satisfy it. When the
two legs return the same status with different contents, the report says so in the observation rather
than leaving a reader to spot it in the numbers.

---

## The thread running through all three

Every one of these is the same mistake in a different costume: **treating the absence of an error as
evidence of capability.**

| what looks like success | what it actually was |
| --- | --- |
| a token was issued for Azure RMS | a token carrying no permission at all |
| no SharePoint delegated permission is listed | a delegated SharePoint token with `Sites.Read.All` in it |
| the permission list returned `200 OK` | an empty list, because the caller may see none of it |

The permissions screen is a statement of intent. The token is a statement of what was granted. The
response body is a statement of what this caller may see. They are three different things, and the run
recorded here is one where all three disagreed.

## What this investigation did not establish

Collected in one place, since a finding's edges matter as much as its middle:

- Whether any of the tokens obtained actually work against their resources. Nothing here calls
  SharePoint REST or Azure RMS.
- The mechanism behind finding 1.
- Whether Graph *application* permissions flow through to SharePoint the way the delegated ones do.
- What a delegated caller with more than visitor rights sees in the permission list.
- Whether any of this holds in another tenant, in another cloud, or with a differently configured app
  registration.

## Reproducing

```bash
dotnet run --project src/CapabilityProbe.Cli -- auth
dotnet run --project src/CapabilityProbe.Cli -- access
```

Configuration and the app registration setup are in the [README](../README.md). Both subcommands write
a JSON report under `reports/`, timestamped, containing every URL called, the headers sent, the status
returned and the verdict reached — which is what makes a run from months ago still worth something.

Sign in as the intended non-administrative account when the device code prompt appears. Signing in as
an administrator quietly turns finding 3 into a different observation, and the tool will tell you which
account it got but will not stop you.
