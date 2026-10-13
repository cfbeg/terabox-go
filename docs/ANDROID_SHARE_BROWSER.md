# Generated public-share browser context

`PrepareAndroidGeneratedShareLinkAttribution` prepares the public share-page
click inputs for a Go-generated installation. It returns `Input`, `Generated`,
`Click`, and a `ProviderSHA256`. The click and generated referrer have the same
link ID, final page URL, deeplink, agency and optional `op_source`.

```go
input, err := client.ResolveAndroidShareLinkReferrerInput(ctx, shareURL)
if err != nil { return err }
prepared, err := client.PrepareAndroidGeneratedShareLinkAttribution(ctx, input,
    terabox.AndroidShareBrowserOptions{
        UserAgent: browserUA, // Ordinary Android Chrome Mobile UA.
        Language: "en-US",   // navigator.language, separate from page language.
    })
if err != nil { return err }
capture.Click = prepared.Click
capture.InstallReferrer = &prepared.Generated.InstallReferrer
capture.Provenance = terabox.AndroidAttributionProvenanceShareLinkGenerated
// Save the complete installation/session before sending any attribution report.
```

The function makes only GET requests. Each call has its own initially empty
browser cookie jar. It never reads native account cookies, a saved Chrome
profile, or the Hy registration page's token. The browser UA and locale are
explicit generated inputs; an actual Chrome process or Play callback is not
claimed. A new direct browser navigation has an empty `document.referrer`.

The live page supplies its executable `window.jsToken` bootstrap, SSR state,
and referenced main bundle. Go's pinned `goja` runtime evaluates the token
bootstrap and invokes the bundle's actual pure `4471`, `d0fc`, `51cd`, `4583`
and `7404` modules for `dp-logid`. No token fragment or random string is used
as a fallback. The application entry, UI, native bridges and analytics do not
execute. The SSR script's removal of its own script element is supported as
the observed bootstrap cleanup operation.

The SSR share ID, owner UK, normalized surl, creation time, expiry type, file
count and encoded access key must agree with the prepared native deeplink.
Unsupported redirects, missing metadata, unknown provider dependencies, absent
or wrongly typed tokens, unsupported browser inputs and execution deadlines
return errors containing only abstract reasons. An error does not produce a
partially usable click or a fake successful report.

For ordinary browser requests the click query uses `clienttype=5`,
`devuid=cuid=version=0`, the share document's interceptor language, and the
freshly evaluated token/provider. The form retains `navigator.language` and
the exact Android device/OS extraction used by module `1f03`. Cookies are
selected for the `/api/srn/ck` path; HttpOnly cookies remain in the HTTP
request while being excluded from the JS-visible cookie string.

HTTPS page redirects are restricted to TeraBox hosts. Referenced main assets
may additionally use TeraBox CDN hosts. The provider uses at most 8 redirects,
4 MiB per response, 512 KiB per inline bootstrap, 8 MiB total executable
source, 16 selected inline scripts, and 2 seconds per JS evaluation within a
45-second operation deadline. Request timeouts and earlier caller deadlines
remain effective. Cookie input sizes are bounded.

After saving the generated capture, use `ReportAndroidShareClick` before the
install/referrer reports. Its existing attempt/success state prevents implicit
resending of an uncertain or successful click after session restoration. This
preparation result alone is not a `/ck` response and does not establish
Webmaster acquisition/rewards.

Tests use the exact pure provider modules extracted from the public share main
bundle (source SHA256
`d5940789b440515e21452c0ebf1bbca5a05dc35a9cb30e7c0a7dd951aee1cfea`),
with sanitized SSR/token/cookie inputs. They cover dynamic encoded token
bootstrap, SSR script cleanup, HttpOnly visibility, cookie path selection,
fresh contexts for separate registrations, redirect share identity, matching
click/referrer values, missing providers, unsupported input fallback rejection,
and bounded execution. A read-only live Go check on 2026-10-13 successfully
evaluated the actual page token/provider and verified the same shared context;
it sent no `/ck` and created no account.
