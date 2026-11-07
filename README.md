# SSL Certificate Expiry Check

A GitHub Action that warns, or fails your workflow, before an SSL/TLS certificate expires.
No API key, no account, nothing to install. It uses `openssl` on the runner.

It also catches what most checkers miss: **the certificate on your origin server behind Cloudflare**.
Public checkers only see Cloudflare's edge certificate, which Cloudflare renews for you. The origin
cert can expire quietly until visitors get [Error 526](https://domaincat.app/cloudflare-error-526.html).

## Usage

Run it every day on a schedule:

```yaml
name: ssl-check
on:
  schedule:
    - cron: '0 13 * * *'   # every day, 13:00 UTC
  workflow_dispatch:

jobs:
  ssl:
    runs-on: ubuntu-latest
    steps:
      - uses: 740ft/ssl-expiry-check@v1
        with:
          domains: |
            example.com
            www.example.com
            api.example.com:8443
            example.com@203.0.113.10
          warn-days: 21
          fail-days: 7
```

A failed run sends you GitHub's normal failure email, so a scheduled workflow works as a free
expiry alert. Results show up as a table in the run summary.

## What each entry means

| Entry | Checks |
|---|---|
| `example.com` | The certificate visitors get on port 443 |
| `example.com:8443` | Same, on another port |
| `example.com@203.0.113.10` | The certificate on that server (your origin), asking for `example.com`. Use this behind Cloudflare or another CDN |
| `example.com@203.0.113.10:8443` | Origin on another port |

## What fails the check

- The certificate expires within `fail-days` (warning within `warn-days`)
- Already expired
- The hostname isn't in the certificate
- Not trusted (self-signed, missing intermediate, unknown CA). A **Cloudflare Origin CA** certificate on an origin counts as trusted, because Cloudflare trusts it
- No TLS on that port, or the handshake fails (what Cloudflare reports as [Error 525](https://domaincat.app/cloudflare-error-525.html))

## Inputs

| Input | Default | |
|---|---|---|
| `domains` | (required) | Space, comma or newline separated |
| `warn-days` | `21` | Warn when this close to expiry |
| `fail-days` | `7` | Fail when this close to expiry |
| `fail-on-error` | `true` | `false` reports without failing the step |
| `timeout` | `15` | Seconds per connection |

## Outputs

`failed`, `warned`, `soonest-days`, for use in later steps (Slack message, issue, and so on).

## Runners

Linux runners (`ubuntu-*`). It needs bash, GNU `date` and `openssl`, which those images include.

## Want alerts without a workflow?

[DomainCat](https://domaincat.app/?utm_source=github&utm_medium=readme&utm_campaign=ssl-expiry-check) checks your
certificates on a schedule, including the origin cert behind Cloudflare, and emails you 30, 14 and 7 days before
expiry. Free for up to 5 domains. Paid plans add domain registration expiry, blacklist and DNS change alerts.

## License

MIT
