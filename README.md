# M365 Assessor

[![CI](https://github.com/rhysetherington/M365-Assessor/actions/workflows/ci.yml/badge.svg)](https://github.com/rhysetherington/M365-Assessor/actions/workflows/ci.yml)

A **read-only** Microsoft 365 security gap assessment you can run against your own tenant. It reads your configuration, compares it with
**136 checks** across Entra ID, Conditional Access, Defender, Exchange Online, Teams, Purview, SharePoint, licensing and email DNS, and
produces a scored report (HTML, Markdown and JSON) with remediation steps. Every check is mapped to SCF, NIST CSF 2.0 and, where it
matches, CIS Microsoft 365 Foundations v7.0.0.

- **Read-only.** Nothing is ever changed in your tenant. Microsoft Graph calls are `GET` requests and the PowerShell domains use `Get-*` cmdlets.
- **Least privilege.** Built for a **Global Reader** account. If you sign in as Global Administrator the tool asks you to confirm, and refuses
  to run unattended that way unless you pass `-AllowGlobalAdministrator`.
- **Honest about what it cannot see.** A setting it cannot read is reported as *NotAssessed* and counted against the score, never as a pass.
- **Tested.** An offline test suite runs in GitHub Actions on Linux, macOS and Windows; no tenant or credentials are involved.

## Try it on your tenant

You need PowerShell 7.2 or later and the Microsoft Graph authentication module:

```powershell
git clone https://github.com/rhysetherington/M365-Assessor.git
cd M365-Assessor
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Import-Module ./M365GapAssessment/M365GapAssessment.psd1
Invoke-M365SecurityReview -TenantId yourtenant.onmicrosoft.com -Format JSON,Markdown,HTML
```

A browser window opens for sign-in. The first time in a tenant, a Global Administrator has to approve the tool's read-only permissions
once. The reports are written to `./M365Assessment/<ClientName>-<date>/` (open the `.html` file). The full guide, including the
permissions it requests, the opt-in Exchange, Defender for Office 365, Purview and Teams domains, and sovereign clouds, is in
[`M365GapAssessment/README.md`](M365GapAssessment/README.md).

## What is checked

[`Docs/Coverage.md`](Docs/Coverage.md) lists every check by the administration console where you would fix it, and what is not covered yet.
Some recommendations cannot be read with a read-only role (for example most SharePoint tenant settings) and are left as manual checks.

## Your data

Reports contain real information about your tenant. `M365Assessment/` and `Assessments/` are in `.gitignore` so they are not committed by
accident, and no tenant ID or credential is stored in the code. Besides the calls to Microsoft's own services, there is one other lookup: on macOS
and Linux the email DNS check sends your verified domain names to a public DNS-over-HTTPS resolver (configurable, or leave out the
`EmailDns` domain).

## Status and limits

Only the global (commercial) Microsoft 365 cloud has been run against a live tenant. GCC High, DoD and China are wired up but untested.
Treat the output as a review aid, not an audit: the checks follow published guidance, some only approximate a recommendation, and
a pass means the setting that was read looks right, not that the tenant is secure.

## Contributing and tests

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser
Invoke-Pester ./Tests          # offline, about ten seconds
```

How to add a check is in the module README (*Extending*). The planning notes are in [`Docs/`](Docs/).

## Licence

[MIT](LICENSE).
