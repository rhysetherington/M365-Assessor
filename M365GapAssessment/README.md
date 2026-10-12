# M365GapAssessment

Read-only Microsoft 365 security gap assessment for PowerShell 7+. Collects Entra ID, Defender/Intune and Secure Score
data through Microsoft Graph, maps every check to **SCF** and **NIST CSF 2.0** (plus **CIS Microsoft 365 Foundations v7.0.0** where a check clearly matches a recommendation), and exports JSON, Markdown and an
executive HTML report. Built for a reviewer signed in as **Global Reader** and for repeatable multi-tenant (MSP) use.

The module never writes to a tenant: every call is an HTTP `GET`.

## 1. Install prerequisites

```powershell
# PowerShell 7.2+ required
Install-Module Microsoft.Graph -Scope CurrentUser          # full SDK (includes Microsoft.Graph.Authentication)
# or just the part this module needs:
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

`Microsoft.Graph.Beta` is optional: beta endpoints (Intune managed devices) are called through `Invoke-MgGraphRequest`.

## 2. Import

```powershell
Import-Module ./M365GapAssessment/M365GapAssessment.psd1 -Force
```

## 3. Run

```powershell
# Interactive sign-in, JSON + Markdown + HTML into ./M365Assessment/<tenantId>_<timestamp>/
Invoke-M365SecurityReview -TenantId contoso.onmicrosoft.com -Format JSON,Markdown,HTML

# Device code (headless / jump host). Blocked in tenants with Security Defaults enabled, and in new tenants from July 2026:
# use interactive sign-in or a certificate there.
Invoke-M365SecurityReview -TenantId contoso.onmicrosoft.com -UseDeviceAuthentication

# App-only with certificate (unattended)
Invoke-M365SecurityReview -TenantId <guid> -ClientId <appId> -CertificateThumbprint <thumb>

# App-only with client secret (Credential username = client ID, password = secret)
Invoke-M365SecurityReview -TenantId <guid> -Credential (Get-Credential)

# Subset of domains and custom thresholds
Invoke-M365SecurityReview -Domain EntraID,SecureScore -StaleDays 60 -TargetScorePercent 80
```

### Multi-tenant, repeatable runs

```powershell
$tenants = 'client1.onmicrosoft.com', 'client2.onmicrosoft.com', 'client3.onmicrosoft.com'
$results = Invoke-M365SecurityReview -TenantId $tenants -ExportPath ~/Assessments -Format JSON,HTML
$results | Select-Object TenantName, Score, @{n='Critical';e={$_.Summary.GapsBySeverity.Critical}}
```

Switching tenants disconnects the previous Graph session first. Each run writes to its own
`<tenantId>_<yyyyMMdd-HHmm>` folder, so re-running monthly gives a history you can diff
(`AssessmentFindings.json` is stable and ingestible).

## Permissions

Delegated scopes requested (all read-only): `User.Read`, `User.Read.All`, `Directory.Read.All`, `Policy.Read.All`,
`SecurityEvents.Read.All`, `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `AuditLog.Read.All`,
`UserAuthenticationMethod.Read.All`, `Reports.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`,
`Group.Read.All`, `DeviceManagementManagedDevices.Read.All`.

Also requested for the policy checks: `RoleManagementPolicy.Read.Directory`, `IdentityRiskyUser.Read.All`,
`AccessReview.Read.All`, `EntitlementManagement.Read.All`, `Agreement.Read.All`, `SharePointTenantSettings.Read.All`.

### Admin consent (first run in each tenant)

Global Reader **cannot** grant consent. The first time the "Microsoft Graph Command Line Tools" app requests these
scopes in a tenant, a Global Administrator (or Privileged Role / Cloud Application Administrator) must approve them once,
either by signing in with that account and ticking *Consent on behalf of your organization*, or via the admin consent URL
(`https://login.microsoftonline.com/<tenant>/v2.0/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e&scope=...`).
Until then a Global Reader sees "Need admin approval". After consent, the Global Reader account signs in normally.

`Connect-M365Assessment` verifies the account holds Global Reader (or Global Administrator / Security Reader /
Security Administrator); a PIM-eligible role must be activated first. Sign-in uses the `organizations` authority, so
personal Microsoft accounts are rejected. For app-only use, grant the equivalent **application** permissions to your app registration.

### Global Administrator confirmation

Global Reader is enough for every check, and a Global Administrator token is a far more valuable thing to expose, so the tool does not
let that account be used by accident or by a script nobody chose to run that way:

- **Interactive session:** if the signed-in account holds Global Administrator (including an account that also holds Global Reader), the
  tool warns and asks `Continue as Global Administrator? [y/N]`. Enter, `n` or anything other than `y` / `yes` stops the run, disconnects,
  and assesses nothing.
- **Session that cannot ask** (`pwsh -NonInteractive`, redirected or piped input, a scheduled job): the run stops with an error before
  anything is assessed, and never waits for an answer. This is what halts an automated run that was coded to use a Global Administrator.
- **On purpose:** pass `-AllowGlobalAdministrator` (on `Invoke-M365SecurityReview` or `Connect-M365Assessment`) to run as Global Administrator
  without being asked. A warning is still printed so it is visible in logs.

What it does not cover, so you are not surprised:

- It applies to delegated (user) sign-ins. App-only sessions (certificate or client secret) have no directory role to check; give the app
  registration only the read-only application permissions.
- `-SkipRoleCheck` still waives the requirement to hold a read role, but it does **not** skip this confirmation. If the roles cannot be read at
  all, the tool warns that it could not check.
- Only roles the account holds now are seen. A Global Administrator role that is eligible in PIM but not activated is not detected.
- A confirmation is remembered for the same account and tenant while one sign-in is reused, a fresh sign-in asks again, and a refusal is
  never remembered.

## Coverage

For the full list of checks by administration console, and what is **not** covered yet, see [`Docs/Coverage.md`](../Docs/Coverage.md).

| `-Domain` | Checks |
|---|---|
| `Licensing` | Reads `subscribedSkus`; flags a tenant with no Entra ID P1/P2. Also explains NotAssessed results caused by a missing licence. |
| `ExchangeOnline` | **Opt-in** (`-Domain ...,ExchangeOnline`). Forwarding, mailbox audit, modern auth, SMTP AUTH, shared mailbox sign-in, anti-phish, Safe Links. Needs `Install-Module ExchangeOnlineManagement` and a second interactive sign-in (Get-* cmdlets only); reported NotAssessed if the module is absent. |
| `DefenderO365` | **Opt-in** (`-Domain ...,DefenderO365`). Safe Attachments (mail, SharePoint, OneDrive, Teams), Safe Links click-through and tracking, anti-malware, anti-spam allow lists and thresholds, outbound spam alerts, preset security policies, mail flow rules that bypass filtering or redirect mail, connection filter lists, external sender tag, Teams zero-hour auto purge, user reporting. Shares the Exchange Online sign-in with the `ExchangeOnline` domain. |
| `Purview` | **Opt-in** (`-Domain ...,Purview`). Unified audit log, DLP policies and workload coverage, sensitivity labels, retention, insider risk. Uses `Connect-IPPSSession` (its own sign-in); needs `Install-Module ExchangeOnlineManagement`. |
| `Teams` | **Opt-in** (`-Domain ...,Teams`). External federation, unmanaged/trial tenant access, anonymous join and lobby, meeting chat, presenter and recording controls, third-party storage, email into channels, user security reporting. Needs `Install-Module MicrosoftTeams` and a separate interactive sign-in (Get-* cmdlets only). |
| `SharePoint` | Tenant external sharing level, guest resharing, domain restrictions, legacy auth, unmanaged-device sync (Graph `/admin/sharepoint/settings`; needs the `SharePointTenantSettings.Read.All` scope, which prompts for consent on the next sign-in). |
| `EntraID` | Conditional Access baseline, PIM permanence, MFA registration, stale accounts, app credentials and application permissions, guests in privileged groups |
| `EntraPolicy` | Baseline sign-in protection (Security Defaults or all-user MFA), SSPR, smart lockout, password expiry, public Microsoft 365 groups, emergency-access accounts (nominated from Conditional Access exclusions; confirm manually), user/admin consent, app and tenant creation, guest settings, delegated tenant-wide grants, authentication methods, password protection, CA depth (device, guest MFA, risk, locations), Global Admin PIM settings, cross-tenant access, stale guests, directory sync, risky users, access reviews, Terms of use |
| `Defender` | High alerts, active incidents, device compliance and encryption |
| `SecureScore` | Score vs target, unimplemented controls |
| `EmailDns` | SPF, DMARC, DKIM for verified custom domains |

### Email DNS lookups

`Resolve-DnsName` is Windows-only. On macOS/Linux the module queries **DNS-over-HTTPS** (default
`https://cloudflare-dns.com/dns-query`), which sends your verified domain names to that resolver. They are public DNS
names, but use `-DohEndpoint` to choose another resolver or `-Domain` without `EmailDns` to skip the check.

## Output

| File | Contents |
|---|---|
| `AssessmentFindings.json` | Full raw findings (always written) |
| `M365_Security_Gap_Assessment.md` | Executive summary, NIST CSF 2.0 / SCF matrix, per-domain findings with remediation steps |
| `M365_Security_Gap_Assessment.html` | Client-ready styled version (`-Format HTML`) |
| `evidence/<FindingId>.csv`, `evidence/_index.csv` | With `-IncludeEvidence`: the full list of affected items for each Gap (the reports show the first 25), linked from the reports. Names that start with `=`, `+`, `-` or `@` get a leading apostrophe so a spreadsheet cannot run them as formulas. No tenant ID is written. |

Optional report additions (also available on `Export-M365GapReport` and `Convert-M365Report`):

- `-IncludeEvidence`: write the evidence files above (the evidence folder gets the same 700/600 permissions as the reports on macOS and Linux).
- `-CisView`: add a section that regroups findings by CIS Microsoft 365 Foundations recommendation number and benchmark section.
  Only CIS-mapped checks appear, so it is **not** a score against the whole benchmark; recommendation numbers follow the control
  mapping, so check them against the benchmark version a client uses.

To see how much of the whole benchmark the tool covers, export the recommendation list from your licensed CIS download to a CSV
(`Recommendation`, `Title`, optionally `Level` and `Section`) and run `pwsh ./Docs/Get-CisCoverage.ps1 -BenchmarkCsv <file>`. It writes a
Covered / Partial / Missing report to `Assessments/CIS-coverage.md`. The CSV and the report hold CIS content, so both are git-ignored.

Each check ends as **Gap**, **Pass** or **NotAssessed**. NotAssessed means Graph refused the call (missing licence such
as Entra ID P2 for PIM, Intune or Defender, or missing consent) and is reported separately rather than counted as a pass.

### Which account each service used (Assessment sessions)

Microsoft Graph, Exchange Online, Security & Compliance (Purview) and Teams are separate sign-ins, and some silently reuse a
cached login. So the tool asks each service which account it signed in as and lists them in the reports ("Assessment sessions")
and in the `Sessions` property of the result and the JSON:

| Service | Signed in as | Matches Graph |
|---|---|---|
| Microsoft Graph | `reader@contoso.com` | Yes |
| Microsoft Teams | `admin@contoso.com` | **No** |

`Matches Graph` is `Yes`, `No`, `Unknown` (the service did not say who signed in) or `n/a` (Graph used an app registration, so there is no
user to compare). The run prints a warning, and the report adds a note, when any service used a different account or its
account could not be determined, because results from different accounts can reflect different permissions. This is what
lets a read-only assessment show that every service really used the read-only account.

## Sovereign clouds (GCC High, DoD, China)

`-Environment` selects the Microsoft cloud for the whole run. Microsoft Graph, Exchange Online, Security & Compliance (Purview)
and Teams are all sent to the **same** cloud, and the run stops if the Graph session lands in a different cloud than requested.
GCC (Moderate) tenants use the commercial endpoints: use `Global`.

| `-Environment` | Cloud | Graph | Exchange / Purview | Teams | Live-tested |
|---|---|---|---|---|---|
| `Global` | Microsoft 365 commercial, GCC | yes | `O365Default` | yes | **yes** |
| `USGov` | US Government GCC High | wired | `O365USGovGCCHigh` | `TeamsGCCH` | **no** |
| `USGovDoD` | US Government DoD | wired | `O365USGovDoD` | `TeamsDOD` | **no** |
| `China` | Operated by 21Vianet | wired | `O365China` | not supported (Teams checks report NotAssessed) | **no** |

Be clear about what this means: only `Global` has been run against a real tenant. The other clouds are wired to Microsoft's
documented parameters and covered by offline tests of the wiring, but they have **not been tested live**, and the tool warns when
you select one. Some Graph endpoints this tool uses (including beta endpoints and the SharePoint tenant settings) may not be
offered in every sovereign cloud; those checks come back as NotAssessed, not as a wrong answer. Please review results before
relying on them, and report what you find. The retired Microsoft Cloud Germany is rejected. The DNS checks use public
DNS-over-HTTPS (Cloudflare by default) on macOS and Linux, which a government network may block: use `-DohEndpoint` to choose an
allowed resolver, or `-Domain` without `EmailDns` to skip them.

```powershell
Invoke-M365SecurityReview -Environment USGov -TenantId contoso.us -Domain Licensing,EntraID,EntraPolicy
```

## Extending

### Add a check

1. **Add a mapping entry** to `Data/ControlMapping.json`, in id order (the tests enforce order and numbering):
   `id` (like `ENT-CA-010`), `domain`, `name` (phrased as the problem), `severity` (Critical, High, Medium, Low),
   `scf`, `nistCsf` and at least two `remediation` steps. Optional: `cis` (CIS recommendation numbers, only where the check clearly tests
   the same setting), `cisPartial` (numbers the check tests only in part; reported as Partial by the coverage generator) and `license` (`EntraP1`, `EntraP2`, `Intune`, `DefenderO365` or `DefenderEndpoint`: a refused call is then reported with the
   missing licence). Ids are never reused: a reserved but unused number goes in `retiredIds`.
2. **Emit it from a collector** inside `Invoke-Collector` so a refused call, a missing licence or an absent cmdlet becomes a NotAssessed
   finding with a reason instead of aborting the run:
   `New-Finding -Id <id> -Status Gap|Pass|NotAssessed -AffectedObjects ... -Detail ...`. Unknown or unreadable data must be
   NotAssessed, never Pass. Use only `GET` calls and `Get-*` cmdlets.
3. **Test it** with the offline fakes (below), including the Pass, Gap and unreadable cases.
4. **Regenerate the coverage document**: `pwsh ./Docs/Update-Coverage.ps1`.

### Add a domain

A domain is a collector function plus its wiring: add the value to `-Domain` on `Invoke-M365SecurityReview` (the `ValidateSet` and a
`switch` case that calls your collector), a row in the Coverage table above, and a console rule in `Docs/Update-Coverage.ps1`. Domains that need the
Exchange or Security & Compliance PowerShell sessions use `Start-ExchangeSession` / `Start-ComplianceSession` (one sign-in per tenant,
shared between domains, closed by the review cmdlet), keep the check logic in a separate function so tests can drive it without a connection,
and are opt-in. Report builders (`New-AssessmentMarkdown`, `New-AssessmentHtml`) and other helpers belong in `Private/`: `Public/` holds only the
exported cmdlets, one per file.

### Test it

```powershell
Invoke-Pester ./Tests          # offline: no tenant, no sign-in, about a minute
pwsh ./Docs/Update-Coverage.ps1   # after changing the mapping or a domain
```

`Tests/Support/FakeGraph.ps1` replaces the Graph request functions with a fixture-driven fake, and `Tests/Support/FakeCmdlets.ps1` defines fake
Exchange, compliance and Teams cmdlets. The suite checks mapping integrity (formats, sorted ids, no unexplained numbering gaps), the module layout,
that every domain is wired, and that `Docs/Coverage.md` matches what the generator produces. When you add a test, break the code once and
confirm the test fails: a test that cannot fail proves nothing. Variables set in Pester's `BeforeDiscovery` are not visible inside `It` blocks.

## Notes and limits

- Mappings to SCF/NIST are best-fit; validate against the SCF release your client uses.
- Emergency-access detection (`ENT-CA-009`) only **nominates** candidates: permanent Global Administrators that an enabled Conditional Access
  policy excludes. It ignores the UPN domain (clients differ on `.onmicrosoft.com` versus custom domains), so a person must confirm that
  the accounts really are break-glass accounts. `ENT-CA-002` is a separate heuristic (all-user policies with no exclusions).
- **Global Reader:** the checks were run as Global Reader across Graph, Exchange Online, Defender for Office 365, Purview and Teams, and
  returned the same results as Global Administrator, with two exceptions that report NotAssessed rather than a wrong answer: `PUR-006`
  (the Insider Risk cmdlet is not offered to Global Reader) and `DFO-014` (the user-reporting policy returned no object). Both messages say so.
- Stale-account detection needs Entra ID P1 (`signInActivity`); MFA registration report needs `Reports.Read.All`.
- Alerts/incidents are capped by `Get-DefenderGaps -MaxItems` (default 2000) to bound runtime on very large tenants.

## Accepted risks and run-to-run diff

```powershell
# Known gaps covered by an accepted-risk file are reported as Status 'Accepted' (counted as passed in the score)
Invoke-M365SecurityReview -TenantId <guid> -AcceptedRiskPath ./client1-accepted.json
```

```json
{ "risks": [ { "findingId": "ENT-USR-001", "affected": ["breakglass1@contoso.com"], "reason": "Break-glass account",
               "approvedBy": "J. Smith", "expires": "2027-01-31" } ] }
```

`affected` (prefix match, case-insensitive) and `expires` are optional. With no `affected` list the whole finding is accepted;
with a list, every affected object must be covered, so a new object re-opens the gap. Expired entries stop applying.

```powershell
Compare-M365Assessment -Baseline .\Assessments\<old>\<old>-Findings.json -Current .\Assessments\<new>\<new>-Findings.json
```

Classifies each finding as New, Resolved, Changed (severity or affected objects differ), Unchanged, **Accepted** (now covered by an accepted-risk entry, not a fix) or **Reopened** (acceptance no longer applies); only `Gap` counts as open.

## Client branding and re-rendering

```powershell
Invoke-M365SecurityReview -TenantId <guid> -Format HTML -ClientName 'Contoso Ltd' -PreparedBy 'Your MSP' -BrandColor '#0f766e' -LogoPath .\logo.png

# Re-render any saved run with the current report design (no sign-in needed; JSON is never modified)
Convert-M365Report -Path .\Assessments\<run>\AssessmentFindings.json -ClientName 'Contoso Ltd' -Format HTML,Markdown
```

`-LogoPath` accepts PNG, JPG or SVG and is embedded in the HTML, so the report stays a single file.

## Security and data handling

- **No stored tenant or credentials.** The tenant is never written into the module or scripts: omit `-TenantId` and you are prompted
  (GUID or domain, validated before use). `-TenantId` values are format-checked, so they cannot inject paths or URLs.
- **Sign-in.** Interactive/device-code sessions use `ContextScope Process`, so tokens are not cached to disk. App-only runs take a
  `[pscredential]` (secret stays a SecureString) or a certificate thumbprint; never put secrets in scripts. Prefer certificates.
- **Read-only.** Graph calls are `GET`; Exchange, Teams and SharePoint use `Get-*` only.
- **Local storage only.** Reports go to `./Assessments` (git-ignored). On macOS/Linux each run folder is created `700` with `600` files;
  on Windows rely on NTFS permissions on the export path. Reports contain tenant IDs, user principal names and security gaps, so treat
  them as confidential client data and delete them per your retention policy.
- **Sharing.** Use `-HideTenantId` (on `Invoke-M365SecurityReview` or `Convert-M365Report`) for client-facing reports: it removes the
  tenant ID from both the HTML and the Markdown (the tenant display name stays). `AssessmentFindings.json` is the raw record and always
  keeps the tenant ID, so share the HTML/Markdown, not the JSON. Run folders are named `Client-Date`, not by tenant ID.
- **HTML safety.** All tenant-supplied text is HTML-encoded, branding colour is validated as `#rrggbb`, and logos load via `<img>` data
  URIs (scripts inside an SVG do not run). Markdown output escapes `<`, `>` and `|`.
- **DNS lookups.** On macOS/Linux, SPF/DKIM/DMARC lookups use DNS-over-HTTPS (default Cloudflare), which sends the client's domain
  names to that provider. Use `-DohEndpoint` to point at your own resolver (https only).
- **Repository hygiene.** `.gitignore` excludes assessments, certificates, keys, logs and accepted-risk files (client-specific).

## Assessment details and file naming

Each run records simple audit artefacts. After sign-in the tool asks (press Enter to accept the default in brackets):

| Prompt | Parameter | Default |
|---|---|---|
| Client name | `-ClientName` | first label of the tenant's primary domain (`contoso.com` -> `contoso`), else the tenant name |
| Assessment name | `-AssessmentName` | Microsoft 365 Security Gap Assessment |
| Assessor (who is performing it) | `-AssessorName` | the signed-in account |
| Assessment date | `-AssessmentDate` | today (`yyyy-MM-dd`) |
| Engagement / reference (optional) | `-Reference` | blank |

Use `-NoPrompt` (or run non-interactively) to accept defaults silently. Answers are stored in the findings JSON under `Metadata`,
shown in the report header, and drive the names: folder `ClientName-YYYY-MM-DD/` containing `ClientName-YYYY-MM-DD-Findings.json`,
`...-Assessment.html` and `...-Assessment.md`. Names are sanitised to letters, digits and dashes, so input cannot add path separators.
A second run for the same client and date gets an `-HHmm` suffix instead of overwriting. `Convert-M365Report` can override any of these.
