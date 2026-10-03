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

# Device code (headless / jump host)
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

## Coverage

| `-Domain` | Checks |
|---|---|
| `Licensing` | Reads `subscribedSkus`; flags a tenant with no Entra ID P1/P2. Also explains NotAssessed results caused by a missing licence. |
| `ExchangeOnline` | **Opt-in** (`-Domain ...,ExchangeOnline`). Forwarding, mailbox audit, modern auth, SMTP AUTH, shared mailbox sign-in, anti-phish, Safe Links. Needs `Install-Module ExchangeOnlineManagement` and a second interactive sign-in (Get-* cmdlets only); reported NotAssessed if the module is absent. |
| `Teams` | **Opt-in** (`-Domain ...,Teams`). External federation, unmanaged/trial tenant access, anonymous join and lobby, meeting chat, presenter and recording controls, third-party storage, email into channels, user security reporting. Needs `Install-Module MicrosoftTeams` and a separate interactive sign-in (Get-* cmdlets only). |
| `SharePoint` | Tenant external sharing level, guest resharing, domain restrictions, legacy auth, unmanaged-device sync (Graph `/admin/sharepoint/settings`; needs the `SharePointTenantSettings.Read.All` scope, which prompts for consent on the next sign-in). |
| `EntraID` | Conditional Access baseline, PIM permanence, MFA registration, stale accounts, app credentials and application permissions, guests in privileged groups |
| `EntraPolicy` | User/admin consent, app and tenant creation, guest settings, delegated tenant-wide grants, authentication methods, password protection, CA depth (device, guest MFA, risk, locations), Global Admin PIM settings, cross-tenant access, stale guests, directory sync, risky users, access reviews, Terms of use |
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

Each check ends as **Gap**, **Pass** or **NotAssessed**. NotAssessed means Graph refused the call (missing licence such
as Entra ID P2 for PIM, Intune or Defender, or missing consent) and is reported separately rather than counted as a pass.

## Extending

1. Add an entry to `Data/ControlMapping.json` (id, severity, SCF, NIST CSF, remediation).
2. Emit it from a collector with `New-Finding -Id <id> -Status Gap|Pass -AffectedObjects ...` inside `Invoke-Collector`.

## Notes and limits

- Mappings to SCF/NIST are best-fit; validate against the SCF release your client uses.
- Break-glass detection in Conditional Access is a heuristic (all-user policies with no exclusions).
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
Compare-M365Assessment -Baseline .\Assessments\<old>\AssessmentFindings.json -Current .\Assessments\<new>\AssessmentFindings.json
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
- **Sharing.** Use `-HideTenantId` (on `Invoke-M365SecurityReview` or `Convert-M365Report`) for client-facing HTML. Folder names and
  the JSON/Markdown still include the tenant ID because they are for your records.
- **HTML safety.** All tenant-supplied text is HTML-encoded, branding colour is validated as `#rrggbb`, and logos load via `<img>` data
  URIs (scripts inside an SVG do not run). Markdown output escapes `<`, `>` and `|`.
- **DNS lookups.** On macOS/Linux, SPF/DKIM/DMARC lookups use DNS-over-HTTPS (default Cloudflare), which sends the client's domain
  names to that provider. Use `-DohEndpoint` to point at your own resolver (https only).
- **Repository hygiene.** `.gitignore` excludes assessments, certificates, keys, logs and accepted-risk files (client-specific).
