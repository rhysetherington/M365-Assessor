# Adoption plan: ideas from M365SAT for M365GapAssessment

Companion to `M365SAT-comparison.md`. All new checks are **written fresh** from CIS and Microsoft documentation (see licence position in the comparison).
Each item keeps the module's rules: read-only, `Invoke-Collector` + `New-Finding`, one `ControlMapping.json` entry per finding.

Effort: S = under half a day, M = 1-2 days, L = several days.

## Priority 1: quick wins that close the CIS gaps found

### 1. Missing Graph-only checks (S each, ~1 day total)
Add to `Private/Get-EntraPolicyGaps.ps1` (new IDs continue the `ENT-` series; add mapping entries with `scf`, `nistCsf`, `cis`, remediation, `license`):

| New finding (proposed) | Source | Reuses |
|---|---|---|
| Security Defaults state (flag if enabled alongside Conditional Access, or disabled with no CA) | `/policies/identitySecurityDefaultsEnforcementPolicy` | CA policy list already fetched |
| SSPR enabled for all users | `authorizationPolicy.allowedToUseSSPR`, plus SSPR registration state | existing `authorizationPolicy` call |
| Smart lockout threshold and duration | `/groupSettings` "Password Rule Settings" (`LockoutThreshold`, `LockoutDurationInSeconds`) | existing password-protection call |
| Passwords set to never expire | `/domains` `passwordValidityPeriodInDays` | existing domains call in EmailDns |
| Only approved public Microsoft 365 groups | `/groups?$filter=visibility eq 'Public'` | paging helper |
| Emergency access accounts exist (upgrade ENT-CA-002 from heuristic) | CA exclusion groups membership plus cloud-only GA accounts | CA policies, role instances |

Acceptance: each has a mapping entry, a mocked offline test, and shows up in the CIS coverage table as Covered.

### 2. Exchange and SharePoint gaps (M)
In `Get-ExchangeOnlineGaps.ps1` and `Get-SharePointGaps.ps1`: audit log search enabled (`Get-AdminAuditLogConfig`), Outlook on the web storage providers restricted (`Get-OwaMailboxPolicy`), OneDrive sync restricted for unmanaged devices (SharePoint admin settings via Graph). Confirm each data source is available read-only to Global Reader before building.

## Priority 2: reporting

### 3. Evidence files (M)
Add `-IncludeEvidence` to `Invoke-M365SecurityReview` and `Export-M365GapReport`. For each Gap finding with affected objects, write
`evidence/<FindingId>.csv` (or `.txt`) beside the reports. Never include secrets; apply the existing `Protect-ExportPath`
and `-HideTenantId` rules. Acceptance: files appear only when the switch is used; report links to them; `Convert-M365Report` ignores a missing folder.

### 4. CIS view of the report (S)
Add an optional report section grouped by CIS recommendation number with L1/L2 level (needs a `cisLevel` field in the mapping where known).
Keep CIS as an *additional* lens; SCF and NIST remain primary.

### 5. CIS coverage generator (S)
Script `Docs/Get-CisCoverage.ps1` that reads `Data/ControlMapping.json` and a user-supplied benchmark list (CSV of recommendation IDs and titles)
and emits Covered / Partial / Missing. The benchmark list must come from the licensed CIS download, not be redistributed in this repo.

## Priority 3: platform

### 6. Pester suite and CI check (M)
`Tests/` with offline mocks (reuse the canned-Graph approach from the earlier `mock-test.ps1`):
- `New-Finding`, `Measure-AssessmentScore` (include weights, NotAssessed, Accepted), `Compare-M365Assessment` change types
- DNS helper (`Resolve-DnsRecordValue`) with a mocked DoH response
- **Mapping integrity:** every ID emitted by a collector exists in `ControlMapping.json`, no duplicates, IDs sorted, required fields present, `license` values valid
- Parse check on all `.ps1` files plus PSScriptAnalyzer
Acceptance: `Invoke-Pester` passes offline in under a minute; fails on a deliberately broken mapping.

### 7. Sovereign cloud validation (M)
Verify `-Environment` handling (Graph base URL, login authority, DoH/DNS behaviour) for USGovGCCHigh, USGovDoD and China, using one connector map in a single place.
Document "tested" versus "untested" per cloud. Needs a tenant in each cloud to claim support; until then mark as untested.

### 8. Azure subscription domain (L, needs a decision)
Opt-in `Azure` domain with read-only `Az.*` checks (Defender for Cloud plans, storage public access, Key Vault purge protection, NSG exposure).
Decision needed: accept an `Az.Accounts`/`Az.Resources` dependency (heavy, version-pinning issues M365SAT hit) or use ARM REST via `Invoke-AzRestMethod`/token reuse.
Recommendation: ARM REST with a single `Invoke-ArmRequestWithRetry` helper mirroring the Graph one; avoids full Az.

## Housekeeping from the review (S)
- Update README "Extending" and "Output" sections; document Accepted-risk semantics.
- **Fix first:** `-HideTenantId` is ignored by the Markdown report (it prints `TenantName (TenantId)` in the header). Pass branding into `New-AssessmentMarkdown` and add a test.
- Move report builders from `Public/` to `Private/`.
- Sort `ControlMapping.json` and note retired ID `ENT-EXT-002`.
- Resolve the nested `.git` (keep and import history, or remove); needs Rhys's decision.

## Do not adopt
- Downloading inspectors at runtime or any `Invoke-Expression` of fetched code.
- Registry edits, module installation or uninstallation, PSGallery trust changes.
- Undocumented portal APIs (`main.iam.ad.ext.azure.com`).
- Credentials as command-line parameters (keep certificate, device code and interactive).

## Suggested order
1 (CIS Graph gaps) → 6 (tests, so later work is safe) → 3 (evidence) → 2 → 4/5 → 7 → 8.
