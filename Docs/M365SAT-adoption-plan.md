# Adoption plan: ideas from M365SAT for M365GapAssessment

Companion to `M365SAT-comparison.md`. All new checks are **written fresh** from CIS and Microsoft documentation (see licence position in the comparison).
Each item keeps the module's rules: read-only, `Invoke-Collector` + `New-Finding`, one `ControlMapping.json` entry per finding.

**Status as of 2026-10-12.** The module now has 97 findings (the review started from 70) and a 771-test offline Pester suite. Of the 8 numbered plan
items, 3 are done (1, 3 and 4), 3 are partly done (2: one check open; 6: suite built, CI and analyzer open; 7: wired, not live-tested) and 2 are not
started (5 and 8). Three unplanned areas were also built. What remains is listed in section 2.

Effort: S = under half a day, M = 1-2 days, L = several days.

## 1. Status at a glance

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Missing Graph-only CIS checks | **Done**, live-verified | `ENT-POL-006/007`, `ENT-AUTH-005/006/007`, `ENT-GRP-003`, `ENT-CA-009`. No CIS numbers on these entries (numbering could not be verified). |
| 2 | Exchange and SharePoint gaps | **Mostly done** | Audit log (`PUR-001`) and OneDrive sync (`SPO-005`) covered. **Outlook on the web storage providers is not built.** |
| 3 | Evidence files | **Done**, live-verified | `-IncludeEvidence`; formula injection tested offline only (no live item started with `=+-@`). |
| 4 | CIS view | **Done**, live-verified | `-CisView`. **No L1/L2 level**: the mapping has no level data. |
| 5 | CIS coverage generator | **Not started** | Needs the licensed CIS benchmark list as input. |
| 6 | Pester suite | **Done**; CI and PSScriptAnalyzer **not done** | 771 offline tests, each feature checked by breaking it in a copy. No CI config, no analyzer. |
| 7 | Sovereign cloud validation | **Wired, not live-tested** | One cloud table drives all services; only `Global` is live-tested. Germany rejected. |
| 8 | Azure subscription domain | **Not started** | Still needs the dependency decision (see below). |
| + | Defender for Office 365 depth | **Done**, live-verified | New: `DFO-001..014`. Not in the original plan. |
| + | Purview | **Done**, live-verified | New: `PUR-001..006`. Not in the original plan. |
| + | Session identity check | **Done**, live-verified | New: records which account each service used. Not in the original plan. |

### Revised CIS coverage against M365SAT's shipped inspectors
The comparison counted 10 covered, 2 partial and 12 missing of 24. Re-reading the same 24 titles against today's findings (same title-based method and the same caveats):

- **Now covered: 19.** Added since the review: Security Defaults (`ENT-POL-006`), SSPR enabled (`ENT-POL-007`), smart lockout threshold and duration (`ENT-AUTH-005/006`), audit log search (`PUR-001`), passwords never expire (`ENT-AUTH-007`), public groups (`ENT-GRP-003`), OneDrive sync (`SPO-005`) and emergency access accounts (`ENT-CA-009`, which nominates candidates for manual confirmation).
- **Partial: 2.** `CISMAz5111` (we require baseline protection rather than "Security Defaults disabled", the opposite polarity) and `CISMAz5131` (dynamic guest group, related to `ENT-GRP-002` with opposite polarity).
- **Still missing: 3.** `CISMAz5124` (Entra admin centre access restricted; confirm a Graph source exists), `CISAz65` (SSPR methods required) and `CISMEx653` (Outlook on the web storage providers).

This is an estimate by title, not a CIS benchmark score: M365SAT ships only about 24 inspectors, and our own CIS references number 43 of 97 findings.

## 2. What is left

### Open plan items
- **Outlook on the web storage providers (item 2, S).** `Get-OwaMailboxPolicy` in the Exchange session; confirm Global Reader can read it before building.
- **CIS coverage generator (item 5, S).** `Docs/Get-CisCoverage.ps1`: reads `ControlMapping.json` plus a user-supplied CSV of benchmark recommendation IDs and titles and emits Covered / Partial / Missing. The CSV must come from the licensed CIS download and must not be committed.
- **Continuous integration and PSScriptAnalyzer (item 6, S).** Run `Invoke-Pester ./Tests` and PSScriptAnalyzer on every change. The suite is offline and takes about a minute, so it suits CI.
- **Live tests in the other clouds (item 7, needs tenants).** GCC High, DoD and China are wired but untested; support cannot be claimed until each has been run live. Teams is unsupported in China by design.
- **Azure subscription domain (item 8, L).** Decision needed: accept an `Az.*` dependency (heavy, version-pinning issues M365SAT hit) or use ARM REST with one `Invoke-ArmRequestWithRetry` helper mirroring the Graph one. Recommendation unchanged: ARM REST.

### Housekeeping still open
- **Move the report builders from `Public/` to `Private/`.** `New-AssessmentHtml`, `New-AssessmentMarkdown` and `Get-ComplianceMatrix` still sit in `Public/Export-M365GapReport.ps1`.
- **Sort `ControlMapping.json`.** `ENT-USR-006` still precedes `ENT-USR-005`; `ENT-EXT-002` is absent and should be recorded as a retired ID.
- **README "Extending" section.** It still does not mention the `cis` and `license` fields or the opt-in domains.

### Found while delivering (not in the original plan)
- **Report layout at phone width.** The "Where to focus first" cards and long unbroken email addresses overshoot a very narrow screen by 15-35px. Appendix tables already scroll; this is a style fix (`overflow-wrap`, card widths).
- **Global Reader limits.** As Global Reader, `PUR-006` (insider risk cmdlet not offered to the role) and `DFO-014` (user-reporting policy returned no object) report NotAssessed. Both are handled and explained; worth re-checking if Microsoft changes the role.
- **Default client name.** The folder and client name come from the tenant's default verified domain (`contoso` for the `contoso.com` tenant). Pass `-ClientName` to override; consider preferring the domain that was typed at the prompt.
- **New `DFO`/`PUR` findings carry no CIS references.** Add them only where the recommendation numbering can be checked against the benchmark version a client uses.
- **Coverage still thin** in Intune depth, Purview beyond audit/DLP/labels/retention, and Defender for Office 365 quarantine and impersonation settings. See `Coverage.md` section 3.

## 3. Lessons that shaped the work
- **Live runs found what offline tests could not:** two wrong Graph endpoints, an empty property reported as a pass (`DFO-014`), and a cached Teams login that hid which account answered. Each fix kept a test.
- **Break it to prove the test.** Several mutations survived at first (a bad `sed` pattern, a test that depended on the machine's `umask`); each time the right fix was a better test.
- **"Not assessed" must never look like "fine".** Unreadable settings, missing licences and absent cmdlets all report NotAssessed with a reason, and NotAssessed counts against the score.
- **Cached logins are a risk for a read-only claim.** The Assessment sessions table now makes the account used by each service visible in every report.

## 4. Original plan items (kept for reference)

### 1. Missing Graph-only checks (S each, ~1 day total): done
| New finding (proposed) | Source | Built as |
|---|---|---|
| Security Defaults state | `/policies/identitySecurityDefaultsEnforcementPolicy` | `ENT-POL-006` |
| SSPR enabled for all users | `authorizationPolicy.allowedToUseSSPR` (tenant-level flag only; scope needs portal confirmation) | `ENT-POL-007` |
| Smart lockout threshold and duration | `/groupSettings` "Password Rule Settings" (defaults when absent) | `ENT-AUTH-005`, `ENT-AUTH-006` |
| Passwords set to never expire | `/domains` `passwordValidityPeriodInDays` | `ENT-AUTH-007` |
| Only approved public Microsoft 365 groups | `/groups?$filter=...` | `ENT-GRP-003` |
| Emergency access accounts exist | CA exclusions plus permanent Global Administrators | `ENT-CA-009` (nominates; a person confirms) |

### 2. Exchange and SharePoint gaps (M): mostly done
Audit log search enabled and OneDrive sync restrictions are covered; Outlook on the web storage providers is open (above).

### 3. Evidence files (M): done
`-IncludeEvidence` writes `evidence/<FindingId>.csv` and `evidence/_index.csv`, linked from the reports, no tenant ID, formula-injection neutralised, folder 700 and files 600.

### 4. CIS view of the report (S): done (without L1/L2)
`-CisView` regroups findings by CIS recommendation number and benchmark section. It states that it is not a score against the whole benchmark.

### 5. CIS coverage generator (S): open
See "Open plan items".

### 6. Pester suite and CI check (M): suite done, CI open
Covers findings and scoring, the compare cmdlet, DNS helper, mapping integrity, every new collector with fake Graph or fake cmdlets, report rendering, sessions, clouds and the generated documentation.

### 7. Sovereign cloud validation (M): wired, untested live
One table (`Private/CloudEnvironments.ps1`) drives Graph, Exchange, Purview and Teams; the run refuses if the Graph session lands in a different cloud than requested.

### 8. Azure subscription domain (L, needs a decision): open
Opt-in `Azure` domain with read-only checks (Defender for Cloud plans, storage public access, Key Vault purge protection, NSG exposure).

## 5. Do not adopt
- Downloading inspectors at runtime or any `Invoke-Expression` of fetched code.
- Registry edits, module installation or uninstallation, PSGallery trust changes.
- Undocumented portal APIs (`main.iam.ad.ext.azure.com`).
- Credentials as command-line parameters (keep certificate, device code and interactive).

## 6. Suggested order from here
1. Housekeeping (builders to `Private/`, sort the mapping, README "Extending"): small, and it removes known rough edges.
2. CI with Pester and PSScriptAnalyzer: protects everything built so far.
3. Outlook on the web storage providers, then the CIS coverage generator.
4. Report layout fix for narrow screens.
5. Live tests in a sovereign cloud when a tenant is available, then the Azure domain once the dependency decision is made.
