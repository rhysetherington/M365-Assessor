# Adoption plan: ideas from M365SAT for M365GapAssessment

Companion to `M365SAT-comparison.md`. All new checks are **written fresh** from CIS and Microsoft documentation (see licence position in the comparison).
Each item keeps the module's rules: read-only, `Invoke-Collector` + `New-Finding`, one `ControlMapping.json` entry per finding.

**Status as of 2026-10-12.** The module now has 107 findings (the review started from 70) and a 1,057-test offline Pester suite that runs in GitHub Actions. Of the 8 numbered plan
items, 6 are done (1 to 6), 1 is partly done (7: wired, not live-tested) and 1 is not
started (8). Three unplanned areas were also built. What remains is listed in section 2.

Effort: S = under half a day, M = 1-2 days, L = several days.

## 1. Status at a glance

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Missing Graph-only CIS checks | **Done**, live-verified | `ENT-POL-006/007`, `ENT-AUTH-005/006/007`, `ENT-GRP-003`, `ENT-CA-009`. No CIS numbers on these entries (numbering could not be verified). |
| 2 | Exchange and SharePoint gaps | **Done**, live-verified | Audit log (`PUR-001`), OneDrive sync (`SPO-005`) and Outlook on the web storage providers (`EXO-008`, CIS 6.5.3) covered. `EXO-008` was run live as Global Reader on 2026-10-12: the role can read `Get-OwaMailboxPolicy`, and the test tenant's default policy allows additional storage providers (a real Gap). |
| 3 | Evidence files | **Done**, live-verified | `-IncludeEvidence`; formula injection tested offline only (no live item started with `=+-@`). |
| 4 | CIS view | **Done**, live-verified | `-CisView`. **No L1/L2 level**: the mapping has no level data. |
| 5 | CIS coverage generator | **Done**, run on the v7.0.0 benchmark | `Docs/Get-CisCoverage.ps1` against the 158 recommendations in CIS Microsoft 365 Foundations v7.0.0: **70 Covered, 2 Partial, 86 Missing**. The run found 17 existing findings that matched a recommendation but had no CIS number; they are now tagged (61 of 98 findings carry `cis`). See "CIS coverage against v7.0.0". The benchmark list and the report stay local and git-ignored. |
| 6 | Pester suite, CI and analyzer | **Done** | 1,057 offline tests, each feature checked by breaking it in a copy. GitHub Actions runs Pester on Linux, macOS and Windows plus PSScriptAnalyzer (`.github/workflows/ci.yml`; rule exclusions and reasons in `PSScriptAnalyzerSettings.psd1`). |
| 7 | Sovereign cloud validation | **Wired, not live-tested** | One cloud table drives all services; only `Global` is live-tested. Germany rejected. |
| 8 | Azure subscription domain | **Not started** | Still needs the dependency decision (see below). |
| + | Defender for Office 365 depth | **Done**, live-verified | New: `DFO-001..014`. Not in the original plan. |
| + | Purview | **Done**, live-verified | New: `PUR-001..006`. Not in the original plan. |
| + | Session identity check | **Done**, live-verified | New: records which account each service used. Not in the original plan. |

### Revised CIS coverage against M365SAT's shipped inspectors
The comparison counted 10 covered, 2 partial and 12 missing of 24. Re-reading the same 24 titles against today's findings (same title-based method and the same caveats):

- **Now covered: 20.** Added since the review: Security Defaults (`ENT-POL-006`), SSPR enabled (`ENT-POL-007`), smart lockout threshold and duration (`ENT-AUTH-005/006`), audit log search (`PUR-001`), passwords never expire (`ENT-AUTH-007`), public groups (`ENT-GRP-003`), OneDrive sync (`SPO-005`), Outlook on the web storage providers (`EXO-008`) and emergency access accounts (`ENT-CA-009`, which nominates candidates for manual confirmation).
- **Partial: 2.** `CISMAz5111` (we require baseline protection rather than "Security Defaults disabled", the opposite polarity) and `CISMAz5131` (dynamic guest group, related to `ENT-GRP-002` with opposite polarity).
- **Still missing: 2.** `CISMAz5124` (Entra admin centre access restricted; confirm a Graph source exists) and `CISAz65` (SSPR methods required).

This is an estimate by title, not a CIS benchmark score: M365SAT ships only about 24 inspectors, and our own CIS references number 70 of 107 findings.

## 2. What is left

### Open plan items
- **CIS coverage generator (item 5, S).** `Docs/Get-CisCoverage.ps1`: reads `ControlMapping.json` plus a user-supplied CSV of benchmark recommendation IDs and titles and emits Covered / Partial / Missing. The CSV must come from the licensed CIS download and must not be committed.
- **Live tests in the other clouds (item 7, needs tenants).** GCC High, DoD and China are wired but untested; support cannot be claimed until each has been run live. Teams is unsupported in China by design.
- **Azure subscription domain (item 8, L).** Decision needed: accept an `Az.*` dependency (heavy, version-pinning issues M365SAT hit) or use ARM REST with one `Invoke-ArmRequestWithRetry` helper mirroring the Graph one. Recommendation unchanged: ARM REST.

### Housekeeping: done
- **Report builders moved to `Private/ReportBuilders.ps1`.** Output was compared byte for byte before and after (Markdown, HTML, JSON, evidence). `Tests/ModuleLayout.Tests.ps1` now enforces one function per Public file, that the manifest, `Export-ModuleMember` and the files agree, and that no function name is defined twice.
- **`ControlMapping.json` sorted by id**, with `retiredIds` recording `ENT-EXT-002` (reserved, never shipped). Tests enforce sort order, no unexplained numbering gaps, and that a retired id is never reused.
- **README "Extending" rewritten** for how the module works now (mapping fields and formats, `NotAssessed` rules, adding a domain, offline tests, regenerating the coverage doc), with a test that fails if it loses those points.

### Found while delivering (not in the original plan)
- **Some mapping tests had been passing on nothing.** In Pester 5 a variable set in `BeforeDiscovery` is not visible inside an `It` block, so the duplicate-id and severity tests saw `$null`. They now load the mapping at run time and a test asserts it loaded. Worth checking any new test file for the same trap.
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

### 2. Exchange and SharePoint gaps (M): done
Audit log search enabled, OneDrive sync restrictions and Outlook on the web storage providers (`EXO-008`) are covered. Live-verified as Global Reader.

### 3. Evidence files (M): done
`-IncludeEvidence` writes `evidence/<FindingId>.csv` and `evidence/_index.csv`, linked from the reports, no tenant ID, formula-injection neutralised, folder 700 and files 600.

### 4. CIS view of the report (S): done (without L1/L2)
`-CisView` regroups findings by CIS recommendation number and benchmark section. It states that it is not a score against the whole benchmark.

### 5. CIS coverage generator (S): done
`pwsh ./Docs/Get-CisCoverage.ps1 -BenchmarkCsv <your export>`. Needs a CSV with `Recommendation` and `Title` columns (optional `Level`, `Section`) taken from the licensed CIS download. A recommendation is Covered when a finding lists it in `cis`, Partial when only `cisPartial` does, otherwise Missing; mapped numbers absent from the CSV are listed so typos and version mismatches show up.

#### CIS coverage against v7.0.0 (run 2026-10-12)
158 recommendations (116 Level 1, 47 Level 2 by the benchmark's E3/E5 profiles), of which **70 are Covered, 2 Partial and 86 Missing**. Every `cis` number in the mapping exists in v7.0.0 and its title matches the finding. Partial: `1.1.2` (`ENT-CA-009` only nominates candidates) and `5.2.4.1` (`ENT-POL-007` checks that SSPR is on, not that it is set to All).

Worth building, cheapest first (all read-only, Global Reader should suffice):

1. **Conditional Access policy checks: built, not yet live-tested.** `ENT-CA-010` to `ENT-CA-018` cover `5.2.2.2`, `5.2.2.4`, `5.2.2.5`, `5.2.2.10`, `5.2.2.12`, `5.2.2.13`, `5.2.2.15`, `5.2.2.16` and `5.2.2.17` (new file `Private/Get-ConditionalAccessGaps.ps1`, 54 offline tests). Admin roles are looked up by name from the tenant's role templates at run time, and phishing-resistant is judged from the strength's allowed methods. Coverage after this group: **79 Covered, 2 Partial, 77 Missing** of 158. Still to confirm live: that Global Reader gets `allowedCombinations` on the authentication strength and the role template names.
2. **SharePoint tenant settings, same call as today (about 8):** `7.2.2`, `7.2.4`, `7.2.7`, `7.2.9`, `7.2.10`, `7.2.11`, `7.3.1`, and `7.2.8` if it is readable.
3. **Entra tenant policies (about 10):** `5.1.3.1` security group creation, `5.1.4.1` to `5.1.4.4` device join and local admin, `5.1.4.6` BitLocker key recovery, `5.1.5.3` to `5.1.5.6` application password and certificate lifetimes, `5.2.3.6` / `5.2.3.7` / `5.2.3.10` from the authentication methods policy, `5.3.5` PIM approval for Privileged Role Administrator.
4. **Identity hygiene (3):** `1.1.1` admin accounts cloud-only, `1.1.4` admin licences with a reduced footprint, `5.2.4.2` to `5.2.4.5` SSPR details if the policy is readable.
5. **Exchange (about 8):** `6.5.5` Direct Send rejected (next to `EXO-004`), `6.1.2` / `6.1.3` mailbox audit actions and bypass, `6.5.2` MailTips, `6.3.1` / `6.3.2` add-ins and personal accounts, `2.1.3`, `2.1.11`, `2.1.15`, `2.4.1` / `2.4.2` / `2.4.5`.
6. **Teams (2):** `8.4.1` app permission policies, `8.5.8` external meeting chat.

Defer: the 12 Power BI / Fabric recommendations (`9.1.x`, a new domain and API), and settings that exist only in a portal (`5.1.2.4`, `5.1.2.5`, `5.1.2.6`, most of `1.3.x`, `2.2.1`, `2.4.3`, `5.1.8.1`, `5.2.3.3`). Each needs a Graph or cmdlet source confirmed first.

### 6. Pester suite and CI check (M): done
Covers findings and scoring, the compare cmdlet, DNS helper, mapping integrity, every new collector with fake Graph or fake cmdlets, report rendering, sessions, clouds and the generated documentation.

CI (`.github/workflows/ci.yml`) runs the suite on Ubuntu, macOS and Windows for every push to `main` and every pull request, and runs PSScriptAnalyzer over the module, `Docs/` and `run-assessment.ps1`. `.gitattributes` pins LF line endings so the generated-document drift test passes on Windows. The analyzer excludes five rules, each with its reason in the settings file; any other finding fails the job.

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
1. Live-check `ENT-CA-010` to `ENT-CA-018`, then build the remaining CIS Missing groups in the order above (SharePoint settings next).
2. Report layout fix for narrow screens.
3. Live tests in a sovereign cloud when a tenant is available, then the Azure domain once the dependency decision is made.
