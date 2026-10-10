# M365GapAssessment vs M365SAT: code and module review

Reviewed 2026-10-10. Scope: `M365GapAssessment` (this repo) against `M365SAT-production` (`/Users/rhys/Documents/M365SAT-production`,
v3.1 beta, MIT licence, Leonardo van de Weteringh / CompliantSec). Findings were read from source; M365SAT was **not executed**.
Claims marked *(verified)* were re-checked directly against the files.

## 1. Summary

| | M365GapAssessment | M365SAT |
|---|---|---|
| Purpose | Read-only gap assessment, multi-tenant consulting use | Security configuration audit against CIS benchmarks |
| Engine | Microsoft Graph via one `Invoke-MgGraphRequest` wrapper; EXO/Teams opt-in | Service cmdlets (Graph SDK, EXO, Teams, SPO/PnP, Az) per inspector |
| Findings | 70 (`ControlMapping.json`), 43 with CIS references | ~24 inspectors shipped locally (CIS M365 v4.0.0 and CIS Azure v4.0.0) |
| Frameworks | SCF, NIST CSF 2.0, CIS | CIS only |
| Output | JSON, Markdown, HTML (branded), diff, re-render | HTML (CDN assets), CSV, per-finding evidence files |
| Safe to run unattended | Yes: GET only | No: installs and uninstalls modules, edits registry, downloads and executes code |

**Bottom line:** the architecture, safety and reporting of M365GapAssessment are ahead of M365SAT. M365SAT's remaining
advantages are CIS benchmark ordering, evidence files, Azure subscription checks, and sovereign-cloud connector maps.
Its code should not be copied (see section 3).

## 2. Side-by-side

| Area | M365GapAssessment | M365SAT | Verdict |
|---|---|---|---|
| Data access | `Invoke-GraphRequestWithRetry` and `Get-GraphPagedResult` give 429/5xx backoff with `Retry-After`, plus paging | Direct cmdlets in each inspector; no throttling or pagination handling | Ours |
| Authentication | Interactive, device code, certificate, client secret; role guardrail; work/school authority | Interactive delegated only; `-Username`/`-Password` parameters | Ours |
| Read-only guarantee | Yes, every call is GET | No *(verified)*: edits `HKLM` SchUseStrongCrypto (`core/Update-M365SATModules.ps1`), installs/uninstalls modules, sets PSGallery trusted, may register a "PnP Rocks" Entra app | Ours |
| Code execution | Local code only | Downloads `M365SAT-Inspectors` `production.zip` from an unpinned branch and runs each file with `Invoke-Expression` *(verified: `core/Get-M365SATChecks.ps1`, `core/Invoke-M365SATChecks.ps1:20`)* | Ours; M365SAT is a supply-chain risk |
| Frameworks | One data file maps each finding to SCF, NIST CSF 2.0, CIS | CIS recommendation ID inline in each inspector; no data file, no cross-reference | Ours |
| Scoring | Severity-weighted (10/5/3/1); NotAssessed counts as failure | Flat pass percentage `100 - (affected / total * 100)` *(verified: `core/Get-M365SATHTMLReport.ps1:524`)*, even though the report text says it is weighted | Ours |
| Result model | Gap / Pass / NotAssessed / Accepted | OK / FAIL / UNKNOWN | Comparable |
| Licence awareness | Reads `subscribedSkus`, explains NotAssessed | None; E3/E5 only as folder names | Ours |
| Accepted risk and trend | Accepted-risk file, `Compare-M365Assessment` | None | Ours |
| Reporting | JSON, MD, HTML (offline, branded), re-render without a tenant | HTML needs CDNs (Bootstrap, Chart.js, jQuery, etc.); CSV uses `^` delimiter; XML/CSMS fall back to HTML | Ours |
| Evidence | Not yet | Inspectors write evidence `.txt` files into an `evidence/` folder | **M365SAT** |
| Services covered | Graph, Exchange Online, Teams, SharePoint, DNS | Graph, EXO, IPPS, Teams, SPO/PnP, Azure (Az) | M365SAT covers Azure subscriptions |
| Sovereign clouds | `-Environment` parameter, untested | Connector maps for GCC High, DoD, China; Germany key mismatch (`Germany` vs `GermanyCloud`) | M365SAT, partly buggy |
| Concurrency | Sequential | Sequential (`Invoke-M365SATChecksP7` is an empty stub) | Equal |
| Tests | None (ad hoc offline mocks only) | None; connection tester script only | Equal |
| Packaging | Manifest exports match real functions | Manifest exports `Get-M365SATModuleUpdates` and `Get-M365SATGetInspectors`, which are undefined *(verified)*; versions disagree (3.1 / 3.1 beta / 3.1 alpha); `#Requires -RunAsAdministrator` on a "cross-platform" tool | Ours |

## 3. M365SAT risks (why we do not port its code)

1. **Remote code execution by design.** Inspectors are downloaded from a mutable branch with no hash or signature check and then executed.
2. **Mutates the host and tenant context.** Registry writes, module install/uninstall, PSGallery policy change, possible Entra app registration.
3. **Undocumented APIs.** `CISAz65/66/67/68` and `CISMAz5124/5241` call `main.iam.ad.ext.azure.com` *(verified)*, which Microsoft can change without notice.
4. **Credential handling.** Username and plaintext-capable password as parameters; no app-only path.
5. **Mixed inspector licence and availability.** The README says v4.0.0 inspectors are being commercialised via CompliantSec and removed from GitHub. Inspectors live in a separate repo (`M365SAT-Inspectors`) whose licence was not verified.

**Licence position.** The `M365SAT-production` repo is MIT: copying and modifying is permitted if the copyright and licence notice are kept.
That does not clearly cover the separate inspectors repo, and CIS Benchmark text has its own terms. **Decision: use M365SAT for coverage and design ideas only;
write any new check fresh from CIS and Microsoft documentation.**

## 4. CIS coverage: M365SAT's shipped inspectors vs our findings

Matching is by recommendation *title and intent*, not number: M365SAT uses CIS Microsoft 365 **v4.0.0** while our `cis` field uses the
numbering in `ControlMapping.json` (noted there as v7.0.0), and numbers differ between versions. The 7 Azure items come from the separate
CIS Azure benchmark, so their numbers are not comparable with M365 numbers.

**Result: 10 covered, 2 partial, 12 missing of 24 shipped inspectors.**

| M365SAT inspector | Recommendation | Our finding | Status |
|---|---|---|---|
| CISMAz5122 | Third-party integrated apps not allowed | ENT-POL-003 | Covered |
| CISMEx218 | SPF published for all domains | EML-001 | Covered |
| CISMEx219 | DKIM enabled for all domains | EML-003 | Covered |
| CISMEx611 | `AuditDisabled` = False | EXO-002 | Covered |
| CISMSp721 | Modern auth required for SharePoint | SPO-004 | Covered |
| CISMTm821 | Teams external access restricted | TMS-001 | Covered |
| CISMTm811 | Teams external file sharing limited | TMS-008 | Covered |
| CISAz6026 | Fewer than 5 Global Admins | ENT-USR-005 | Covered |
| CISAz68 | Custom banned password list enforced | ENT-AUTH-004 | Covered |
| CISAz624 | MFA policy exists for all users | ENT-CA-006 | Covered |
| CISMOff112 | Two emergency access accounts defined | ENT-CA-002 (heuristic only) | Partial: we check exclusions, not that the accounts exist |
| CISMAz5131 | Dynamic group for guests exists | ENT-GRP-002 | Partial: related, opposite polarity |
| CISMAz5111 / CISAz611 | Security Defaults state | none | **Missing** |
| CISMAz5124 | Entra admin centre access restricted | none | **Missing** (confirm a Graph source exists) |
| CISMAz5241 | SSPR enabled for All | none | **Missing** |
| CISAz65 | SSPR methods required = 2 | none | **Missing** |
| CISAz66 / CISAz67 | Smart lockout threshold and duration | none | **Missing** (we already read `/groupSettings` for password rules) |
| CISMEx311 | Audit log search enabled | none | **Missing** |
| CISMEx653 | Outlook on the web storage providers restricted | none | **Missing** |
| CISMOff131 | Passwords set to never expire | none | **Missing** (domain `passwordValidityPeriodInDays`) |
| CISMOff121 | Only approved public groups | none | **Missing** |
| CISMSp732 | OneDrive sync restricted for unmanaged devices | none | **Missing** |

**Important limit:** M365SAT ships only ~24 inspectors locally, while its README claims 200+. This table therefore measures us against a sample.
A true coverage figure needs the CIS Microsoft 365 Foundations benchmark itself (licensed separately, not in either repo).
Conversely, our 43 CIS-mapped findings already exceed M365SAT's local M365 set.

## 5. Issues found in M365GapAssessment

All verified against source unless noted.

1. **No automated tests.** No `*.Tests.ps1` anywhere; the live-run bugs earlier (empty tenant loop, two wrong endpoints, `$_` rebound in `switch`) are exactly what a mocked suite catches.
2. **README is stale** *(from exploration; not re-read)*: the "Extending" section omits `cis` and `license`; the output table does not show the base-name file naming.
3. **`-HideTenantId` is HTML-only, so Markdown leaks the tenant ID** *(verified)*: `Export-M365GapReport.ps1:41` always writes `TenantName (TenantId)` into the Markdown header, and `Convert-M365Report.ps1:65` calls `New-AssessmentMarkdown` without the branding hashtable. A user who sets `-HideTenantId` for a client deliverable still gets the ID in the `.md`. Fix: accept `-Branding` in `New-AssessmentMarkdown` and honour `HideTenantId`. **Highest-priority item in this list**, because it defeats an explicit privacy option.
4. **Report builders sit in `Public/`** *(from exploration)*: `New-AssessmentHtml`, `New-AssessmentMarkdown`, `Get-ComplianceMatrix` are unexported but live with public cmdlets. Move to `Private/` for clarity.
5. **`ControlMapping.json` ordering and gaps** *(verified)*: `ENT-USR-006` precedes `ENT-USR-005`; there is no `ENT-EXT-002`. Cosmetic, but a mapping-integrity test should enforce order and document retired IDs.
6. **Git layout** *(verified)*: the project folder now has its own empty `.git` (created 2026-10-10 10:19) that shadows the real history in `/Users/rhys/.git` (latest commit `753abc2`). `git log` run inside the project shows no commits. Decide whether to keep a project-level repo (and import history) or remove the nested one. Not changed by this review.
7. **Not an issue:** accepted-risk handling is consistent: the score counts Accepted as passed (`Helpers.ps1:188`) and `Compare-M365Assessment` treats Accepted as not open. Worth documenting in the README.

## 6. What M365SAT does well (ideas worth taking)

- **CIS-ordered output with L1/L2 levels** so auditors can read results against the benchmark.
- **Evidence files** per finding for audit workpapers.
- **One connector per service** with environment maps for sovereign clouds.
- **Azure subscription coverage** alongside M365.
- A clean, repeatable **inspector template** (identity fields, status, risk, remediation, references).

See `M365SAT-adoption-plan.md` for the prioritised plan.
