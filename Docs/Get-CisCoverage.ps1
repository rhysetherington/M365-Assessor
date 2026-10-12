<#
.SYNOPSIS
    Reports which CIS Microsoft 365 Foundations recommendations the assessor covers, from your own copy of the benchmark list.
.DESCRIPTION
    Reads a CSV of benchmark recommendations that you export from the licensed CIS download (it is NOT shipped or committed:
    CIS content has its own terms) and compares it with the CIS references in Data/ControlMapping.json:

      Covered  a finding lists the recommendation in "cis".
      Partial  a finding lists it only in "cisPartial" (the check tests part of the recommendation, or the opposite polarity).
      Missing  no finding references it.

    Mapped numbers that are not in the CSV are listed separately, which usually means a typo or a different benchmark version.
    This is coverage by recommendation number, not a score: a Covered recommendation still has to be judged by the finding.
.PARAMETER BenchmarkCsv
    CSV with a header row and these columns (names are case-insensitive): Recommendation (also accepted: Id, Number), Title, and
    optionally Level (or Profile) and Section.
.PARAMETER OutputPath
    Markdown report to write. Defaults to Assessments/CIS-coverage.md, which is git-ignored because it repeats CIS titles.
.PARAMETER MappingPath
    Alternative mapping file (used by the tests).
.PARAMETER PassThru
    Also return one object per recommendation.
.EXAMPLE
    pwsh ./Docs/Get-CisCoverage.ps1 -BenchmarkCsv ~/Downloads/cis-m365-benchmark.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BenchmarkCsv,
    [string]$OutputPath = (Join-Path $PSScriptRoot '../Assessments/CIS-coverage.md'),
    [string]$MappingPath = (Join-Path $PSScriptRoot '../M365GapAssessment/Data/ControlMapping.json'),
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$numberPattern = '^\d+(\.\d+)*$'

if (-not (Test-Path -LiteralPath $BenchmarkCsv -PathType Leaf)) { throw "Benchmark CSV not found: $BenchmarkCsv" }
$rows = @(Import-Csv -LiteralPath $BenchmarkCsv)
if (-not $rows.Count) { throw "Benchmark CSV has no rows: $BenchmarkCsv" }

function Get-Column {
    param($Row, [string[]]$Names)
    foreach ($n in $Names) {
        $p = $Row.PSObject.Properties | Where-Object { $_.Name.Trim() -ieq $n } | Select-Object -First 1
        if ($p -and "$($p.Value)".Trim()) { return "$($p.Value)".Trim() }
    }
    $null
}

$benchmark = foreach ($row in $rows) {
    $id = Get-Column $row 'Recommendation', 'Id', 'Number'
    if (-not $id) { throw "A row has no recommendation number (expected a Recommendation, Id or Number column): $($row | ConvertTo-Json -Compress)" }
    if ($id -notmatch $numberPattern) { throw "Recommendation '$id' is not a number like 1.1.1." }
    [pscustomobject]@{
        Id      = $id
        Title   = Get-Column $row 'Title'
        Level   = Get-Column $row 'Level', 'Profile'
        Section = Get-Column $row 'Section'
    }
}
$dupes = @($benchmark | Group-Object Id | Where-Object Count -gt 1 | ForEach-Object Name)
if ($dupes) { throw "Duplicate recommendation numbers in the CSV: $($dupes -join ', ')" }

$controls = @((Get-Content -Raw -LiteralPath $MappingPath | ConvertFrom-Json).controls)
$covered = @{}; $partial = @{}
foreach ($c in $controls) {
    foreach ($r in @($c.cis) | Where-Object { $_ }) { if (-not $covered.ContainsKey($r)) { $covered[$r] = @() }; $covered[$r] += $c.id }
    foreach ($r in @($c.cisPartial) | Where-Object { $_ }) { if (-not $partial.ContainsKey($r)) { $partial[$r] = @() }; $partial[$r] += $c.id }
}

$sortKey = { ($_.Id -split '\.' | ForEach-Object { '{0:D4}' -f [int]$_ }) -join '.' }
$result = foreach ($b in ($benchmark | Sort-Object $sortKey)) {
    $status = if ($covered.ContainsKey($b.Id)) { 'Covered' } elseif ($partial.ContainsKey($b.Id)) { 'Partial' } else { 'Missing' }
    $ids = @(@($covered[$b.Id]) + @($partial[$b.Id]) | Where-Object { $_ } | Select-Object -Unique)
    [pscustomobject]@{
        Recommendation = $b.Id; Title = $b.Title; Level = $b.Level; Section = $(if ($b.Section) { $b.Section } else { ($b.Id -split '\.')[0] })
        Status = $status; Findings = $ids
    }
}
$known = @($benchmark | ForEach-Object Id)
$unknown = @(@($covered.Keys) + @($partial.Keys) | Where-Object { $_ -notin $known } | Sort-Object -Unique)

$count = { param($s) @($result | Where-Object Status -eq $s).Count }
$total = @($result).Count
$pct = { param($n) if ($total) { '{0:N0}%' -f (100 * $n / $total) } else { '0%' } }
$nC = & $count 'Covered'; $nP = & $count 'Partial'; $nM = & $count 'Missing'

$md = [System.Collections.Generic.List[string]]::new()
$md.Add('# CIS Microsoft 365 Foundations coverage')
$md.Add('')
$md.Add("Generated $(Get-Date -Format 'yyyy-MM-dd') from ``$(Split-Path -Leaf $BenchmarkCsv)`` and ``ControlMapping.json``. This file repeats CIS titles: do not commit or redistribute it.")
$md.Add('')
$md.Add('Coverage is by recommendation number. It says a finding exists for a recommendation, not that the tenant passes it.')
$md.Add('')
$md.Add('| Status | Recommendations | Share |')
$md.Add('|---|---|---|')
$md.Add("| Covered | $nC | $(& $pct $nC) |")
$md.Add("| Partial | $nP | $(& $pct $nP) |")
$md.Add("| Missing | $nM | $(& $pct $nM) |")
$md.Add("| **Total** | **$total** | |")
$levels = @($result | Where-Object Level | Group-Object Level | Sort-Object Name)
if ($levels.Count) {
    $md.Add('')
    $md.Add('By level:')
    $md.Add('')
    $md.Add('| Level | Covered | Partial | Missing |')
    $md.Add('|---|---|---|---|')
    foreach ($l in $levels) {
        $md.Add("| $($l.Name) | $(@($l.Group | Where-Object Status -eq 'Covered').Count) | $(@($l.Group | Where-Object Status -eq 'Partial').Count) | $(@($l.Group | Where-Object Status -eq 'Missing').Count) |")
    }
}
foreach ($s in ($result | Group-Object Section)) {
    $md.Add('')
    $md.Add("## Section $($s.Name)")
    $md.Add('')
    $md.Add('| Recommendation | Level | Status | Findings | Title |')
    $md.Add('|---|---|---|---|---|')
    foreach ($r in $s.Group) {
        $md.Add("| $($r.Recommendation) | $($r.Level) | $($r.Status) | $($r.Findings -join ', ') | $(("$($r.Title)") -replace '\|', '\|') |")
    }
}
if ($unknown.Count) {
    $md.Add('')
    $md.Add('## Mapped numbers not found in the benchmark CSV')
    $md.Add('')
    $md.Add('Check these for typos or a different benchmark version: ' + ($unknown -join ', ') + '.')
}

$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
Set-Content -LiteralPath $OutputPath -Value ($md -join "`n") -Encoding utf8
Write-Host "CIS coverage: $nC covered, $nP partial, $nM missing of $total. Report: $OutputPath" 
if ($unknown.Count) { Write-Warning "Mapped CIS numbers not in the CSV: $($unknown -join ', ')" }
if ($PassThru) { $result }
