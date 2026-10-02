function ConvertTo-MdCell {
    param($Text)
    ([string]$Text) -replace '\|', '\|' -replace '\r?\n', ' '
}

function Get-ScoreText {
    param($Assessment)
    if ($null -eq $Assessment.Score) { 'Not calculated' } else { "$($Assessment.Score)%" }
}

function Get-ComplianceMatrix {
    # One row per NIST CSF 2.0 subcategory: worst status wins (Gap > NotAssessed > Pass).
    param($Findings)
    $Findings | Group-Object NistCsf | Sort-Object Name | ForEach-Object {
        $status = if ($_.Group.Status -contains 'Gap') { 'Gap' } elseif ($_.Group.Status -contains 'NotAssessed') { 'Not assessed' } else { 'Pass' }
        [pscustomobject]@{
            Nist    = $_.Name
            Scf     = (($_.Group.ScfControl | Sort-Object -Unique) -join ', ')
            Status  = $status
            Finding = (($_.Group | ForEach-Object { $_.FindingId }) -join ', ')
        }
    }
}

function New-AssessmentMarkdown {
    param($Assessment)
    $f = @($Assessment.Findings)
    $gaps = @($f | Where-Object Status -eq 'Gap')
    $sev = $Assessment.Summary.GapsBySeverity
    $md = [System.Collections.Generic.List[string]]::new()

    $md.Add("# Microsoft 365 Security Gap Assessment")
    $md.Add('')
    $md.Add("| | |`n|---|---|")
    $md.Add("| **Tenant** | $(ConvertTo-MdCell "$($Assessment.TenantName) ($($Assessment.TenantId))") |")
    $md.Add("| **Assessed** | $($Assessment.AssessedAt.ToString('yyyy-MM-dd HH:mm')) UTC by $(ConvertTo-MdCell $Assessment.AssessedBy) |")
    $md.Add("| **Tool version** | M365GapAssessment $($Assessment.ModuleVersion) (read-only) |")
    $md.Add('')
    $md.Add('## Executive Summary')
    $md.Add('')
    $md.Add("| Metric | Value |`n|---|---|")
    $md.Add("| Compliance score | **$(Get-ScoreText $Assessment)** |")
    $md.Add("| Checks performed | $($Assessment.Summary.TotalChecks) |")
    $md.Add("| Passed | $($Assessment.Summary.Passed) |")
    $md.Add("| Gaps | $($Assessment.Summary.Gaps) |")
    $md.Add("| Not assessed (permission/licence) | $($Assessment.Summary.NotAssessed) |")
    $md.Add('')
    $md.Add("| Critical | High | Medium | Low |`n|:-:|:-:|:-:|:-:|`n| $($sev.Critical) | $($sev.High) | $($sev.Medium) | $($sev.Low) |")
    $md.Add('')
    if ($Assessment.Licensing) {
        $md.Add('## Licensing Context')
        $md.Add('')
        $md.Add("| Capability | Licensed |`n|---|:-:|")
        foreach ($cap in $Assessment.Licensing.Capabilities.PSObject.Properties) {
            $md.Add("| $($script:LicenseDisplay[$cap.Name]) | $(if ($cap.Value) { 'Yes' } else { 'No' }) |")
        }
        $md.Add('')
        $md.Add('Checks needing an unlicensed capability are reported as *Not assessed* so they are not mistaken for passes.')
        $md.Add('')
    }
    $md.Add('## Control Compliance Matrix (NIST CSF 2.0 / SCF)')
    $md.Add('')
    $md.Add("| NIST CSF 2.0 | SCF | Status | Findings |`n|---|---|---|---|")
    foreach ($row in (Get-ComplianceMatrix -Findings $f)) {
        $md.Add("| $($row.Nist) | $($row.Scf) | $($row.Status) | $($row.Finding) |")
    }
    $md.Add('')
    $md.Add('## Detailed Findings by Domain')
    foreach ($domain in ($gaps | Group-Object Domain | Sort-Object Name)) {
        $md.Add('')
        $md.Add("### $($domain.Name)")
        foreach ($g in $domain.Group) {
            $md.Add('')
            $md.Add("#### [$($g.Severity)] $($g.FindingId) - $($g.Name)")
            $md.Add('')
            $md.Add("- **SCF:** $($g.ScfControl)  |  **NIST CSF 2.0:** $($g.NistCsf)")
            if ($g.Detail) { $md.Add("- **Detail:** $($g.Detail)") }
            if ($g.AffectedCount -gt 0) {
                $md.Add("- **Affected ($($g.AffectedCount)):**")
                foreach ($a in ($g.AffectedObjects | Select-Object -First 25)) { $md.Add("  - $(ConvertTo-MdCell $a)") }
                if ($g.AffectedCount -gt 25) { $md.Add("  - ...and $($g.AffectedCount - 25) more (see AssessmentFindings.json)") }
            }
            $md.Add('')
            $md.Add('**Remediation (admin portal):**')
            $md.Add('')
            $i = 1
            foreach ($step in $g.Remediation) { $md.Add("$i. $step"); $i++ }
        }
    }
    $na = @($f | Where-Object Status -eq 'NotAssessed')
    if ($na.Count) {
        $md.Add('')
        $md.Add('## Checks Not Assessed')
        $md.Add('')
        foreach ($n in $na) { $md.Add("- **$($n.FindingId)** $($n.Name): $(ConvertTo-MdCell $n.Detail)") }
    }
    $passed = @($f | Where-Object Status -eq 'Pass')
    if ($passed.Count) {
        $md.Add('')
        $md.Add('## Checks Passed')
        $md.Add('')
        foreach ($p in $passed) { $md.Add("- $($p.FindingId) $($p.Name)") }
    }
    $md -join "`n"
}

function New-AssessmentHtml {
    param($Assessment)
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $f = @($Assessment.Findings)
    $gaps = @($f | Where-Object Status -eq 'Gap')
    $sev = $Assessment.Summary.GapsBySeverity
    $sb = [System.Text.StringBuilder]::new()

    [void]$sb.Append(@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Security Gap Assessment - $(& $enc $Assessment.TenantName)</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1c2430;--mute:#5d6b7c;--line:#e2e6ec;--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2f6fba;--pass:#1b7f4b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px}h2{margin-top:36px;border-bottom:2px solid var(--line);padding-bottom:6px}
.meta{color:var(--mute)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.tile b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{background:#eef1f5}
.finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--mute);border-radius:8px;padding:14px 18px;margin:14px 0}
.finding.Critical{border-left-color:var(--critical)}.finding.High{border-left-color:var(--high)}.finding.Medium{border-left-color:var(--medium)}.finding.Low{border-left-color:var(--low)}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;color:#fff;font-size:12px;font-weight:600;margin-right:6px}
.badge.Critical{background:var(--critical)}.badge.High{background:var(--high)}.badge.Medium{background:var(--medium)}.badge.Low{background:var(--low)}
.s-Gap{color:var(--critical);font-weight:600}.s-Pass{color:var(--pass);font-weight:600}.s-Not{color:var(--mute);font-weight:600}
code{background:#eef1f5;padding:1px 5px;border-radius:4px}@media print{body{background:#fff}.finding{break-inside:avoid}}
</style></head><body><main>
<h1>Microsoft 365 Security Gap Assessment</h1>
<div class="meta">$(& $enc $Assessment.TenantName) &middot; <code>$(& $enc $Assessment.TenantId)</code> &middot; $($Assessment.AssessedAt.ToString('yyyy-MM-dd HH:mm')) UTC &middot; M365GapAssessment $(& $enc $Assessment.ModuleVersion) (read-only)</div>
<h2>Executive Summary</h2>
<div class="grid">
<div class="tile">Compliance score<b>$(& $enc (Get-ScoreText $Assessment))</b></div>
<div class="tile">Checks<b>$($Assessment.Summary.TotalChecks)</b></div>
<div class="tile">Gaps<b>$($Assessment.Summary.Gaps)</b></div>
<div class="tile">Not assessed<b>$($Assessment.Summary.NotAssessed)</b></div></div>
<table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr><tr><td>$($sev.Critical)</td><td>$($sev.High)</td><td>$($sev.Medium)</td><td>$($sev.Low)</td></tr></table>
<h2>Control Compliance Matrix (NIST CSF 2.0 / SCF)</h2>
<table><tr><th>NIST CSF 2.0</th><th>SCF</th><th>Status</th><th>Findings</th></tr>
"@)
    foreach ($row in (Get-ComplianceMatrix -Findings $f)) {
        $cls = switch ($row.Status) { 'Gap' { 's-Gap' } 'Pass' { 's-Pass' } default { 's-Not' } }
        [void]$sb.Append("<tr><td>$(& $enc $row.Nist)</td><td>$(& $enc $row.Scf)</td><td class=`"$cls`">$(& $enc $row.Status)</td><td>$(& $enc $row.Finding)</td></tr>")
    }
    [void]$sb.Append('</table>')
    if ($Assessment.Licensing) {
        [void]$sb.Append('<h2>Licensing Context</h2><table><tr><th>Capability</th><th>Licensed</th></tr>')
        foreach ($cap in $Assessment.Licensing.Capabilities.PSObject.Properties) {
            $cls = if ($cap.Value) { 's-Pass' } else { 's-Not' }
            [void]$sb.Append("<tr><td>$(& $enc $script:LicenseDisplay[$cap.Name])</td><td class=`"$cls`">$(if ($cap.Value) { 'Yes' } else { 'No' })</td></tr>")
        }
        [void]$sb.Append('</table><p class="meta">Checks that need an unlicensed capability are reported as Not assessed rather than passed.</p>')
    }
    [void]$sb.Append('<h2>Detailed Findings</h2>')
    foreach ($domain in ($gaps | Group-Object Domain | Sort-Object Name)) {
        [void]$sb.Append("<h3>$(& $enc $domain.Name)</h3>")
        foreach ($g in $domain.Group) {
            [void]$sb.Append("<div class=`"finding $($g.Severity)`"><span class=`"badge $($g.Severity)`">$($g.Severity)</span><b>$(& $enc $g.FindingId) &ndash; $(& $enc $g.Name)</b>")
            [void]$sb.Append("<div class=`"meta`">SCF <code>$(& $enc $g.ScfControl)</code> &middot; NIST CSF 2.0 <code>$(& $enc $g.NistCsf)</code></div>")
            if ($g.Detail) { [void]$sb.Append("<p>$(& $enc $g.Detail)</p>") }
            if ($g.AffectedCount -gt 0) {
                [void]$sb.Append("<details><summary>Affected ($($g.AffectedCount))</summary><ul>")
                foreach ($a in ($g.AffectedObjects | Select-Object -First 25)) { [void]$sb.Append("<li>$(& $enc $a)</li>") }
                if ($g.AffectedCount -gt 25) { [void]$sb.Append("<li>&hellip;and $($g.AffectedCount - 25) more (see JSON)</li>") }
                [void]$sb.Append('</ul></details>')
            }
            [void]$sb.Append('<b>Remediation</b><ol>')
            foreach ($step in $g.Remediation) { [void]$sb.Append("<li>$(& $enc $step)</li>") }
            [void]$sb.Append('</ol></div>')
        }
    }
    [void]$sb.Append('</main></body></html>')
    $sb.ToString()
}

function Export-M365GapReport {
    <#
    .SYNOPSIS
        Writes AssessmentFindings.json (always) plus Markdown and/or HTML reports for an assessment object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Assessment,
        [Parameter(Mandatory)][string]$ExportPath,
        [ValidateSet('JSON', 'HTML', 'Markdown')][string[]]$Format = @('JSON', 'Markdown')
    )

    process {
        try {
            $null = New-Item -ItemType Directory -Path $ExportPath -Force -ErrorAction Stop
            $written = [System.Collections.Generic.List[string]]::new()

            $jsonPath = Join-Path $ExportPath 'AssessmentFindings.json'
            $Assessment | Select-Object * -ExcludeProperty ExportedFiles | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding utf8
            $written.Add($jsonPath)

            if ('Markdown' -in $Format) {
                $p = Join-Path $ExportPath 'M365_Security_Gap_Assessment.md'
                New-AssessmentMarkdown -Assessment $Assessment | Set-Content -Path $p -Encoding utf8
                $written.Add($p)
            }
            if ('HTML' -in $Format) {
                $p = Join-Path $ExportPath 'M365_Security_Gap_Assessment.html'
                New-AssessmentHtml -Assessment $Assessment | Set-Content -Path $p -Encoding utf8
                $written.Add($p)
            }
            $written.ToArray()
        }
        catch { throw "Report export failed: $($_.Exception.Message)" }
    }
}
