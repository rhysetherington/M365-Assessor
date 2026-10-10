function ConvertTo-MdCell {
    param($Text)
    # Tenant-controlled text (display names, policy names) must not become live Markdown/HTML in a viewer.
    ([string]$Text) -replace '<', '&lt;' -replace '>', '&gt;' -replace '\|', '\|' -replace '\r?\n', ' '
}

function Get-ScoreText {
    param($Assessment)
    if ($null -eq $Assessment.Score) { 'Not calculated' } else { "$($Assessment.Score)%" }
}

function Get-ComplianceMatrix {
    # One row per NIST CSF 2.0 subcategory: worst status wins (Gap > NotAssessed > Accepted > Pass).
    param($Findings)
    $Findings | Group-Object NistCsf | Sort-Object Name | ForEach-Object {
        $status = if ($_.Group.Status -contains 'Gap') { 'Gap' } elseif ($_.Group.Status -contains 'NotAssessed') { 'Not assessed' } elseif ($_.Group.Status -contains 'Accepted') { 'Accepted' } else { 'Pass' }
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

    $m = $Assessment.Metadata
    $md.Add("# $(ConvertTo-MdCell $(if ($m.AssessmentName) { $m.AssessmentName } else { 'Microsoft 365 Security Gap Assessment' }))")
    $md.Add('')
    $md.Add("| | |`n|---|---|")
    if ($m.ClientName) { $md.Add("| **Client** | $(ConvertTo-MdCell $m.ClientName) |") }
    if ($m.AssessmentDate) { $md.Add("| **Assessment date** | $(ConvertTo-MdCell $m.AssessmentDate) |") }
    if ($m.AssessorName) { $md.Add("| **Assessor** | $(ConvertTo-MdCell $m.AssessorName)$(if ($m.PreparedBy) { ', ' + (ConvertTo-MdCell $m.PreparedBy) }) |") }
    if ($m.Reference) { $md.Add("| **Reference** | $(ConvertTo-MdCell $m.Reference) |") }
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
    if ($Assessment.Summary.Accepted) { $md.Add("| Accepted risks | $($Assessment.Summary.Accepted) |") }
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
            $cis = if (@($g.CisControl).Count) { "  |  **CIS M365 v7.0.0:** $(@($g.CisControl) -join ', ')" } else { '' }
            $md.Add("- **SCF:** $($g.ScfControl)  |  **NIST CSF 2.0:** $($g.NistCsf)$cis")
            if ($g.Detail) { $md.Add("- **Detail:** $($g.Detail)") }
            if ($g.AffectedCount -gt 0) {
                $md.Add("- **Affected ($($g.AffectedCount)):**")
                foreach ($a in ($g.AffectedObjects | Select-Object -First 25)) { $md.Add("  - $(ConvertTo-MdCell $a)") }
                if ($g.AffectedCount -gt 25) { $md.Add("  - ...and $($g.AffectedCount - 25) more (see AssessmentFindings.json)") }
            }
            if ($g.Workloads) {
                $md.Add('')
                $md.Add("| Workload | Controls | Points available | Biggest wins |`n|---|--:|--:|---|")
                foreach ($w in $g.Workloads) { $md.Add("| $(ConvertTo-MdCell $w.Workload) | $($w.Controls) | $($w.PointsAvailable) | $(ConvertTo-MdCell (@($w.Top) -join '; ')) |") }
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
    $accepted = @($f | Where-Object Status -eq 'Accepted')
    if ($accepted.Count) {
        $md.Add('')
        $md.Add('## Accepted Risks')
        $md.Add('')
        foreach ($a in $accepted) {
            $exp = if ($a.AcceptedRisk.Expires) { ", expires $($a.AcceptedRisk.Expires)" } else { '' }
            $md.Add("- **$($a.FindingId)** $($a.Name): $(ConvertTo-MdCell $a.AcceptedRisk.Reason) (approved by $(if ($a.AcceptedRisk.ApprovedBy) { $a.AcceptedRisk.ApprovedBy } else { 'n/a' })$exp)")
        }
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
    param($Assessment, [hashtable]$Branding = @{})
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $f = @($Assessment.Findings)
    $gaps = @($f | Where-Object Status -eq 'Gap')
    $sev = $Assessment.Summary.GapsBySeverity
    $sum = $Assessment.Summary
    $sb = [System.Text.StringBuilder]::new()
    $add = { param($t) [void]$sb.Append($t) }

    $assessedAt = [datetime]$Assessment.AssessedAt
    $meta = $Assessment.Metadata
    $client = if ($Branding.ClientName) { $Branding.ClientName } elseif ($meta.ClientName) { $meta.ClientName } else { $Assessment.TenantName }
    $title = if ($meta.AssessmentName) { $meta.AssessmentName } else { 'Microsoft 365 Security Gap Assessment' }
    $when = if ($meta.AssessmentDate) { ([datetime]$meta.AssessmentDate).ToString('d MMMM yyyy') } else { $assessedAt.ToString('d MMMM yyyy') }
    $assessor = if ($meta.AssessorName) { " &middot; Assessor: <b>$(& $enc $meta.AssessorName)</b>" } else { '' }
    $ref = if ($meta.Reference) { " &middot; Ref: $(& $enc $meta.Reference)" } else { '' }
    $accent = if ($Branding.BrandColor -match '^#[0-9a-fA-F]{6}$') { ":root{--hero2:$($Branding.BrandColor)}" } else { '' }
    $logo = ''
    if ($Branding.LogoPath) {
        $ext = [IO.Path]::GetExtension($Branding.LogoPath).TrimStart('.').ToLowerInvariant()
        $mime = switch ($ext) { 'svg' { 'image/svg+xml' } 'jpg' { 'image/jpeg' } 'jpeg' { 'image/jpeg' } 'png' { 'image/png' } default { $null } }
        if ($mime) { $logo = "<img class=`"logo`" alt=`"`" src=`"data:$mime;base64,$([Convert]::ToBase64String([IO.File]::ReadAllBytes($Branding.LogoPath)))`">" }
    }
    $byName = if ($Branding.PreparedBy) { $Branding.PreparedBy } else { $meta.PreparedBy }
    $preparedBy = if ($byName) { " by <b>$(& $enc $byName)</b>" } else { '' }

    $score = $Assessment.Score
    $scoreText = if ($null -eq $score) { 'n/a' } else { "$([math]::Round($score))%" }
    $scoreDeg = if ($null -eq $score) { 0 } else { [math]::Round(3.6 * [double]$score) }
    $scoreVar = if ($null -eq $score) { 'var(--mute)' } elseif ($score -ge 80) { 'var(--pass)' } elseif ($score -ge 60) { 'var(--medium)' } else { 'var(--critical)' }
    $scoreWord = if ($null -eq $score) { 'Not calculated' } elseif ($score -ge 80) { 'Strong' } elseif ($score -ge 60) { 'Fair' } else { 'Needs attention' }
    $assessed = $sum.TotalChecks - $sum.NotAssessed

    $css = @'
:root{--bg:#f4f6f9;--card:#fff;--ink:#17202c;--mute:#5a6879;--line:#e1e6ed;--soft:#eef2f7;--accent:#1d4ed8;--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2f6fba;--pass:#1b7f4b;--hero1:#0f2742;--hero2:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#0e141b;--card:#161e28;--ink:#e6ebf2;--mute:#9aa8b9;--line:#263241;--soft:#1d2733;--accent:#6ea0ff;--critical:#f97066;--high:#ff8a4c;--medium:#e3b341;--low:#6ea8ff;--pass:#4cc38a;--hero1:#0b1a2e;--hero2:#1e3a8a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.hero{background:linear-gradient(135deg,var(--hero1),var(--hero2));color:#fff;padding:44px 20px 84px}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px}.hero .wrap{padding:0}
.eyebrow{letter-spacing:.14em;text-transform:uppercase;font-size:12px;opacity:.75;font-weight:600}
h1{margin:6px 0 8px;font-size:34px;line-height:1.15;letter-spacing:-.01em}.hero p{margin:0;opacity:.85}
main.wrap{margin:-56px auto 0;padding-bottom:40px}
section{margin-top:28px}h2{font-size:20px;margin:0 0 4px;letter-spacing:-.005em}h3{font-size:16px;margin:22px 0 8px}
.lede{color:var(--mute);margin:0 0 14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;box-shadow:0 1px 2px rgba(15,23,42,.04)}
.glance{display:grid;grid-template-columns:200px 1fr;gap:28px;align-items:center}
.ring{width:176px;height:176px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--deg)*1deg),var(--soft) 0);display:grid;place-items:center;margin:auto}
.ring div{width:144px;height:144px;border-radius:50%;background:var(--card);display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;line-height:1.15}
.ring b{font-size:38px;display:block}.ring span{font-size:11px;color:var(--mute);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.stat{background:var(--soft);border-radius:10px;padding:12px 14px}.stat b{font-size:24px;display:block;line-height:1.2}.stat span{color:var(--mute);font-size:13px}
.sevbar{display:flex;height:12px;border-radius:99px;overflow:hidden;background:var(--soft);margin:16px 0 8px}
.sevbar i{display:block}.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px;color:var(--mute)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:baseline}
.Critical{--s:var(--critical)}.High{--s:var(--high)}.Medium{--s:var(--medium)}.Low{--s:var(--low)}
.bg-Critical{background:var(--critical)}.bg-High{background:var(--high)}.bg-Medium{background:var(--medium)}.bg-Low{background:var(--low)}
.priorities{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px}
.prio{background:var(--card);border:1px solid var(--line);border-top:4px solid var(--s,var(--mute));border-radius:12px;padding:16px 18px}
.prio h4{margin:6px 0 6px;font-size:15px;line-height:1.35}.prio p{margin:0 0 8px;color:var(--mute);font-size:14px}
.prio .step{font-size:13px;background:var(--soft);border-radius:8px;padding:8px 10px}.prio .step b{color:var(--ink)}
.badge{display:inline-block;padding:1px 10px;border-radius:99px;color:#fff;font-size:11.5px;font-weight:700;letter-spacing:.03em;text-transform:uppercase}
.rows{display:grid;gap:12px}.row{display:grid;grid-template-columns:200px 1fr 120px;gap:14px;align-items:center;font-size:14px}
.track{display:flex;height:12px;border-radius:99px;overflow:hidden;background:var(--soft)}.track i{display:block}
.pass{background:var(--pass)}.gapc{background:var(--critical)}.na{background:var(--mute);opacity:.55}.pts{background:var(--accent)}
.row small{color:var(--mute);text-align:right}
.chips{display:flex;flex-wrap:wrap;gap:8px}.chip{background:var(--soft);border-radius:99px;padding:4px 12px;font-size:13px}
.chip.ok::before{content:"\2713";color:var(--pass);font-weight:700;margin-right:6px}
details{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:10px 0}
details>summary{cursor:pointer;padding:12px 16px;list-style:none;display:flex;gap:10px;align-items:center;font-weight:600}
details>summary::-webkit-details-marker{display:none}details>summary::after{content:"\25BE";margin-left:auto;color:var(--mute)}details[open]>summary::after{content:"\25B4"}
details .body{padding:2px 18px 16px;border-top:1px solid var(--line)}
details.sub{border-radius:8px;margin:8px 0;background:var(--soft);border:0}details.sub>summary{font-weight:500;padding:8px 12px}
.meta{color:var(--mute);font-size:13px}code{background:var(--soft);padding:1px 6px;border-radius:5px;font-size:12.5px}
ul,ol{margin:6px 0 6px 20px;padding:0}li{margin:3px 0}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600}
.s-Gap{color:var(--critical);font-weight:600}.s-Pass{color:var(--pass);font-weight:600}.s-Not{color:var(--mute);font-weight:600}
@media (prefers-color-scheme:dark){.logo{background:#fff}}
.logo{height:40px;width:auto;background:#fff;border-radius:8px;padding:6px 10px;margin-bottom:16px;display:block}
footer{color:var(--mute);font-size:12.5px;margin-top:36px;padding-top:16px;border-top:1px solid var(--line)}
@media (max-width:720px){.glance{grid-template-columns:1fr}.row{grid-template-columns:1fr}.row small{text-align:left}h1{font-size:26px}}
@media print{body{background:#fff}.hero{-webkit-print-color-adjust:exact;print-color-adjust:exact}.card,.prio,details{break-inside:avoid;box-shadow:none}}
'@

    & $add @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(& $enc $title) - $(& $enc $client)</title>
<style>$css$accent</style></head><body>
<header class="hero"><div class="wrap">$logo<div class="eyebrow">Security assessment</div>
<h1>$(& $enc $title)</h1>
<p>Prepared for <b>$(& $enc $client)</b>$preparedBy &middot; $when$assessor$ref</p></div></header>
<main class="wrap">
<section><div class="card glance">
<div class="ring" style="--c:$scoreVar;--deg:$scoreDeg"><div><b style="color:$scoreVar">$scoreText</b><span>$scoreWord</span></div></div>
<div>
<div class="stats">
<div class="stat"><b>$($sum.Passed)</b><span>checks passed</span></div>
<div class="stat"><b>$($sum.Gaps)</b><span>gaps found</span></div>
<div class="stat"><b>$assessed</b><span>settings assessed</span></div>
$(if ($sum.Accepted) { "<div class=`"stat`"><b>$($sum.Accepted)</b><span>accepted risks</span></div>" })
$(if ($sum.NotAssessed) { "<div class=`"stat`"><b>$($sum.NotAssessed)</b><span>not assessable</span></div>" })
</div>
"@
    $sevTotal = [math]::Max(1, [int]$sev.Critical + [int]$sev.High + [int]$sev.Medium + [int]$sev.Low)
    & $add '<div class="sevbar" role="img" aria-label="Gaps by severity">'
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') {
        if ([int]$sev.$s -gt 0) { & $add "<i class=`"bg-$s`" style=`"width:$([math]::Round(100 * [int]$sev.$s / $sevTotal, 1))%`"></i>" }
    }
    & $add '</div><div class="legend">'
    foreach ($s in 'Critical', 'High', 'Medium', 'Low') { & $add "<span><span class=`"dot bg-$s`"></span>$s $([int]$sev.$s)</span>" }
    & $add '</div></div></div></section>'

    # --- Priorities -----------------------------------------------------------------------------
    $prio = @($gaps | Where-Object { $_.Severity -in 'Critical', 'High' -and $_.FindingId -ne 'SSC-002' } | Select-Object -First 8)
    if ($prio.Count) {
        & $add '<section><h2>Where to focus first</h2><p class="lede">The highest-impact gaps, with the first step to take on each.</p><div class="priorities">'
        foreach ($g in $prio) {
            $first = @($g.Remediation)[0]
            & $add "<div class=`"prio $($g.Severity)`"><span class=`"badge bg-$($g.Severity)`">$($g.Severity)</span><h4>$(& $enc $g.Name)</h4>"
            if ($g.Detail) { & $add "<p>$(& $enc $g.Detail)</p>" }
            if ($first) { & $add "<div class=`"step`"><b>First step:</b> $(& $enc $first)</div>" }
            & $add '</div>'
        }
        & $add '</div></section>'
    }

    # --- Posture by area ------------------------------------------------------------------------
    & $add '<section><h2>Posture by area</h2><p class="lede">How each area of the tenant performed across the checks we ran.</p><div class="card rows">'
    foreach ($d in ($f | Group-Object Domain | Sort-Object Name)) {
        $n = $d.Count
        $p = @($d.Group | Where-Object { $_.Status -in 'Pass', 'Accepted' }).Count
        $g = @($d.Group | Where-Object Status -eq 'Gap').Count
        $x = @($d.Group | Where-Object Status -eq 'NotAssessed').Count
        & $add "<div class=`"row`"><b>$(& $enc $d.Name)</b><div class=`"track`" role=`"img`" aria-label=`"$p passed, $g gaps, $x not assessed`"><i class=`"pass`" style=`"width:$([math]::Round(100*$p/$n,1))%`"></i><i class=`"gapc`" style=`"width:$([math]::Round(100*$g/$n,1))%`"></i><i class=`"na`" style=`"width:$([math]::Round(100*$x/$n,1))%`"></i></div><small>$([int]$p) passed &middot; $([int]$g) gaps</small></div>"
    }
    & $add '</div><div class="legend" style="margin-top:8px"><span><span class="dot pass"></span>Passed</span><span><span class="dot gapc"></span>Gap</span><span><span class="dot na"></span>Not assessable</span></div></section>'

    # --- Secure Score opportunity ---------------------------------------------------------------
    $ws = @(($f | Where-Object { $_.FindingId -eq 'SSC-002' -and $_.Workloads } | Select-Object -First 1).Workloads)
    if ($ws.Count) {
        $maxPts = [math]::Max(1, ($ws | Measure-Object PointsAvailable -Maximum).Maximum)
        & $add '<section><h2>Microsoft Secure Score: where the points are</h2><p class="lede">Points still available in each Microsoft 365 workload. Larger bars mean larger gains from the same effort.</p><div class="card rows">'
        foreach ($w in ($ws | Select-Object -First 8)) {
            & $add "<div class=`"row`"><b>$(& $enc $w.Workload)</b><div class=`"track`" role=`"img`" aria-label=`"$([double]$w.PointsAvailable) points`"><i class=`"pts`" style=`"width:$([math]::Round(100 * $w.PointsAvailable / $maxPts, 1))%`"></i></div><small>$([double]$w.PointsAvailable) pts &middot; $([int]$w.Controls) controls</small></div>"
        }
        & $add '</div></section>'
    }

    # --- What's working -------------------------------------------------------------------------
    $ok = @($f | Where-Object { $_.Status -in 'Pass', 'Accepted' })
    if ($ok.Count) {
        & $add '<section><h2>What is already working</h2><div class="chips" style="margin-top:10px">'
        foreach ($p in $ok) { & $add "<span class=`"chip ok`">$(& $enc $p.Name)</span>" }
        & $add '</div></section>'
    }

    # --- Technical detail -----------------------------------------------------------------------
    & $add '<section><h2>Detailed findings</h2><p class="lede">Technical detail and remediation steps for each gap, grouped by area.</p>'
    foreach ($domain in ($gaps | Group-Object Domain | Sort-Object Name)) {
        & $add "<details><summary>$(& $enc $domain.Name) <span class=`"meta`">$($domain.Count) gap$(if ($domain.Count -ne 1) { 's' })</span></summary><div class=`"body`">"
        foreach ($g in $domain.Group) {
            & $add "<details class=`"sub`"><summary><span class=`"badge bg-$($g.Severity)`">$($g.Severity)</span>$(& $enc $g.Name)</summary><div class=`"body`" style=`"border:0`">"
            $cis = if (@($g.CisControl).Count) { " &middot; CIS M365 v7.0.0 <code>$(& $enc (@($g.CisControl) -join ', '))</code>" } else { '' }
            & $add "<div class=`"meta`"><code>$(& $enc $g.FindingId)</code> &middot; SCF <code>$(& $enc $g.ScfControl)</code> &middot; NIST CSF 2.0 <code>$(& $enc $g.NistCsf)</code>$cis</div>"
            if ($g.Detail) { & $add "<p>$(& $enc $g.Detail)</p>" }
            if ($g.AffectedCount -gt 0) {
                & $add "<b>Affected ($($g.AffectedCount))</b><ul>"
                foreach ($a in ($g.AffectedObjects | Select-Object -First 25)) { & $add "<li>$(& $enc $a)</li>" }
                if ($g.AffectedCount -gt 25) { & $add "<li>&hellip;and $($g.AffectedCount - 25) more (see AssessmentFindings.json)</li>" }
                & $add '</ul>'
            }
            & $add '<b>Remediation</b><ol>'
            foreach ($step in $g.Remediation) { & $add "<li>$(& $enc $step)</li>" }
            & $add '</ol></div></details>'
        }
        & $add '</div></details>'
    }
    & $add '</section>'

    # --- Appendix -------------------------------------------------------------------------------
    & $add '<section><h2>Appendix</h2><details><summary>Control compliance matrix (NIST CSF 2.0 / SCF)</summary><div class="body"><table><tr><th>NIST CSF 2.0</th><th>SCF</th><th>Status</th><th>Findings</th></tr>'
    foreach ($row in (Get-ComplianceMatrix -Findings $f)) {
        $cls = switch ($row.Status) { 'Gap' { 's-Gap' } 'Pass' { 's-Pass' } 'Accepted' { 's-Pass' } default { 's-Not' } }
        & $add "<tr><td>$(& $enc $row.Nist)</td><td>$(& $enc $row.Scf)</td><td class=`"$cls`">$(& $enc $row.Status)</td><td>$(& $enc $row.Finding)</td></tr>"
    }
    & $add '</table></div></details>'
    if ($Assessment.Licensing) {
        & $add '<details><summary>Licensing context</summary><div class="body"><table><tr><th>Capability</th><th>Licensed</th></tr>'
        foreach ($cap in $Assessment.Licensing.Capabilities.PSObject.Properties) {
            $cls = if ($cap.Value) { 's-Pass' } else { 's-Not' }
            & $add "<tr><td>$(& $enc $script:LicenseDisplay[$cap.Name])</td><td class=`"$cls`">$(if ($cap.Value) { 'Yes' } else { 'No' })</td></tr>"
        }
        & $add '</table><p class="meta">Checks that need an unlicensed capability are reported as not assessable rather than passed.</p></div></details>'
    }
    & $add '</section>'

    & $add @"
<footer>$(if (-not $Branding.HideTenantId) { "Tenant <code>$(& $enc $Assessment.TenantId)</code> &middot; " })Assessed $($assessedAt.ToString('yyyy-MM-dd HH:mm')) UTC &middot; M365GapAssessment $(& $enc $Assessment.ModuleVersion). Read-only assessment: no changes were made to the tenant. The score weights each check by severity (Critical 10, High 5, Medium 3, Low 1).</footer>
</main>
<script>window.addEventListener('beforeprint',function(){document.querySelectorAll('details').forEach(function(d){d.open=true})})</script>
</body></html>
"@
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
        [ValidateSet('JSON', 'HTML', 'Markdown')][string[]]$Format = @('JSON', 'Markdown'),
        [hashtable]$Branding = @{}
    )

    process {
        try {
            $null = New-Item -ItemType Directory -Path $ExportPath -Force -ErrorAction Stop
            $written = [System.Collections.Generic.List[string]]::new()

            $base = Get-AssessmentBaseName -Assessment $Assessment
            $jsonPath = Join-Path $ExportPath $(if ($base) { "$base-Findings.json" } else { 'AssessmentFindings.json' })
            $Assessment | Select-Object * -ExcludeProperty ExportedFiles | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding utf8
            $written.Add($jsonPath)

            if ('Markdown' -in $Format) {
                $p = Join-Path $ExportPath $(if ($base) { "$base-Assessment.md" } else { 'M365_Security_Gap_Assessment.md' })
                New-AssessmentMarkdown -Assessment $Assessment | Set-Content -Path $p -Encoding utf8
                $written.Add($p)
            }
            if ('HTML' -in $Format) {
                $p = Join-Path $ExportPath $(if ($base) { "$base-Assessment.html" } else { 'M365_Security_Gap_Assessment.html' })
                New-AssessmentHtml -Assessment $Assessment -Branding $Branding | Set-Content -Path $p -Encoding utf8
                $written.Add($p)
            }
            Protect-ExportPath -Path $ExportPath
            $written.ToArray()
        }
        catch { throw "Report export failed: $($_.Exception.Message)" }
    }
}
