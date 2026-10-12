# CIS Microsoft 365 Foundations view: findings regrouped by CIS recommendation number and benchmark section, for clients and
# auditors who read results against the benchmark instead of by technology area. Opt-in (-CisView) so default reports are unchanged.
#
# Only findings that carry CIS references appear (the mapping notes say CIS numbers are added only where a check clearly tests the
# same setting). The benchmark's total recommendation count is not in this repository, so the view reports what was assessed and
# deliberately does not state a percentage of the whole benchmark. Numbers follow the control mapping (see its notes) and should be
# checked against the benchmark version a client uses.

$script:CisSectionTitles = @{
    '1' = 'Microsoft 365 admin center'
    '2' = 'Microsoft Defender (email and collaboration)'
    '3' = 'Microsoft Purview'
    '4' = 'Microsoft Intune admin center'
    '5' = 'Microsoft Entra admin center'
    '6' = 'Exchange admin center'
    '7' = 'SharePoint admin center'
    '8' = 'Microsoft Teams admin center'
    '9' = 'Microsoft Fabric'
}

function Get-CisView {
    <#
    .SYNOPSIS
        Groups findings by CIS recommendation (and benchmark section). One row per recommendation; worst status wins
        (Gap > Not assessed > Accepted > Pass). Returns $null when no finding carries a CIS reference.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)

    $byRef = @{}
    foreach ($f in $Findings) {
        foreach ($ref in @($f.CisControl | Where-Object { $_ })) {
            if (-not $byRef.ContainsKey($ref)) { $byRef[$ref] = [System.Collections.Generic.List[object]]::new() }
            $byRef[$ref].Add($f)
        }
    }
    if (-not $byRef.Count) { return $null }

    # Version-style ordering: 5.2.2.3 sorts after 5.2.2.2 and before 5.2.2.10.
    $sortKey = { ($_ -split '\.' | ForEach-Object { '{0:D4}' -f ([int]$_) }) -join '.' }
    $items = foreach ($ref in ($byRef.Keys | Sort-Object $sortKey)) {
        $group = $byRef[$ref]
        $status = if ($group.Status -contains 'Gap') { 'Gap' }
        elseif ($group.Status -contains 'NotAssessed') { 'Not assessed' }
        elseif ($group.Status -contains 'Accepted') { 'Accepted' }
        else { 'Pass' }
        [pscustomobject]@{
            Ref      = $ref
            Section  = ($ref -split '\.')[0]
            Status   = $status
            Findings = @($group | ForEach-Object { [pscustomobject]@{ Id = $_.FindingId; Name = $_.Name; Status = $_.Status } })
        }
    }

    $sections = foreach ($g in ($items | Group-Object Section | Sort-Object { [int]$_.Name })) {
        $title = if ($script:CisSectionTitles.ContainsKey($g.Name)) { $script:CisSectionTitles[$g.Name] } else { "Section $($g.Name)" }
        [pscustomobject]@{
            Number      = $g.Name
            Title       = $title
            Items       = @($g.Group)
            Pass        = @($g.Group | Where-Object Status -in 'Pass', 'Accepted').Count
            Gap         = @($g.Group | Where-Object Status -eq 'Gap').Count
            NotAssessed = @($g.Group | Where-Object Status -eq 'Not assessed').Count
        }
    }
    [pscustomobject]@{ Sections = @($sections); Total = @($items).Count }
}

function Get-CisViewMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$View)
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('## CIS Microsoft 365 Foundations View')
    $md.Add('')
    $md.Add("Findings regrouped by CIS recommendation number. $($View.Total) recommendation(s) were assessed by this tool; recommendations with no CIS-mapped check are not listed, so this is **not** a score against the whole benchmark.")
    $md.Add('')
    $md.Add("| Section | Assessed | Pass | Gap | Not assessed |`n|---|:-:|:-:|:-:|:-:|")
    foreach ($s in $View.Sections) { $md.Add("| $($s.Number) $(ConvertTo-MdCell $s.Title) | $($s.Items.Count) | $($s.Pass) | $($s.Gap) | $($s.NotAssessed) |") }
    foreach ($s in $View.Sections) {
        $md.Add('')
        $md.Add("### $($s.Number) $(ConvertTo-MdCell $s.Title)")
        $md.Add('')
        $md.Add("| CIS | Status | Findings |`n|---|---|---|")
        foreach ($i in $s.Items) {
            $names = ($i.Findings | ForEach-Object { "$($_.Id) $(ConvertTo-MdCell $_.Name)" }) -join '; '
            $md.Add("| $($i.Ref) | $($i.Status) | $names |")
        }
    }
    $md.Add('')
    $md
}

function Get-CisViewHtml {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$View)
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    $cls = { param($status) switch ($status) { 'Gap' { 's-Gap' } 'Pass' { 's-Pass' } 'Accepted' { 's-Pass' } default { 's-Not' } } }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<details><summary>CIS Microsoft 365 Foundations view ($($View.Total) recommendations assessed)</summary><div class=`"body`">")
    [void]$sb.Append('<p class="meta">Findings regrouped by CIS recommendation number. Only recommendations with a CIS-mapped check are listed, so this is not a score against the whole benchmark.</p>')
    [void]$sb.Append('<table><tr><th>Section</th><th>Assessed</th><th>Pass</th><th>Gap</th><th>Not assessed</th></tr>')
    foreach ($s in $View.Sections) {
        [void]$sb.Append("<tr><td>$(& $enc "$($s.Number) $($s.Title)")</td><td>$($s.Items.Count)</td><td>$($s.Pass)</td><td>$($s.Gap)</td><td>$($s.NotAssessed)</td></tr>")
    }
    [void]$sb.Append('</table>')
    foreach ($s in $View.Sections) {
        [void]$sb.Append("<h4>$(& $enc "$($s.Number) $($s.Title)")</h4><table><tr><th>CIS</th><th>Status</th><th>Findings</th></tr>")
        foreach ($i in $s.Items) {
            $names = ($i.Findings | ForEach-Object { "$(& $enc $_.Id) $(& $enc $_.Name)" }) -join '; '
            [void]$sb.Append("<tr><td>$(& $enc $i.Ref)</td><td class=`"$(& $cls $i.Status)`">$(& $enc $i.Status)</td><td>$names</td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append('</div></details>')
    $sb.ToString()
}
