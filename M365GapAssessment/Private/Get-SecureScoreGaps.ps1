function Get-SecureScoreGaps {
    <#
    .SYNOPSIS
        Secure Score collector: overall score vs. target, plus controls where the achieved score is below the maximum.
    #>
    [CmdletBinding()]
    param(
        [int]$TargetScorePercent = 70,
        [int]$HighValuePoints = 5
    )

    Write-Progress -Id 2 -ParentId 1 -Activity 'Secure Score' -Status 'Retrieving score and control profiles' -PercentComplete 10
    Invoke-Collector -Name 'Secure Score' -FindingIds 'SSC-001', 'SSC-002', 'SSC-003' -Script {
        $latest = @(Get-GraphPagedResult -Uri '/v1.0/security/secureScores?$top=1' -MaxItems 1) | Select-Object -First 1
        if (-not $latest) { throw 'No Secure Score data returned for this tenant.' }
        $profiles = @(Get-GraphPagedResult -Uri '/v1.0/security/secureScoreControlProfiles?$top=200')
        $profileById = @{}
        foreach ($p in $profiles) { $profileById[[string]$p.id] = $p }

        $percent = if ($latest.maxScore) { [math]::Round(($latest.currentScore / $latest.maxScore) * 100, 1) } else { 0 }
        $peer = @($latest.averageComparativeScores | Where-Object { $_.basis -eq 'AllTenants' }) | Select-Object -First 1
        $peerText = if ($peer) { " All-tenant average: $([math]::Round($peer.averageScore, 1)) points." } else { '' }
        New-Finding -Id 'SSC-001' -Status $(if ($percent -lt $TargetScorePercent) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($percent -lt $TargetScorePercent) { @("Score $($latest.currentScore) / $($latest.maxScore) ($percent%) vs target $TargetScorePercent%") } else { @() }) `
            -Detail "Current Secure Score $percent% (target $TargetScorePercent%).$peerText"

        $gaps = foreach ($cs in $latest.controlScores) {
            $profile = $profileById[[string]$cs.controlName]
            if ($profile -and $profile.deprecated) { continue }
            $max = if ($profile.maxScore) { [double]$profile.maxScore } else { $null }
            if ($null -eq $max) { continue }
            $achieved = [double]$cs.score
            $status = if ($cs.implementationStatus) { [string]$cs.implementationStatus } elseif ($achieved -ge $max) { 'Implemented' } else { 'Not fully implemented' }
            # implementationStatus often carries HTML fragments; reduce to short plain text for reports.
            $status = [System.Net.WebUtility]::HtmlDecode(($status -replace '<[^>]+>', ' ')) -replace '\s+', ' '
            $status = $status.Trim()
            if ($status.Length -gt 110) { $status = $status.Substring(0, 107) + '...' }
            if ($achieved -ge $max -or $status -match '^(implemented|completed)$') { continue }
            [pscustomobject]@{
                Category = $cs.controlCategory
                Title    = if ($profile.title) { $profile.title } else { $cs.controlName }
                Achieved = $achieved
                Max      = $max
                Gap      = $max - $achieved
                Status   = $status
            }
        }
        $gaps = @($gaps | Sort-Object Gap -Descending)
        $fmt = { "[$($_.Category)] $($_.Title) - $($_.Achieved)/$($_.Max) pts ($($_.Status))" }

        New-Finding -Id 'SSC-002' -Status $(if ($gaps.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($gaps | ForEach-Object $fmt) `
            -Detail "$($gaps.Count) control(s) below maximum score; sorted by points available."

        $high = @($gaps | Where-Object { $_.Gap -ge $HighValuePoints })
        New-Finding -Id 'SSC-003' -Status $(if ($high.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($high | ForEach-Object $fmt) `
            -Detail "Controls with at least $HighValuePoints points still available."
    }
    Write-Progress -Id 2 -ParentId 1 -Activity 'Secure Score' -Completed
}
