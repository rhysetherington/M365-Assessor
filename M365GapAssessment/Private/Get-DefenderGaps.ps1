function Get-DefenderGaps {
    <#
    .SYNOPSIS
        Defender / Intune collector: unresolved alerts and incidents, device compliance and encryption.
    #>
    [CmdletBinding()]
    param([int]$MaxItems = 2000)

    $sevRank = @{ high = 0; medium = 1; low = 2; informational = 3; unknown = 4 }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender' -Status 'Security alerts' -PercentComplete 10
    Invoke-Collector -Name 'Security alerts' -FindingIds 'DEF-ALR-001' -Script {
        # alerts_v2 severities are: unknown, informational, low, medium, high (no 'critical').
        $alerts = @(Get-GraphPagedResult -Uri "/v1.0/security/alerts_v2?`$filter=severity eq 'high'&`$top=500" -MaxItems $MaxItems)
        $open = @($alerts | Where-Object { $_.status -ne 'resolved' } | Sort-Object { $_.createdDateTime } -Descending)
        $labels = @($open | ForEach-Object { "[$($_.status)] $($_.title) - $($_.serviceSource), created $(([datetime]$_.createdDateTime).ToString('yyyy-MM-dd'))" })
        New-Finding -Id 'DEF-ALR-001' -Status $(if ($labels.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $labels `
            -Detail "$($labels.Count) unresolved High severity alert(s) out of $($alerts.Count) High alerts retrieved."
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender' -Status 'Security incidents' -PercentComplete 40
    Invoke-Collector -Name 'Security incidents' -FindingIds 'DEF-INC-001' -Script {
        $incidents = @(Get-GraphPagedResult -Uri "/v1.0/security/incidents?`$filter=status ne 'resolved'&`$top=50" -MaxItems $MaxItems)
        $active = @($incidents | Where-Object { $_.severity -in 'high', 'medium' } |
                Sort-Object @{ Expression = { $sevRank[[string]$_.severity] } }, @{ Expression = { $_.createdDateTime }; Descending = $false })
        $top = @($active | Select-Object -First 25 | ForEach-Object { "[$($_.severity)/$($_.status)] $($_.displayName) - created $(([datetime]$_.createdDateTime).ToString('yyyy-MM-dd'))" })
        New-Finding -Id 'DEF-INC-001' -Status $(if ($active.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $top `
            -Detail "$($active.Count) unresolved High/Medium incident(s) (oldest first within severity; top 25 listed)."
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender' -Status 'Device compliance' -PercentComplete 70
    Invoke-Collector -Name 'Managed devices' -FindingIds 'DEF-DEV-001', 'DEF-DEV-002' -Script {
        $devices = @(Get-GraphPagedResult -Uri '/beta/deviceManagement/managedDevices?$select=id,deviceName,userPrincipalName,operatingSystem,complianceState,isEncrypted&$top=500')
        if (-not $devices.Count) {
            # Zero devices is "nothing to evaluate", not a pass. Surface it so the reviewer confirms Intune isn't in use
            # or that endpoint controls exist elsewhere.
            $msg = 'No Intune-managed devices returned; endpoint compliance could not be evaluated (Intune not in use, or devices managed elsewhere).'
            New-Finding -Id 'DEF-DEV-001' -Status NotAssessed -Detail $msg
            New-Finding -Id 'DEF-DEV-002' -Status NotAssessed -Detail $msg
            return
        }

        $nonCompliant = @($devices | Where-Object { $_.complianceState -eq 'noncompliant' } |
                ForEach-Object { "$($_.deviceName) ($($_.operatingSystem), $($_.userPrincipalName))" })
        New-Finding -Id 'DEF-DEV-001' -Status $(if ($nonCompliant.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $nonCompliant `
            -Detail "$($nonCompliant.Count) of $($devices.Count) managed devices are non-compliant."

        $unencrypted = @($devices | Where-Object { $_.isEncrypted -eq $false -and $_.operatingSystem -in 'Windows', 'macOS' } |
                ForEach-Object { "$($_.deviceName) ($($_.operatingSystem), $($_.userPrincipalName))" })
        New-Finding -Id 'DEF-DEV-002' -Status $(if ($unencrypted.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $unencrypted `
            -Detail 'Windows/macOS managed devices reporting isEncrypted = false.'
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender' -Completed
}
