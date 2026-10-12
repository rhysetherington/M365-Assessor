$script:PurviewIds = 'PUR-001', 'PUR-002', 'PUR-003', 'PUR-004', 'PUR-005', 'PUR-006'

function Get-PurviewGaps {
    <#
    .SYNOPSIS
        Microsoft Purview collector (opt-in domain 'Purview'): unified audit log, DLP, sensitivity labels, retention, insider risk.
    .DESCRIPTION
        Needs the ExchangeOnlineManagement module (Connect-IPPSSession) and its own interactive sign-in. Only Get-* cmdlets are used.
        A failed connection reports every check as NotAssessed. Whether a read-only role such as Global Reader can run each cmdlet
        is confirmed per tenant: a refusal is reported as NotAssessed with the reason.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Status 'Connecting' -PercentComplete 5
    $session = Start-ComplianceSession -TenantId $TenantId
    if (-not $session.Ready) {
        foreach ($id in $script:PurviewIds) { New-Finding -Id $id -Status NotAssessed -Detail $session.Error }
        Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Completed
        return
    }
    try { Invoke-PurviewChecks }
    finally { Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Completed }
}

function Invoke-PurviewChecks {
    # The checks themselves: assumes a Security & Compliance session is already open (tests supply fake cmdlets instead).
    [CmdletBinding()]
    param()

    # --- Audit ---------------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Status 'Audit' -PercentComplete 10
    Invoke-Collector -Name 'Unified audit log' -FindingIds 'PUR-001' -Script {
        Assert-Cmdlet Get-AdminAuditLogConfig 'compliance session not available'
        $cfg = @(Get-AdminAuditLogConfig) | Select-Object -First 1
        $on = [bool]$cfg.UnifiedAuditLogIngestionEnabled
        New-Finding -Id 'PUR-001' -Status $(if ($on) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($on) { @() } else { @('Unified audit log ingestion is turned off') }) `
            -Detail "UnifiedAuditLogIngestionEnabled = $($cfg.UnifiedAuditLogIngestionEnabled). Without it, user and admin activity is not recorded for investigations."
    }

    # --- DLP -----------------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Status 'Data loss prevention' -PercentComplete 30
    Invoke-Collector -Name 'Data loss prevention' -FindingIds 'PUR-002', 'PUR-003' -Script {
        Assert-Cmdlet Get-DlpCompliancePolicy 'DLP cmdlets unavailable'
        $all = @(Get-DlpCompliancePolicy)
        # Only Mode 'Enable' enforces; the test modes and 'Disable' do not block or alert on real content.
        $active = @($all | Where-Object { $_.Enabled -ne $false -and "$($_.Mode)" -eq 'Enable' })
        $notActive = @($all | Where-Object { $_ -notin $active } | ForEach-Object { "$($_.Name) - mode $($_.Mode), enabled $($_.Enabled)" })

        New-Finding -Id 'PUR-002' -Status $(if ($active.Count) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($active.Count) { @() } else { $notActive }) `
            -Detail "$($active.Count) of $($all.Count) DLP policy(ies) are enabled and enforcing."

        $covered = @($active | ForEach-Object { "$($_.Workload)" -split '[,\s]+' } | Where-Object { $_ } | Sort-Object -Unique)
        $required = [ordered]@{ Exchange = 'Exchange email'; SharePoint = 'SharePoint'; OneDriveForBusiness = 'OneDrive'; Teams = 'Teams chat and channels' }
        $missing = @($required.Keys | Where-Object { $_ -notin $covered } | ForEach-Object { "No enforcing DLP policy covers $($required[$_])" })
        New-Finding -Id 'PUR-003' -Status $(if ($missing.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $missing `
            -Detail "Workloads covered by enforcing DLP policies: $(if ($covered.Count) { $covered -join ', ' } else { 'none' })."
    }

    # --- Sensitivity labels --------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Status 'Sensitivity labels and retention' -PercentComplete 55
    Invoke-Collector -Name 'Sensitivity labels' -FindingIds 'PUR-004' -Script {
        Assert-Cmdlet Get-LabelPolicy 'sensitivity label cmdlets unavailable'
        $policies = @(Get-LabelPolicy | Where-Object { $_.Enabled -ne $false })
        $published = @($policies | ForEach-Object { @($_.Labels) } | Where-Object { $_ } | Sort-Object -Unique)
        New-Finding -Id 'PUR-004' -Status $(if ($policies.Count -and $published.Count) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($policies.Count -and $published.Count) { @() } else { @('No sensitivity label is published to users') }) `
            -Detail "$($policies.Count) enabled label polic$(if ($policies.Count -eq 1) { 'y' } else { 'ies' }) publishing $($published.Count) label(s)."
    }

    # --- Retention -------------------------------------------------------------------------------------------
    Invoke-Collector -Name 'Retention' -FindingIds 'PUR-005' -Script {
        Assert-Cmdlet Get-RetentionCompliancePolicy 'retention cmdlets unavailable'
        $enabled = @(Get-RetentionCompliancePolicy | Where-Object { $_.Enabled -ne $false })
        New-Finding -Id 'PUR-005' -Status $(if ($enabled.Count) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($enabled.Count) { @() } else { @('No enabled retention policy') }) `
            -Detail "$($enabled.Count) enabled retention polic$(if ($enabled.Count -eq 1) { 'y' } else { 'ies' })."
    }

    # --- Insider risk ------------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Purview' -Status 'Insider risk' -PercentComplete 85
    Invoke-Collector -Name 'Insider risk management' -FindingIds 'PUR-006' -Script {
        Assert-Cmdlet Get-InsiderRiskPolicy 'Insider Risk Management needs a Microsoft Purview premium licence (for example Microsoft 365 E5)'
        $policies = @(Get-InsiderRiskPolicy)
        New-Finding -Id 'PUR-006' -Status $(if ($policies.Count) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($policies.Count) { @() } else { @('No insider risk policy is configured') }) `
            -Detail "$($policies.Count) insider risk polic$(if ($policies.Count -eq 1) { 'y' } else { 'ies' })."
    }
}
