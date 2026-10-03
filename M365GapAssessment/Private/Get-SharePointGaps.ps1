function Get-SharePointGaps {
    <#
    .SYNOPSIS
        SharePoint / OneDrive collector: external sharing level, guest resharing, domain restrictions, legacy auth, unmanaged sync.
    .DESCRIPTION
        Reads the tenant-level settings from Graph (GET /admin/sharepoint/settings). Needs the SharePointTenantSettings.Read.All scope;
        without it the checks are reported NotAssessed.
    #>
    [CmdletBinding()]
    param()

    Write-Progress -Id 2 -ParentId 1 -Activity 'SharePoint' -Status 'Tenant sharing settings' -PercentComplete 20
    Invoke-Collector -Name 'SharePoint settings' -FindingIds 'SPO-001', 'SPO-002', 'SPO-003', 'SPO-004', 'SPO-005' -Script {
        $s = Invoke-GraphRequestWithRetry -Uri '/v1.0/admin/sharepoint/settings'

        $capability = [string]$s.sharingCapability
        $friendly = switch ($capability) {
            'disabled' { 'Only people in your organization' }
            'existingExternalUserSharingOnly' { 'Existing guests only' }
            'externalUserSharingOnly' { 'New and existing guests' }
            'externalUserAndGuestSharing' { 'Anyone (anonymous links)' }
            default { $capability }
        }
        New-Finding -Id 'SPO-001' -Status $(if ($capability -eq 'externalUserAndGuestSharing') { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($capability -eq 'externalUserAndGuestSharing') { 'Tenant-level sharing allows anonymous "Anyone" links' } else { @() }) `
            -Detail "Tenant external sharing level: $friendly. Individual sites can only be as permissive as this setting."

        New-Finding -Id 'SPO-002' -Status $(if ($s.isResharingByExternalUsersEnabled) { 'Gap' } else { 'Pass' }) `
            -Detail "Guests can reshare items they do not own = $($s.isResharingByExternalUsersEnabled)."

        $externalOn = $capability -ne 'disabled'
        $restricted = [string]$s.sharingDomainRestrictionMode -in 'allowList', 'blockList'
        New-Finding -Id 'SPO-003' -Status $(if ($externalOn -and -not $restricted) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($externalOn -and -not $restricted) { 'External sharing is on with no allowed or blocked domain list' } else { @() }) `
            -Detail "sharingDomainRestrictionMode = $($s.sharingDomainRestrictionMode); external sharing enabled = $externalOn."

        New-Finding -Id 'SPO-004' -Status $(if ($s.isLegacyAuthProtocolsEnabled) { 'Gap' } else { 'Pass' }) `
            -Detail "Legacy authentication protocols enabled for SharePoint = $($s.isLegacyAuthProtocolsEnabled)."

        New-Finding -Id 'SPO-005' -Status $(if ($s.isUnmanagedSyncAppForTenantRestricted) { 'Pass' } else { 'Gap' }) `
            -Detail "OneDrive sync restricted to managed (domain-joined) devices = $($s.isUnmanagedSyncAppForTenantRestricted)."
    }
    Write-Progress -Id 2 -ParentId 1 -Activity 'SharePoint' -Completed
}
