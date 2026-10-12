function Get-ExchangeOnlineGaps {
    <#
    .SYNOPSIS
        Exchange Online collector (opt-in domain 'ExchangeOnline'): forwarding, audit, modern auth, SMTP AUTH, shared mailbox sign-in, anti-phish, Safe Links, Outlook on the web storage providers.
    .DESCRIPTION
        Needs the ExchangeOnlineManagement module and a separate interactive sign-in (shared with the DefenderO365 domain). Only Get-* cmdlets are used.
        If the module is missing or the connection fails, every check is reported NotAssessed rather than aborting the run.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    $ids = 'EXO-001', 'EXO-002', 'EXO-003', 'EXO-004', 'EXO-005', 'EXO-006', 'EXO-007', 'EXO-008'

    Write-Progress -Id 2 -ParentId 1 -Activity 'Exchange Online' -Status 'Connecting' -PercentComplete 5
    $session = Start-ExchangeSession -TenantId $TenantId
    if (-not $session.Ready) {
        foreach ($id in $ids) { New-Finding -Id $id -Status NotAssessed -Detail $session.Error }
        Write-Progress -Id 2 -ParentId 1 -Activity 'Exchange Online' -Completed
        return
    }

    try {
        Invoke-Collector -Name 'Exchange organization' -FindingIds 'EXO-002', 'EXO-003', 'EXO-004' -Script {
            $org = Get-OrganizationConfig
            New-Finding -Id 'EXO-002' -Status $(if ($org.AuditDisabled) { 'Gap' } else { 'Pass' }) `
                -Detail "Organization-wide mailbox auditing AuditDisabled = $($org.AuditDisabled)."
            New-Finding -Id 'EXO-003' -Status $(if ($org.OAuth2ClientProfileEnabled) { 'Pass' } else { 'Gap' }) `
                -Detail "Modern authentication (OAuth2ClientProfileEnabled) = $($org.OAuth2ClientProfileEnabled)."
            $transport = Get-TransportConfig
            New-Finding -Id 'EXO-004' -Status $(if ($transport.SmtpClientAuthenticationDisabled) { 'Pass' } else { 'Gap' }) `
                -Detail "Tenant-wide SMTP AUTH disabled = $($transport.SmtpClientAuthenticationDisabled). Individual mailboxes can still override this."
        }

        Invoke-Collector -Name 'Mail forwarding' -FindingIds 'EXO-001' -Script {
            $policies = @(Get-HostedOutboundSpamFilterPolicy | Where-Object { $_.AutoForwardingMode -ne 'Off' })
            $forwarded = @(Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, ForwardingAddress |
                    Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
            $items = @($policies | ForEach-Object { "Outbound spam policy '$($_.Name)' - AutoForwardingMode $($_.AutoForwardingMode)" }) +
            @($forwarded | ForEach-Object { "$($_.UserPrincipalName) - forwards to $(if ($_.ForwardingSmtpAddress) { $_.ForwardingSmtpAddress } else { $_.ForwardingAddress })" })
            New-Finding -Id 'EXO-001' -Status $(if ($items.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $items `
                -Detail 'Outbound auto-forwarding not blocked by policy, or mailboxes with forwarding configured.'
        }

        Invoke-Collector -Name 'Shared mailbox sign-in' -FindingIds 'EXO-005' -Script {
            $shared = @(Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties ExternalDirectoryObjectId)
            $open = foreach ($m in $shared) {
                $u = Invoke-GraphRequestWithRetry -Uri "/v1.0/users/$($m.ExternalDirectoryObjectId)`?`$select=accountEnabled,userPrincipalName"
                if ($u.accountEnabled) { $u.userPrincipalName }
            }
            New-Finding -Id 'EXO-005' -Status $(if (@($open).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($open) `
                -Detail "Shared mailboxes whose user account is enabled for sign-in ($($shared.Count) shared mailboxes reviewed)."
        }

        Invoke-Collector -Name 'Anti-phishing' -FindingIds 'EXO-006' -Script {
            $custom = @(Get-AntiPhishPolicy | Where-Object { -not $_.IsDefault -and $_.Enabled })
            New-Finding -Id 'EXO-006' -Status $(if ($custom.Count) { 'Pass' } else { 'Gap' }) `
                -Detail "$($custom.Count) enabled custom anti-phishing policy(ies). Only the built-in default policy applies when there are none."
        }

        Invoke-Collector -Name 'Safe Links' -FindingIds 'EXO-007' -Script {
            if (-not (Get-Command Get-SafeLinksPolicy -ErrorAction SilentlyContinue)) { throw 'Safe Links cmdlets unavailable (Defender for Office 365 not licensed).' }
            $links = @(Get-SafeLinksPolicy | Where-Object { $_.EnableSafeLinksForEmail -and $_.EnableSafeLinksForOffice -and $_.EnableSafeLinksForTeams })
            New-Finding -Id 'EXO-007' -Status $(if ($links.Count) { 'Pass' } else { 'Gap' }) `
                -Detail "$($links.Count) Safe Links policy(ies) cover email, Office apps and Teams."
        }

        Invoke-Collector -Name 'Outlook on the web policies' -FindingIds 'EXO-008' -Script {
            $policies = @(Get-OwaMailboxPolicy)
            if (-not $policies.Count) { throw 'No Outlook on the web mailbox policy was returned.' }
            # A policy that does not report the setting is unknown, never a pass.
            $unknown = @($policies | Where-Object { $null -eq $_.AdditionalStorageProvidersAvailable })
            if ($unknown.Count) { throw "AdditionalStorageProvidersAvailable was not returned for: $(($unknown | ForEach-Object { $_.Name }) -join ', ')." }
            $open = @($policies | Where-Object { $_.AdditionalStorageProvidersAvailable } | ForEach-Object { $_.Name })
            New-Finding -Id 'EXO-008' -Status $(if ($open.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $open `
                -Detail "$($open.Count) of $($policies.Count) Outlook on the web policy(ies) allow additional storage providers (Dropbox, Box, Google Drive and similar)."
        }
    }
    finally {
        # The Exchange session is shared with the DefenderO365 domain and closed by Invoke-M365SecurityReview.
        Write-Progress -Id 2 -ParentId 1 -Activity 'Exchange Online' -Completed
    }
}
