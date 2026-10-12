function Get-ExchangeOnlineGaps {
    <#
    .SYNOPSIS
        Exchange Online collector (opt-in domain 'ExchangeOnline'): forwarding, audit, modern auth, SMTP AUTH, shared mailbox sign-in, anti-phish, Safe Links, Outlook on the web policies, add-ins, direct send, MailTips, mailbox audit.
    .DESCRIPTION
        Needs the ExchangeOnlineManagement module and a separate interactive sign-in (shared with the DefenderO365 domain). Only Get-* cmdlets are used.
        If the module is missing or the connection fails, every check is reported NotAssessed rather than aborting the run.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    $ids = 'EXO-001', 'EXO-002', 'EXO-003', 'EXO-004', 'EXO-005', 'EXO-006', 'EXO-007', 'EXO-008', 'EXO-009', 'EXO-010', 'EXO-011', 'EXO-012', 'EXO-013', 'EXO-014'

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

        Invoke-Collector -Name 'Exchange organization (CIS)' -FindingIds 'EXO-009', 'EXO-010' -Script {
            $org = Get-OrganizationConfig
            # A property the cmdlet does not return is unknown, never a pass.
            if ($null -eq $org.RejectDirectSend) { New-Finding -Id 'EXO-009' -Status NotAssessed -Detail 'Get-OrganizationConfig did not return RejectDirectSend.' }
            else {
                New-Finding -Id 'EXO-009' -Status $(if ($org.RejectDirectSend) { 'Pass' } else { 'Gap' }) -Detail "RejectDirectSend = $($org.RejectDirectSend). When false, anyone can send mail as your domain straight to your mailboxes without authenticating."
            }
            $tips = 'MailTipsAllTipsEnabled', 'MailTipsExternalRecipientsTipsEnabled', 'MailTipsGroupMetricsEnabled'
            $unknownTips = @($tips | Where-Object { $null -eq $org.$_ })
            if ($unknownTips.Count) { New-Finding -Id 'EXO-010' -Status NotAssessed -Detail "Get-OrganizationConfig did not return: $($unknownTips -join ', ')." }
            else {
                $off = @($tips | Where-Object { -not $org.$_ })
                New-Finding -Id 'EXO-010' -Status $(if ($off.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($off | ForEach-Object { "$_ = False" }) `
                    -Detail "MailTips: $(($tips | ForEach-Object { "$_ = $($org.$_)" }) -join '; ')."
            }
        }

        Invoke-Collector -Name 'Outlook on the web personal accounts' -FindingIds 'EXO-011' -Script {
            $default = @(Get-OwaMailboxPolicy | Where-Object { $_.IsDefault }) | Select-Object -First 1
            if (-not $default) { throw 'No default Outlook on the web mailbox policy was returned.' }
            $props = 'PersonalAccountsEnabled', 'PersonalAccountCalendarsEnabled'
            # Exchange Online can return an empty PersonalAccountsEnabled. A setting that is on is a Gap whatever the other one says;
            # a pass needs both to be read and off.
            $unknown = @($props | Where-Object { $null -eq $default.$_ })
            $on = @($props | Where-Object { $null -ne $default.$_ -and $default.$_ })
            $state = ($props | ForEach-Object { "$_ = $(if ($null -eq $default.$_) { 'not returned' } else { $default.$_ })" }) -join '; '
            if ($on.Count) {
                New-Finding -Id 'EXO-011' -Status Gap -AffectedObjects @($on | ForEach-Object { "$($default.Name): $_ = True" }) `
                    -Detail "Default Outlook on the web policy '$($default.Name)': $state.$(if ($unknown.Count) { " $($unknown -join ', ') was not returned and could not be evaluated." })"
            }
            elseif ($unknown.Count) {
                New-Finding -Id 'EXO-011' -Status NotAssessed -Detail "Default Outlook on the web policy '$($default.Name)': $state. $($unknown -join ', ') was not returned, so the policy cannot be shown to block personal accounts."
            }
            else {
                New-Finding -Id 'EXO-011' -Status Pass -Detail "Default Outlook on the web policy '$($default.Name)': $state."
            }
        }

        Invoke-Collector -Name 'Outlook add-in installation' -FindingIds 'EXO-012' -Script {
            $default = @(Get-RoleAssignmentPolicy | Where-Object { $_.IsDefault }) | Select-Object -First 1
            if (-not $default) { throw 'No default role assignment policy was returned.' }
            $addInRoles = 'My Custom Apps', 'My Marketplace Apps', 'My ReadWriteMailbox Apps'
            $assigned = @($default.AssignedRoles | Where-Object { $_ -in $addInRoles })
            New-Finding -Id 'EXO-012' -Status $(if ($assigned.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($assigned | ForEach-Object { "$($default.Name): $_" }) `
                -Detail "Default role assignment policy '$($default.Name)' $(if ($assigned.Count) { "lets users install add-ins through: $($assigned -join ', ')" } else { 'assigns none of the add-in roles' })."
        }

        Invoke-Collector -Name 'Mailbox audit bypass' -FindingIds 'EXO-013' -Script {
            $bypass = @(Get-MailboxAuditBypassAssociation -ResultSize Unlimited -WarningAction SilentlyContinue | Where-Object { $_.AuditBypassEnabled -eq $true } | ForEach-Object { [string]$_.Name })
            New-Finding -Id 'EXO-013' -Status $(if ($bypass.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $bypass `
                -Detail "$($bypass.Count) account(s) are excluded from mailbox auditing (AuditBypassEnabled). Accounts on bypass leave no audit trail for what they read or change."
        }

        Invoke-Collector -Name 'Mailbox audit actions' -FindingIds 'EXO-014' -Script {
            # Actions CIS expects to be audited for each logon type, in a user mailbox.
            $expected = @{
                AuditAdmin    = 'ApplyRecord', 'Copy', 'Create', 'FolderBind', 'HardDelete', 'MailItemsAccessed', 'Move', 'MoveToDeletedItems', 'SendAs', 'SendOnBehalf', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateFolderPermissions', 'UpdateInboxRules'
                AuditDelegate = 'ApplyRecord', 'Create', 'FolderBind', 'HardDelete', 'Move', 'MailItemsAccessed', 'MoveToDeletedItems', 'SendAs', 'SendOnBehalf', 'SoftDelete', 'Update', 'UpdateFolderPermissions', 'UpdateInboxRules'
                AuditOwner    = 'ApplyRecord', 'Create', 'HardDelete', 'MailboxLogin', 'Move', 'MailItemsAccessed', 'MoveToDeletedItems', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateFolderPermissions', 'UpdateInboxRules'
            }
            $mailboxes = @(Get-EXOMailbox -PropertySets Audit, Minimum -ResultSize Unlimited | Where-Object { "$($_.RecipientTypeDetails)" -eq 'UserMailbox' })
            $probe = $mailboxes | Select-Object -First 1
            $missingProps = if ($probe) { @(@($expected.Keys) + 'AuditEnabled' | Where-Object { $null -eq $probe.PSObject.Properties[$_] }) } else { @() }
            if ($missingProps.Count) { throw "Get-EXOMailbox did not return: $($missingProps -join ', ')." }
            $bad = foreach ($m in $mailboxes) {
                $problems = @()
                if (-not $m.AuditEnabled) { $problems += 'auditing is off' }
                foreach ($type in 'AuditAdmin', 'AuditDelegate', 'AuditOwner') {
                    $missing = @($expected[$type] | Where-Object { $_ -notin @($m.$type) })
                    if ($missing.Count) { $problems += "$type missing $($missing -join ', ')" }
                }
                if ($problems.Count) { "$($m.UserPrincipalName) - $($problems -join '; ')" }
            }
            $shown = @($bad | Select-Object -First 100)
            if (@($bad).Count -gt 100) { $shown += "... and $(@($bad).Count - 100) more" }
            New-Finding -Id 'EXO-014' -Status $(if (@($bad).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $shown `
                -Detail "$(@($bad).Count) of $($mailboxes.Count) user mailbox(es) do not audit every action CIS expects (the default set for owner, delegate and admin actions)."
        }
    }
    finally {
        # The Exchange session is shared with the DefenderO365 domain and closed by Invoke-M365SecurityReview.
        Write-Progress -Id 2 -ParentId 1 -Activity 'Exchange Online' -Completed
    }
}
