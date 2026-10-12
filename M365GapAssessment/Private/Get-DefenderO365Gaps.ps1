$script:DefenderO365Ids = 'DFO-001', 'DFO-002', 'DFO-003', 'DFO-004', 'DFO-005', 'DFO-006', 'DFO-007',
    'DFO-008', 'DFO-009', 'DFO-010', 'DFO-011', 'DFO-012', 'DFO-013', 'DFO-014'

function Get-DefenderO365Gaps {
    <#
    .SYNOPSIS
        Defender for Office 365 / Exchange Online Protection collector (opt-in domain 'DefenderO365').
    .DESCRIPTION
        Policy depth that complements the basic anti-phishing and Safe Links checks in the ExchangeOnline domain: Safe Attachments,
        anti-malware, anti-spam, preset security policies, mail flow rules that bypass filtering, connection filtering, external
        sender tagging, Teams ZAP and user reporting. Uses the Exchange Online session shared with the ExchangeOnline domain.
        Only Get-* cmdlets are used. A failed connection reports every check as NotAssessed.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Status 'Connecting' -PercentComplete 5
    $session = Start-ExchangeSession -TenantId $TenantId
    if (-not $session.Ready) {
        foreach ($id in $script:DefenderO365Ids) { New-Finding -Id $id -Status NotAssessed -Detail $session.Error }
        Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Completed
        return
    }
    try { Invoke-DefenderO365Checks }
    finally { Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Completed }
}

function Invoke-DefenderO365Checks {
    # The checks themselves: assumes an Exchange Online session is already open (tests supply fake cmdlets instead).
    [CmdletBinding()]
    param()

    $licenceHint = 'Defender for Office 365 may not be licensed'
    $enabledRule = { param($r) "$($r.State)" -eq 'Enabled' }

    # --- Safe Attachments ---------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Status 'Safe Attachments and Safe Links' -PercentComplete 10
    Invoke-Collector -Name 'Safe Attachments policies' -FindingIds 'DFO-001' -Script {
        Assert-Cmdlet Get-SafeAttachmentPolicy $licenceHint
        $policies = @(Get-SafeAttachmentPolicy)
        # A policy only protects mailboxes when a rule assigns it; the built-in protection policy applies to everyone.
        $assigned = @()
        if (Get-Command Get-SafeAttachmentRule -ErrorAction SilentlyContinue) {
            $assigned = @(Get-SafeAttachmentRule | Where-Object { "$($_.State)" -eq 'Enabled' } | ForEach-Object { $_.SafeAttachmentPolicy })
        }
        $strong = @($policies | Where-Object { $_.Enable -and "$($_.Action)" -in 'Block', 'Replace', 'DynamicDelivery' -and ($_.Name -like 'Built-In*' -or $_.Name -in $assigned) })
        $weak = @($policies | Where-Object { $_ -notin $strong } | ForEach-Object { "$($_.Name) - enabled=$($_.Enable), action=$($_.Action)" })
        New-Finding -Id 'DFO-001' -Status $(if ($strong.Count) { 'Pass' } else { 'Gap' }) -AffectedObjects $(if ($strong.Count) { @() } else { $weak }) `
            -Detail "$($strong.Count) of $($policies.Count) Safe Attachments policy(ies) are enabled, assigned and block or replace malicious attachments."
    }

    Invoke-Collector -Name 'Safe Attachments for SharePoint, OneDrive and Teams' -FindingIds 'DFO-002' -Script {
        Assert-Cmdlet Get-AtpPolicyForO365 $licenceHint
        $atp = @(Get-AtpPolicyForO365) | Select-Object -First 1
        $issues = @()
        if (-not $atp.EnableATPForSPOTeamsODB) { $issues += 'Safe Attachments is not turned on for SharePoint, OneDrive and Microsoft Teams' }
        if ($atp.AllowSafeDocsOpen) { $issues += 'Users can click through Protected View to open files Safe Documents flagged as malicious' }
        New-Finding -Id 'DFO-002' -Status $(if ($issues.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $issues `
            -Detail "EnableATPForSPOTeamsODB = $($atp.EnableATPForSPOTeamsODB); EnableSafeDocs = $($atp.EnableSafeDocs); AllowSafeDocsOpen = $($atp.AllowSafeDocsOpen)."
    }

    Invoke-Collector -Name 'Safe Links settings' -FindingIds 'DFO-003' -Script {
        Assert-Cmdlet Get-SafeLinksPolicy $licenceHint
        $inUse = @(Get-SafeLinksPolicy | Where-Object { $_.EnableSafeLinksForEmail -or $_.EnableSafeLinksForOffice -or $_.EnableSafeLinksForTeams })
        $issues = foreach ($p in $inUse) {
            if ($p.DoNotAllowClickThrough -eq $false) { "$($p.Name) - users can click through to the original URL" }
            if ($p.DoNotTrackUserClicks -eq $true) { "$($p.Name) - user clicks are not tracked" }
            if ($p.ScanUrls -eq $false) { "$($p.Name) - real-time URL scanning is off" }
        }
        New-Finding -Id 'DFO-003' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues) `
            -Detail "$($inUse.Count) Safe Links policy(ies) in use were checked for click-through, click tracking and real-time URL scanning."
    }

    # --- Anti-malware, anti-spam ----------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Status 'Anti-malware and anti-spam' -PercentComplete 35
    Invoke-Collector -Name 'Anti-malware policies' -FindingIds 'DFO-004' -Script {
        $malware = @(Get-MalwareFilterPolicy)
        $issues = foreach ($p in $malware) {
            if (-not $p.EnableFileFilter) { "$($p.Name) - common attachment types filter is off" }
            if (-not $p.ZapEnabled) { "$($p.Name) - zero-hour auto purge for malware is off" }
        }
        New-Finding -Id 'DFO-004' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues) `
            -Detail "$($malware.Count) anti-malware policy(ies) were checked for the common attachment types filter and zero-hour auto purge."
    }

    Invoke-Collector -Name 'Inbound anti-spam allow lists' -FindingIds 'DFO-005' -Script {
        $spam = @(Get-HostedContentFilterPolicy)
        $lists = foreach ($p in $spam) {
            $senders = @($p.AllowedSenders | Where-Object { $_ })
            $domains = @($p.AllowedSenderDomains | Where-Object { $_ })
            if ($senders.Count) { "$($p.Name) - $($senders.Count) allowed sender(s)" }
            if ($domains.Count) { "$($p.Name) - $($domains.Count) allowed sender domain(s): $(($domains | Select-Object -First 5) -join ', ')" }
        }
        New-Finding -Id 'DFO-005' -Status $(if (@($lists).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($lists) `
            -Detail "$($spam.Count) anti-spam policy(ies) were checked for allowed sender and domain lists, which let mail skip spam filtering (including spoofed mail)."
    }

    Invoke-Collector -Name 'Inbound anti-spam thresholds and actions' -FindingIds 'DFO-006' -Script {
        $spamPolicies = @(Get-HostedContentFilterPolicy)
        $issues = foreach ($p in $spamPolicies) {
            if ($null -ne $p.BulkThreshold -and [int]$p.BulkThreshold -gt 6) { "$($p.Name) - bulk complaint level threshold is $($p.BulkThreshold) (6 or lower recommended)" }
            if ("$($p.HighConfidencePhishAction)" -and "$($p.HighConfidencePhishAction)" -ne 'Quarantine') { "$($p.Name) - high confidence phishing action is $($p.HighConfidencePhishAction) (Quarantine recommended)" }
            if ($p.PhishZapEnabled -eq $false) { "$($p.Name) - zero-hour auto purge for phishing is off" }
            if ($p.SpamZapEnabled -eq $false) { "$($p.Name) - zero-hour auto purge for spam is off" }
        }
        New-Finding -Id 'DFO-006' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues) `
            -Detail "$($spamPolicies.Count) anti-spam policy(ies) were checked for bulk threshold (6 or lower), high-confidence phishing action (Quarantine) and zero-hour auto purge."
    }

    Invoke-Collector -Name 'Outbound spam notifications' -FindingIds 'DFO-007' -Script {
        $silent = @(Get-HostedOutboundSpamFilterPolicy | Where-Object { -not $_.NotifyOutboundSpam } | ForEach-Object { "$($_.Name) - admins are not notified when a user is blocked for sending spam" })
        New-Finding -Id 'DFO-007' -Status $(if ($silent.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $silent `
            -Detail 'A compromised account sending spam is blocked silently unless an administrator is notified.'
    }

    # --- Preset security policies -----------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Status 'Preset security policies and mail flow' -PercentComplete 60
    Invoke-Collector -Name 'Preset security policies' -FindingIds 'DFO-008' -Script {
        Assert-Cmdlet Get-EOPProtectionPolicyRule 'Exchange Online Protection cmdlets unavailable'
        $rules = @(Get-EOPProtectionPolicyRule)
        if (Get-Command Get-ATPProtectionPolicyRule -ErrorAction SilentlyContinue) { $rules += @(Get-ATPProtectionPolicyRule) }
        $active = @($rules | Where-Object { $_.Name -match 'Standard Preset|Strict Preset' -and (& $enabledRule $_) } | ForEach-Object { $_.Name } | Sort-Object -Unique)
        New-Finding -Id 'DFO-008' -Status $(if ($active.Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($active.Count) { "Enabled preset policies: $($active -join ', ')." } else { 'Neither the Standard nor the Strict preset security policy is enabled; protection relies on the default and custom policies.' })
    }

    # --- Mail flow rules and connection filter -------------------------------------------------------------
    Invoke-Collector -Name 'Mail flow rules that bypass filtering' -FindingIds 'DFO-009', 'DFO-010' -Script {
        $rules = @(Get-TransportRule | Where-Object { & $enabledRule $_ })
        $bypass = @($rules | Where-Object { $null -ne $_.SetSCL -and "$($_.SetSCL)" -in '-1', 'Bypass spam filtering' } | ForEach-Object { $_.Name })
        New-Finding -Id 'DFO-009' -Status $(if ($bypass.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $bypass `
            -Detail "Enabled mail flow rules that set the spam confidence level to -1 (bypass spam filtering); $($rules.Count) enabled rule(s) reviewed."
        $redirect = @($rules | Where-Object { (Test-HasItems $_.RedirectMessageTo) -or (Test-HasItems $_.BlindCopyTo) } | ForEach-Object { $_.Name })
        New-Finding -Id 'DFO-010' -Status $(if ($redirect.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $redirect `
            -Detail "$($rules.Count) enabled mail flow rule(s) were checked for redirect or blind-copy actions. Review any listed: forwarding rules are a common data-exfiltration path."
    }

    Invoke-Collector -Name 'Connection filter' -FindingIds 'DFO-011' -Script {
        $connection = @(Get-HostedConnectionFilterPolicy)
        $issues = foreach ($p in $connection) {
            $ips = @($p.IPAllowList | Where-Object { $_ })
            if ($ips.Count) { "$($p.Name) - $($ips.Count) IP address(es) on the allow list: $(($ips | Select-Object -First 5) -join ', ')" }
            if ($p.EnableSafeList) { "$($p.Name) - Microsoft's dynamic safe list is enabled" }
        }
        New-Finding -Id 'DFO-011' -Status $(if (@($issues).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($issues) `
            -Detail "$($connection.Count) connection filter policy(ies) were checked for IP allow lists and the safe list, which let mail from those sources skip spam filtering."
    }

    # --- User-facing protections ---------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Defender for Office 365' -Status 'External sender tag, Teams and reporting' -PercentComplete 80
    Invoke-Collector -Name 'External sender identification' -FindingIds 'DFO-012' -Script {
        Assert-Cmdlet Get-ExternalInOutlook 'cmdlet unavailable in this tenant'
        $ext = @(Get-ExternalInOutlook) | Select-Object -First 1
        New-Finding -Id 'DFO-012' -Status $(if ($ext.Enabled) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($ext.Enabled) { @() } else { @('External sender tag in Outlook is disabled') }) -Detail "Enabled = $($ext.Enabled)."
    }

    Invoke-Collector -Name 'Teams zero-hour auto purge' -FindingIds 'DFO-013' -Script {
        Assert-Cmdlet Get-TeamsProtectionPolicy $licenceHint
        $tpp = @(Get-TeamsProtectionPolicy) | Select-Object -First 1
        New-Finding -Id 'DFO-013' -Status $(if ($tpp.ZapEnabled) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($tpp.ZapEnabled) { @() } else { @('Zero-hour auto purge for Microsoft Teams messages is off') }) -Detail "ZapEnabled = $($tpp.ZapEnabled)."
    }

    Invoke-Collector -Name 'User message reporting' -FindingIds 'DFO-014' -Script {
        Assert-Cmdlet Get-ReportSubmissionPolicy 'cmdlet unavailable in this tenant'
        $rsp = @(Get-ReportSubmissionPolicy) | Select-Object -First 1
        # An absent or empty property means the setting could not be read; that must not be reported as a pass.
        if ($null -eq $rsp -or $null -eq $rsp.EnableReportToMicrosoft) {
            $names = if ($rsp) { ($rsp.PSObject.Properties.Name | Select-Object -First 12) -join ', ' } else { 'no policy object returned' }
            New-Finding -Id 'DFO-014' -Status NotAssessed -Detail "EnableReportToMicrosoft was not returned by Get-ReportSubmissionPolicy, so user reporting could not be evaluated. Properties seen: $names."
        }
        else {
            New-Finding -Id 'DFO-014' -Status $(if ($rsp.EnableReportToMicrosoft -eq $false) { 'Gap' } else { 'Pass' }) `
                -AffectedObjects $(if ($rsp.EnableReportToMicrosoft -eq $false) { @('Users cannot report suspicious messages to Microsoft') } else { @() }) `
                -Detail "EnableReportToMicrosoft = $($rsp.EnableReportToMicrosoft)."
        }
    }
}
