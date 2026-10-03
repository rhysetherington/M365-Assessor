function Get-TeamsGaps {
    <#
    .SYNOPSIS
        Microsoft Teams collector (opt-in domain 'Teams'): external access, anonymous and lobby settings, presenter and chat controls.
    .DESCRIPTION
        Needs the MicrosoftTeams module and a separate interactive sign-in. Only Get-* cmdlets are used, against the Global (org-wide) policies.
        If the module is missing or the connection fails, every check is reported NotAssessed rather than aborting the run.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    $ids = 'TMS-001', 'TMS-002', 'TMS-003', 'TMS-004', 'TMS-005', 'TMS-006', 'TMS-007', 'TMS-008', 'TMS-009', 'TMS-010', 'TMS-011'

    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        foreach ($id in $ids) { New-Finding -Id $id -Status NotAssessed -Detail 'MicrosoftTeams module is not installed (Install-Module MicrosoftTeams -Scope CurrentUser).' }
        return
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Teams' -Status 'Connecting' -PercentComplete 5
    try {
        Import-Module MicrosoftTeams -ErrorAction Stop
        $conn = @{ ErrorAction = 'Stop' }
        if ($TenantId) { $conn.TenantId = $TenantId }
        # The Windows broker (WAM) is not available on macOS/Linux and fails with a kernel32.dll load error.
        if (-not $IsWindows -and (Get-Command Connect-MicrosoftTeams).Parameters.ContainsKey('DisableWAM')) { $conn.DisableWAM = $true }
        $null = Connect-MicrosoftTeams @conn
    }
    catch {
        foreach ($id in $ids) { New-Finding -Id $id -Status NotAssessed -Detail "Could not connect to Microsoft Teams: $((($_.Exception.Message -split '\r?\n')[0]))" }
        return
    }

    try {
        Invoke-Collector -Name 'Teams external access' -FindingIds 'TMS-001', 'TMS-002', 'TMS-003' -Script {
            $fed = Get-CsTenantFederationConfiguration
            $domains = @($fed.AllowedDomains.AllowedDomain | Where-Object { $_ })
            # AllowedDomains is an "AllowAllKnownDomains" object when federation is open, or a list of specific domains.
            $open = $fed.AllowFederatedUsers -and ($fed.AllowedDomains -is [string] -or $fed.AllowedDomains.GetType().Name -match 'AllowAll' -or -not $domains.Count)
            New-Finding -Id 'TMS-001' -Status $(if ($open) { 'Gap' } else { 'Pass' }) `
                -AffectedObjects $(if ($open) { 'External federation allows all domains' } else { @() }) `
                -Detail "AllowFederatedUsers = $($fed.AllowFederatedUsers); $($domains.Count) specifically allowed domain(s)."
            $consumer = @(if ($fed.AllowTeamsConsumer) { 'Users can communicate with unmanaged Teams (personal) accounts' }; if ($fed.AllowTeamsConsumerInbound) { 'Unmanaged Teams users can initiate conversations' })
            New-Finding -Id 'TMS-002' -Status $(if ($consumer.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $consumer `
                -Detail "AllowTeamsConsumer = $($fed.AllowTeamsConsumer); AllowTeamsConsumerInbound = $($fed.AllowTeamsConsumerInbound)."
            New-Finding -Id 'TMS-003' -Status $(if ($fed.ExternalAccessWithTrialTenants -eq 'Blocked') { 'Pass' } else { 'Gap' }) `
                -Detail "ExternalAccessWithTrialTenants = $($fed.ExternalAccessWithTrialTenants)."
        }

        Invoke-Collector -Name 'Teams meetings' -FindingIds 'TMS-004', 'TMS-005', 'TMS-006', 'TMS-007', 'TMS-011' -Script {
            $m = Get-CsTeamsMeetingPolicy -Identity Global
            $anon = @(if ($m.AllowAnonymousUsersToJoinMeeting) { 'Anonymous users can join meetings' }; if ($m.AllowAnonymousUsersToStartMeeting) { 'Anonymous users can start meetings' })
            New-Finding -Id 'TMS-004' -Status $(if ($anon.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $anon `
                -Detail "Global meeting policy: AllowAnonymousUsersToJoinMeeting = $($m.AllowAnonymousUsersToJoinMeeting); AllowAnonymousUsersToStartMeeting = $($m.AllowAnonymousUsersToStartMeeting)."

            $lobby = @(if ($m.AutoAdmittedUsers -notin 'InvitedUsers', 'EveryoneInCompanyExcludingGuests', 'OrganizerOnly') { "Who can bypass the lobby: $($m.AutoAdmittedUsers)" }
                if ($m.AllowPSTNUsersToBypassLobby) { 'Dial-in callers can bypass the lobby' })
            New-Finding -Id 'TMS-005' -Status $(if ($lobby.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $lobby `
                -Detail "AutoAdmittedUsers = $($m.AutoAdmittedUsers); AllowPSTNUsersToBypassLobby = $($m.AllowPSTNUsersToBypassLobby)."

            $chatOk = $m.MeetingChatEnabledType -in 'EnabledExceptAnonymous', 'EnabledInMeetingOnlyForAllExceptAnonymous', 'Disabled'
            New-Finding -Id 'TMS-006' -Status $(if ($chatOk) { 'Pass' } else { 'Gap' }) `
                -Detail "MeetingChatEnabledType = $($m.MeetingChatEnabledType). Anonymous users should not be able to use meeting chat."

            $present = @(if ($m.DesignatedPresenterRoleMode -ne 'OrganizerOnlyUserOverride') { "Who can present: $($m.DesignatedPresenterRoleMode)" }
                if ($m.AllowExternalParticipantGiveRequestControl) { 'External participants can give or request control' })
            New-Finding -Id 'TMS-007' -Status $(if ($present.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $present `
                -Detail "DesignatedPresenterRoleMode = $($m.DesignatedPresenterRoleMode); AllowExternalParticipantGiveRequestControl = $($m.AllowExternalParticipantGiveRequestControl)."

            New-Finding -Id 'TMS-011' -Status $(if ($m.AllowCloudRecording) { 'Gap' } else { 'Pass' }) `
                -Detail "AllowCloudRecording = $($m.AllowCloudRecording). CIS recommends recording off by default and enabled per organiser where needed."
        }

        Invoke-Collector -Name 'Teams client settings' -FindingIds 'TMS-008', 'TMS-009' -Script {
            $c = Get-CsTeamsClientConfiguration -Identity Global
            $storage = @(foreach ($p in 'AllowDropBox', 'AllowBox', 'AllowGoogleDrive', 'AllowShareFile', 'AllowEgnyte') { if ($c.$p) { $p -replace '^Allow', '' } })
            New-Finding -Id 'TMS-008' -Status $(if ($storage.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $storage `
                -Detail 'Third-party cloud storage providers enabled for file sharing in Teams.'
            New-Finding -Id 'TMS-009' -Status $(if ($c.AllowEmailIntoChannel) { 'Gap' } else { 'Pass' }) `
                -Detail "AllowEmailIntoChannel = $($c.AllowEmailIntoChannel)."
        }

        Invoke-Collector -Name 'Teams messaging' -FindingIds 'TMS-010' -Script {
            $msg = Get-CsTeamsMessagingPolicy -Identity Global
            New-Finding -Id 'TMS-010' -Status $(if ($msg.AllowSecurityEndUserReporting) { 'Pass' } else { 'Gap' }) `
                -Detail "AllowSecurityEndUserReporting = $($msg.AllowSecurityEndUserReporting). Lets users report suspicious messages to the security team."
        }
    }
    finally {
        $null = Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Teams' -Completed
    }
}
