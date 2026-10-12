function Get-TeamsGaps {
    <#
    .SYNOPSIS
        Microsoft Teams collector (opt-in domain 'Teams'): external access, anonymous and lobby settings, presenter and chat controls, external meeting chat.
    .DESCRIPTION
        Needs the MicrosoftTeams module and a separate interactive sign-in. Only Get-* cmdlets are used, against the Global (org-wide) policies.
        If the module is missing or the connection fails, every check is reported NotAssessed rather than aborting the run.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    $ids = 'TMS-001', 'TMS-002', 'TMS-003', 'TMS-004', 'TMS-005', 'TMS-006', 'TMS-007', 'TMS-008', 'TMS-009', 'TMS-010', 'TMS-011', 'TMS-012'

    $cloud = Get-CloudEnvironment
    if (-not $cloud.TeamsSupported) {
        foreach ($id in $ids) { New-Finding -Id $id -Status NotAssessed -Detail "The Teams checks are not available for the $($cloud.Display) cloud: this tool does not know a supported Teams PowerShell environment for it." }
        return
    }

    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        foreach ($id in $ids) { New-Finding -Id $id -Status NotAssessed -Detail 'MicrosoftTeams module is not installed (Install-Module MicrosoftTeams -Scope CurrentUser).' }
        return
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Teams' -Status 'Connecting' -PercentComplete 5
    try {
        Import-Module MicrosoftTeams -ErrorAction Stop
        $conn = @{ ErrorAction = 'Stop' }
        if ($TenantId) { $conn.TenantId = $TenantId }
        if ($cloud.TeamsName) { $conn.TeamsEnvironmentName = $cloud.TeamsName }
        # The Windows broker (WAM) is not available on macOS/Linux and fails with a kernel32.dll load error.
        if (-not $IsWindows -and (Get-Command Connect-MicrosoftTeams).Parameters.ContainsKey('DisableWAM')) { $conn.DisableWAM = $true }
        $teamsConnection = Connect-MicrosoftTeams @conn
        Register-SessionIdentity -Service 'Microsoft Teams' -Account (Get-TeamsSessionAccount -Connection $teamsConnection)
    }
    catch {
        foreach ($id in $ids) { New-Finding -Id $id -Status NotAssessed -Detail "Could not connect to Microsoft Teams: $((($_.Exception.Message -split '\r?\n')[0]))" }
        return
    }

    try { Invoke-TeamsChecks }
    finally {
        $null = Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
        Write-Progress -Id 2 -ParentId 1 -Activity 'Microsoft Teams' -Completed
    }
}

function Get-UnreturnedProperties {
    # Names from the list that the object did not return (null or absent). Such a setting is unknown, which is not the same as off.
    param($Object, [string[]]$Names)
    @($Names | Where-Object { $null -eq $Object.$_ })
}

function New-SettingFinding {
    <#
    .SYNOPSIS
        One finding from a setting check. A Gap when a setting that WAS returned is wrong; a Pass only when every setting the check
        needs was returned and is fine; otherwise NotAssessed, because a setting that could not be read cannot be shown to be safe.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][bool]$Gap,
        [string[]]$Affected = @(),
        [string[]]$Unreturned = @(),
        [Parameter(Mandatory)][string]$Detail
    )
    if ($Gap) {
        $text = if ($Unreturned.Count) { "$Detail $($Unreturned -join ', ') was not returned and could not be evaluated." } else { $Detail }
        New-Finding -Id $Id -Status Gap -AffectedObjects $Affected -Detail $text
    }
    elseif ($Unreturned.Count) {
        New-Finding -Id $Id -Status NotAssessed -Detail "$Detail $($Unreturned -join ', ') was not returned, so the setting cannot be shown to be safe."
    }
    else {
        New-Finding -Id $Id -Status Pass -AffectedObjects $Affected -Detail $Detail
    }
}

function Invoke-TeamsChecks {
    # The checks themselves: assumes a Teams PowerShell session is already open (tests supply fake cmdlets instead).
    [CmdletBinding()]
    param()

    Invoke-Collector -Name 'Teams external access' -FindingIds 'TMS-001', 'TMS-002', 'TMS-003' -Script {
        $fed = Get-CsTenantFederationConfiguration

        # TMS-001: federation open to all domains. AllowedDomains only matters while federation is on.
        $federationOn = [bool]$fed.AllowFederatedUsers
        $unknown = @(Get-UnreturnedProperties $fed 'AllowFederatedUsers')
        if ($federationOn) { $unknown += Get-UnreturnedProperties $fed 'AllowedDomains' }
        $domains = @($fed.AllowedDomains.AllowedDomain | Where-Object { $_ })
        # AllowedDomains is an "AllowAllKnownDomains" object when federation is open, or a list of specific domains.
        $open = $federationOn -and $null -ne $fed.AllowedDomains -and ($fed.AllowedDomains -is [string] -or $fed.AllowedDomains.GetType().Name -match 'AllowAll' -or -not $domains.Count)
        New-SettingFinding -Id 'TMS-001' -Gap $open -Unreturned $unknown `
            -Affected $(if ($open) { 'External federation allows all domains' } else { @() }) `
            -Detail "AllowFederatedUsers = $($fed.AllowFederatedUsers); $($domains.Count) specifically allowed domain(s)."

        # TMS-002: unmanaged (personal) Teams accounts.
        $consumer = @(if ($fed.AllowTeamsConsumer) { 'Users can communicate with unmanaged Teams (personal) accounts' }; if ($fed.AllowTeamsConsumerInbound) { 'Unmanaged Teams users can initiate conversations' })
        New-SettingFinding -Id 'TMS-002' -Gap ($consumer.Count -gt 0) -Affected $consumer -Unreturned (Get-UnreturnedProperties $fed 'AllowTeamsConsumer', 'AllowTeamsConsumerInbound') `
            -Detail "AllowTeamsConsumer = $($fed.AllowTeamsConsumer); AllowTeamsConsumerInbound = $($fed.AllowTeamsConsumerInbound)."

        # TMS-003: trial tenants.
        $trial = $fed.ExternalAccessWithTrialTenants
        New-SettingFinding -Id 'TMS-003' -Gap ($null -ne $trial -and "$trial" -ne 'Blocked') -Unreturned (Get-UnreturnedProperties $fed 'ExternalAccessWithTrialTenants') `
            -Detail "ExternalAccessWithTrialTenants = $trial."
    }

    Invoke-Collector -Name 'Teams meetings' -FindingIds 'TMS-004', 'TMS-005', 'TMS-006', 'TMS-007', 'TMS-011' -Script {
        $m = Get-CsTeamsMeetingPolicy -Identity Global

        $anon = @(if ($m.AllowAnonymousUsersToJoinMeeting) { 'Anonymous users can join meetings' }; if ($m.AllowAnonymousUsersToStartMeeting) { 'Anonymous users can start meetings' })
        New-SettingFinding -Id 'TMS-004' -Gap ($anon.Count -gt 0) -Affected $anon -Unreturned (Get-UnreturnedProperties $m 'AllowAnonymousUsersToJoinMeeting', 'AllowAnonymousUsersToStartMeeting') `
            -Detail "Global meeting policy: AllowAnonymousUsersToJoinMeeting = $($m.AllowAnonymousUsersToJoinMeeting); AllowAnonymousUsersToStartMeeting = $($m.AllowAnonymousUsersToStartMeeting)."

        $lobby = @(if ($null -ne $m.AutoAdmittedUsers -and $m.AutoAdmittedUsers -notin 'InvitedUsers', 'EveryoneInCompanyExcludingGuests', 'OrganizerOnly') { "Who can bypass the lobby: $($m.AutoAdmittedUsers)" }
            if ($m.AllowPSTNUsersToBypassLobby) { 'Dial-in callers can bypass the lobby' })
        New-SettingFinding -Id 'TMS-005' -Gap ($lobby.Count -gt 0) -Affected $lobby -Unreturned (Get-UnreturnedProperties $m 'AutoAdmittedUsers', 'AllowPSTNUsersToBypassLobby') `
            -Detail "AutoAdmittedUsers = $($m.AutoAdmittedUsers); AllowPSTNUsersToBypassLobby = $($m.AllowPSTNUsersToBypassLobby)."

        $chatBad = $null -ne $m.MeetingChatEnabledType -and $m.MeetingChatEnabledType -notin 'EnabledExceptAnonymous', 'EnabledInMeetingOnlyForAllExceptAnonymous', 'Disabled'
        New-SettingFinding -Id 'TMS-006' -Gap $chatBad -Unreturned (Get-UnreturnedProperties $m 'MeetingChatEnabledType') `
            -Detail "MeetingChatEnabledType = $($m.MeetingChatEnabledType). Anonymous users should not be able to use meeting chat."

        $present = @(if ($null -ne $m.DesignatedPresenterRoleMode -and $m.DesignatedPresenterRoleMode -ne 'OrganizerOnlyUserOverride') { "Who can present: $($m.DesignatedPresenterRoleMode)" }
            if ($m.AllowExternalParticipantGiveRequestControl) { 'External participants can give or request control' })
        New-SettingFinding -Id 'TMS-007' -Gap ($present.Count -gt 0) -Affected $present -Unreturned (Get-UnreturnedProperties $m 'DesignatedPresenterRoleMode', 'AllowExternalParticipantGiveRequestControl') `
            -Detail "DesignatedPresenterRoleMode = $($m.DesignatedPresenterRoleMode); AllowExternalParticipantGiveRequestControl = $($m.AllowExternalParticipantGiveRequestControl)."

        New-SettingFinding -Id 'TMS-011' -Gap ([bool]$m.AllowCloudRecording) -Unreturned (Get-UnreturnedProperties $m 'AllowCloudRecording') `
            -Detail "AllowCloudRecording = $($m.AllowCloudRecording). CIS recommends recording off by default and enabled per organiser where needed."
    }

    Invoke-Collector -Name 'Teams client settings' -FindingIds 'TMS-008', 'TMS-009' -Script {
        $c = Get-CsTeamsClientConfiguration -Identity Global
        $providers = 'AllowDropBox', 'AllowBox', 'AllowGoogleDrive', 'AllowShareFile', 'AllowEgnyte'
        $storage = @(foreach ($p in $providers) { if ($c.$p) { $p -replace '^Allow', '' } })
        New-SettingFinding -Id 'TMS-008' -Gap ($storage.Count -gt 0) -Affected $storage -Unreturned (Get-UnreturnedProperties $c $providers) `
            -Detail 'Third-party cloud storage providers enabled for file sharing in Teams.'
        New-SettingFinding -Id 'TMS-009' -Gap ([bool]$c.AllowEmailIntoChannel) -Unreturned (Get-UnreturnedProperties $c 'AllowEmailIntoChannel') `
            -Detail "AllowEmailIntoChannel = $($c.AllowEmailIntoChannel)."
    }

    Invoke-Collector -Name 'Teams messaging' -FindingIds 'TMS-010' -Script {
        $msg = Get-CsTeamsMessagingPolicy -Identity Global
        # Reporting should be ON: here the bad state is False, and an unreturned value is unknown.
        New-SettingFinding -Id 'TMS-010' -Gap ($null -ne $msg.AllowSecurityEndUserReporting -and -not $msg.AllowSecurityEndUserReporting) -Unreturned (Get-UnreturnedProperties $msg 'AllowSecurityEndUserReporting') `
            -Detail "AllowSecurityEndUserReporting = $($msg.AllowSecurityEndUserReporting). Lets users report suspicious messages to the security team."
    }

    Invoke-Collector -Name 'Teams external meeting chat' -FindingIds 'TMS-012' -Script {
        $m = Get-CsTeamsMeetingPolicy -Identity Global
        New-SettingFinding -Id 'TMS-012' -Gap ([bool]$m.AllowExternalNonTrustedMeetingChat) -Unreturned (Get-UnreturnedProperties $m 'AllowExternalNonTrustedMeetingChat') `
            -Detail "Global meeting policy: AllowExternalNonTrustedMeetingChat = $($m.AllowExternalNonTrustedMeetingChat). When true, people from untrusted organizations can chat in your meetings."
    }
}
