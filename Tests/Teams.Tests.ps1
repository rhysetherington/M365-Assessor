#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Invoke-TeamsChecks (TMS-001..TMS-012) with fake Teams cmdlets: no tenant, no session. Each case starts from a tenant that meets every
# check and changes one setting, so a failing case names the rule that broke.

BeforeDiscovery {
    $script:Cases = @(
        # TMS-012 external meeting chat (CIS 8.5.8)
        @{ Name = 'TMS-012 gap: external meeting chat is on';           Id = 'TMS-012'; Status = 'Gap';  Patch = @{ Meeting = @{ AllowExternalNonTrustedMeetingChat = $true } } }
        @{ Name = 'TMS-012 NotAssessed (not a pass): property not returned'; Id = 'TMS-012'; Status = 'NotAssessed'; Patch = @{ Meeting = @{ AllowExternalNonTrustedMeetingChat = $null } } }
        # Existing checks: one gap each, and the healthy tenant passes them all (see the Describe below)
        @{ Name = 'TMS-001 gap: federation open to all domains';         Id = 'TMS-001'; Status = 'Gap';  Patch = @{ Federation = @{ AllowedDomains = 'AllowAllKnownDomains' } } }
        @{ Name = 'TMS-002 gap: unmanaged Teams accounts allowed';        Id = 'TMS-002'; Status = 'Gap';  Patch = @{ Federation = @{ AllowTeamsConsumer = $true } } }
        @{ Name = 'TMS-002 gap: unmanaged Teams users can start chats';   Id = 'TMS-002'; Status = 'Gap';  Patch = @{ Federation = @{ AllowTeamsConsumerInbound = $true } } }
        @{ Name = 'TMS-003 gap: trial tenants not blocked';               Id = 'TMS-003'; Status = 'Gap';  Patch = @{ Federation = @{ ExternalAccessWithTrialTenants = 'Allowed' } } }
        @{ Name = 'TMS-004 gap: anonymous users can join';                Id = 'TMS-004'; Status = 'Gap';  Patch = @{ Meeting = @{ AllowAnonymousUsersToJoinMeeting = $true } } }
        @{ Name = 'TMS-004 gap: anonymous users can start';               Id = 'TMS-004'; Status = 'Gap';  Patch = @{ Meeting = @{ AllowAnonymousUsersToStartMeeting = $true } } }
        @{ Name = 'TMS-005 gap: everyone bypasses the lobby';             Id = 'TMS-005'; Status = 'Gap';  Patch = @{ Meeting = @{ AutoAdmittedUsers = 'Everyone' } } }
        @{ Name = 'TMS-005 gap: dial-in callers bypass the lobby';        Id = 'TMS-005'; Status = 'Gap';  Patch = @{ Meeting = @{ AllowPSTNUsersToBypassLobby = $true } } }
        @{ Name = 'TMS-006 gap: anonymous users can use meeting chat';    Id = 'TMS-006'; Status = 'Gap';  Patch = @{ Meeting = @{ MeetingChatEnabledType = 'Enabled' } } }
        @{ Name = 'TMS-007 gap: anyone can present';                      Id = 'TMS-007'; Status = 'Gap';  Patch = @{ Meeting = @{ DesignatedPresenterRoleMode = 'EveryoneUserOverride' } } }
        @{ Name = 'TMS-007 gap: external participants can take control';  Id = 'TMS-007'; Status = 'Gap';  Patch = @{ Meeting = @{ AllowExternalParticipantGiveRequestControl = $true } } }
        @{ Name = 'TMS-011 gap: cloud recording on by default';           Id = 'TMS-011'; Status = 'Gap';  Patch = @{ Meeting = @{ AllowCloudRecording = $true } } }
        @{ Name = 'TMS-008 gap: Dropbox allowed';                         Id = 'TMS-008'; Status = 'Gap';  Patch = @{ Client = @{ AllowDropBox = $true } } }
        @{ Name = 'TMS-009 gap: email into channels allowed';             Id = 'TMS-009'; Status = 'Gap';  Patch = @{ Client = @{ AllowEmailIntoChannel = $true } } }
        @{ Name = 'TMS-010 gap: users cannot report security concerns';   Id = 'TMS-010'; Status = 'Gap';  Patch = @{ Messaging = @{ AllowSecurityEndUserReporting = $false } } }
        # An unreadable setting is never a pass: NotAssessed unless a setting that WAS returned already makes it a Gap
        @{ Name = 'TMS-001 NotAssessed: AllowFederatedUsers not returned';          Id = 'TMS-001'; Status = 'NotAssessed'; Patch = @{ Federation = @{ AllowFederatedUsers = $null } } }
        @{ Name = 'TMS-001 NotAssessed: federation on but AllowedDomains not returned'; Id = 'TMS-001'; Status = 'NotAssessed'; Patch = @{ Federation = @{ AllowedDomains = $null } } }
        @{ Name = 'TMS-001 pass: federation off, so AllowedDomains does not matter'; Id = 'TMS-001'; Status = 'Pass'; Patch = @{ Federation = @{ AllowFederatedUsers = $false; AllowedDomains = $null } } }
        @{ Name = 'TMS-002 NotAssessed: both settings not returned';                Id = 'TMS-002'; Status = 'NotAssessed'; Patch = @{ Federation = @{ AllowTeamsConsumer = $null; AllowTeamsConsumerInbound = $null } } }
        @{ Name = 'TMS-002 NotAssessed: one off, the other not returned';           Id = 'TMS-002'; Status = 'NotAssessed'; Patch = @{ Federation = @{ AllowTeamsConsumerInbound = $null } } }
        @{ Name = 'TMS-002 gap: one on, the other not returned';                    Id = 'TMS-002'; Status = 'Gap'; Patch = @{ Federation = @{ AllowTeamsConsumer = $true; AllowTeamsConsumerInbound = $null } } }
        @{ Name = 'TMS-003 NotAssessed: trial tenant setting not returned';         Id = 'TMS-003'; Status = 'NotAssessed'; Patch = @{ Federation = @{ ExternalAccessWithTrialTenants = $null } } }
        @{ Name = 'TMS-004 NotAssessed: one setting not returned';                  Id = 'TMS-004'; Status = 'NotAssessed'; Patch = @{ Meeting = @{ AllowAnonymousUsersToJoinMeeting = $null } } }
        @{ Name = 'TMS-004 gap: one on, the other not returned';                    Id = 'TMS-004'; Status = 'Gap'; Patch = @{ Meeting = @{ AllowAnonymousUsersToJoinMeeting = $true; AllowAnonymousUsersToStartMeeting = $null } } }
        @{ Name = 'TMS-005 NotAssessed: who bypasses the lobby not returned';       Id = 'TMS-005'; Status = 'NotAssessed'; Patch = @{ Meeting = @{ AutoAdmittedUsers = $null } } }
        @{ Name = 'TMS-005 gap: everyone bypasses, dial-in setting not returned';   Id = 'TMS-005'; Status = 'Gap'; Patch = @{ Meeting = @{ AutoAdmittedUsers = 'Everyone'; AllowPSTNUsersToBypassLobby = $null } } }
        @{ Name = 'TMS-005 gap: dial-in bypass on, lobby setting not returned';     Id = 'TMS-005'; Status = 'Gap'; Patch = @{ Meeting = @{ AutoAdmittedUsers = $null; AllowPSTNUsersToBypassLobby = $true } } }
        @{ Name = 'TMS-006 NotAssessed: meeting chat type not returned';            Id = 'TMS-006'; Status = 'NotAssessed'; Patch = @{ Meeting = @{ MeetingChatEnabledType = $null } } }
        @{ Name = 'TMS-007 NotAssessed: presenter mode not returned';               Id = 'TMS-007'; Status = 'NotAssessed'; Patch = @{ Meeting = @{ DesignatedPresenterRoleMode = $null } } }
        @{ Name = 'TMS-007 gap: external control on, presenter mode not returned';  Id = 'TMS-007'; Status = 'Gap'; Patch = @{ Meeting = @{ DesignatedPresenterRoleMode = $null; AllowExternalParticipantGiveRequestControl = $true } } }
        @{ Name = 'TMS-011 NotAssessed: cloud recording setting not returned';      Id = 'TMS-011'; Status = 'NotAssessed'; Patch = @{ Meeting = @{ AllowCloudRecording = $null } } }
        @{ Name = 'TMS-008 NotAssessed: one provider setting not returned';         Id = 'TMS-008'; Status = 'NotAssessed'; Patch = @{ Client = @{ AllowEgnyte = $null } } }
        @{ Name = 'TMS-008 gap: Dropbox on, another provider not returned';         Id = 'TMS-008'; Status = 'Gap'; Patch = @{ Client = @{ AllowDropBox = $true; AllowEgnyte = $null } } }
        @{ Name = 'TMS-009 NotAssessed: email into channels not returned';          Id = 'TMS-009'; Status = 'NotAssessed'; Patch = @{ Client = @{ AllowEmailIntoChannel = $null } } }
        @{ Name = 'TMS-010 NotAssessed: reporting setting not returned (was a gap)'; Id = 'TMS-010'; Status = 'NotAssessed'; Patch = @{ Messaging = @{ AllowSecurityEndUserReporting = $null } } }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeCmdlets.ps1')

    # A tenant that meets every Teams check.
    function script:Get-Healthy {
        @{
            Federation = @{ AllowFederatedUsers = $true; AllowedDomains = [pscustomobject]@{ AllowedDomain = @([pscustomobject]@{ Domain = 'partner.com' }) }
                AllowTeamsConsumer = $false; AllowTeamsConsumerInbound = $false; ExternalAccessWithTrialTenants = 'Blocked' }
            Meeting    = @{ AllowAnonymousUsersToJoinMeeting = $false; AllowAnonymousUsersToStartMeeting = $false; AutoAdmittedUsers = 'EveryoneInCompanyExcludingGuests'
                AllowPSTNUsersToBypassLobby = $false; MeetingChatEnabledType = 'EnabledExceptAnonymous'; DesignatedPresenterRoleMode = 'OrganizerOnlyUserOverride'
                AllowExternalParticipantGiveRequestControl = $false; AllowCloudRecording = $false; AllowExternalNonTrustedMeetingChat = $false }
            Client     = @{ AllowDropBox = $false; AllowBox = $false; AllowGoogleDrive = $false; AllowShareFile = $false; AllowEgnyte = $false; AllowEmailIntoChannel = $false }
            Messaging  = @{ AllowSecurityEndUserReporting = $true }
        }
    }

    function script:Invoke-Teams {
        param([hashtable]$Patch = @{}, [hashtable]$Replace = @{})
        $t = Get-Healthy
        foreach ($section in $Patch.Keys) { foreach ($k in $Patch[$section].Keys) { $t[$section][$k] = $Patch[$section][$k] } }
        foreach ($section in $Replace.Keys) { $t[$section] = $Replace[$section] }
        $obj = { param($h) [pscustomobject]$h }
        Invoke-WithCmdlets -Command 'Invoke-TeamsChecks' -Data @{
            'Get-CsTenantFederationConfiguration' = (& $obj $t.Federation)
            'Get-CsTeamsMeetingPolicy'            = (& $obj $t.Meeting)
            'Get-CsTeamsClientConfiguration'      = (& $obj $t.Client)
            'Get-CsTeamsMessagingPolicy'          = (& $obj $t.Messaging)
        }
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Teams checks' {
    It '<Name>' -ForEach $script:Cases {
        (Invoke-Teams -Patch $Patch)[$Id].Status | Should -Be $Status
    }

    It 'a healthy tenant passes all 12 checks, each reported once' {
        $r = Invoke-Teams
        $r.Keys.Count | Should -Be 12
        ($r.Values | Where-Object Status -ne 'Pass' | ForEach-Object { "$($_.FindingId)=$($_.Status)" }) | Should -BeNullOrEmpty
    }

    It 'a NotAssessed result names the setting that was not returned' {
        $f = (Invoke-Teams -Patch @{ Meeting = @{ AllowCloudRecording = $null } })['TMS-011']
        $f.Status | Should -Be 'NotAssessed'
        $f.Detail | Should -BeLike '*AllowCloudRecording was not returned*cannot be shown to be safe*'
    }

    It 'a Gap still says when another setting could not be read' {
        $f = (Invoke-Teams -Patch @{ Client = @{ AllowDropBox = $true; AllowEgnyte = $null } })['TMS-008']
        $f.Status | Should -Be 'Gap'
        @($f.AffectedObjects) | Should -Be @('DropBox')
        $f.Detail | Should -BeLike '*AllowEgnyte was not returned and could not be evaluated*'
    }

    It 'TMS-012 names the setting in its detail' {
        (Invoke-Teams -Patch @{ Meeting = @{ AllowExternalNonTrustedMeetingChat = $true } })['TMS-012'].Detail | Should -BeLike '*AllowExternalNonTrustedMeetingChat = True*'
    }

    It 'TMS-012 passes when external meeting chat is off' {
        (Invoke-Teams)['TMS-012'].Status | Should -Be 'Pass'
    }

    It 'a refused meeting-policy cmdlet makes only the meeting checks NotAssessed' {
        $r = Invoke-WithCmdlets -Command 'Invoke-TeamsChecks' -Data @{
            'Get-CsTenantFederationConfiguration' = [pscustomobject]((Get-Healthy).Federation)
            'Get-CsTeamsMeetingPolicy'            = { throw 'forbidden' }
            'Get-CsTeamsClientConfiguration'      = [pscustomobject]((Get-Healthy).Client)
            'Get-CsTeamsMessagingPolicy'          = [pscustomobject]((Get-Healthy).Messaging)
        }
        foreach ($id in 'TMS-004', 'TMS-005', 'TMS-006', 'TMS-007', 'TMS-011', 'TMS-012') { $r[$id].Status | Should -Be 'NotAssessed' -Because $id }
        $r['TMS-012'].Detail | Should -BeLike '*forbidden*'
        $r['TMS-001'].Status | Should -Be 'Pass'
        $r['TMS-010'].Status | Should -Be 'Pass'
    }
}
