#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Get-TeamsGaps: the connection, the hand-over to Invoke-TeamsChecks, and the NotAssessed fallbacks. The Teams module and every cmdlet
# are fakes defined inside the module, so no test can reach a tenant or open a sign-in prompt. Kept in its own file because the
# fakes replace Get-Module and Import-Module for the whole module session.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeCmdlets.ps1')
    InModuleScope M365GapAssessment {
        $script:ModuleInstalled = $true
        $script:ConnectFails = $false
        function script:Get-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) if ($script:ModuleInstalled) { [pscustomobject]@{ Name = 'MicrosoftTeams'; Version = [version]'6.0.0' } } }
        function script:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Connect-MicrosoftTeams { param([Parameter(ValueFromRemainingArguments = $true)]$R) if ($script:ConnectFails) { throw "boom`nsecond line" }; [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'reader@contoso.com' } } }
        function script:Disconnect-MicrosoftTeams { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
    }
    $script:Healthy = @{
        'Get-CsTenantFederationConfiguration' = [pscustomobject]@{ AllowFederatedUsers = $true; AllowedDomains = [pscustomobject]@{ AllowedDomain = @([pscustomobject]@{ Domain = 'partner.com' }) }; AllowTeamsConsumer = $false; AllowTeamsConsumerInbound = $false; ExternalAccessWithTrialTenants = 'Blocked' }
        'Get-CsTeamsMeetingPolicy'            = [pscustomobject]@{ AllowAnonymousUsersToJoinMeeting = $false; AllowAnonymousUsersToStartMeeting = $false; AutoAdmittedUsers = 'EveryoneInCompanyExcludingGuests'; AllowPSTNUsersToBypassLobby = $false; MeetingChatEnabledType = 'EnabledExceptAnonymous'; DesignatedPresenterRoleMode = 'OrganizerOnlyUserOverride'; AllowExternalParticipantGiveRequestControl = $false; AllowCloudRecording = $false; AllowExternalNonTrustedMeetingChat = $false }
        'Get-CsTeamsClientConfiguration'      = [pscustomobject]@{ AllowDropBox = $false; AllowBox = $false; AllowGoogleDrive = $false; AllowShareFile = $false; AllowEgnyte = $false; AllowEmailIntoChannel = $false }
        'Get-CsTeamsMessagingPolicy'          = [pscustomobject]@{ AllowSecurityEndUserReporting = $true }
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Get-TeamsGaps' {
    BeforeEach { InModuleScope M365GapAssessment { $script:ModuleInstalled = $true; $script:ConnectFails = $false } }

    It 'runs all 12 checks once connected' {
        $r = Invoke-WithCmdlets -Data $script:Healthy -Command 'Get-TeamsGaps'
        $r.Keys.Count | Should -Be 12
        $r['TMS-012'].Status | Should -Be 'Pass'
    }
    It 'reports all 12 checks NotAssessed when the module is not installed' {
        InModuleScope M365GapAssessment { $script:ModuleInstalled = $false }
        $r = Invoke-WithCmdlets -Data $script:Healthy -Command 'Get-TeamsGaps'
        $r.Keys.Count | Should -Be 12
        $r['TMS-012'].Status | Should -Be 'NotAssessed'
        $r['TMS-012'].Detail | Should -BeLike '*MicrosoftTeams module is not installed*'
    }
    It 'reports all 12 checks NotAssessed with the first line of the error when the connection fails' {
        InModuleScope M365GapAssessment { $script:ConnectFails = $true }
        $r = Invoke-WithCmdlets -Data $script:Healthy -Command 'Get-TeamsGaps'
        $r.Keys.Count | Should -Be 12
        $r['TMS-012'].Detail | Should -BeLike 'Could not connect to Microsoft Teams: boom'
    }
}
