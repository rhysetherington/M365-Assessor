#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Private/Get-ConditionalAccessGaps.ps1 (ENT-CA-010..018, CIS 5.2.2.x) against fake Conditional Access policies: no tenant.
# Each case describes ONE policy as plain data; the builders below fill in the defaults (enabled, all users, all resources).

BeforeDiscovery {
    $MfaGrant = @{ operator = 'OR'; builtInControls = @('mfa') }
    $BlockGrant = @{ operator = 'OR'; builtInControls = @('block') }
    $script:Cases = @(
        # ENT-CA-010 MFA for all users on all resources
        @{ Name = 'CA-010 pass: MFA for all users and resources';      Id = 'ENT-CA-010'; Status = 'Pass'; Spec = @{ Grant = $MfaGrant } }
        @{ Name = 'CA-010 pass: authentication strength alone';        Id = 'ENT-CA-010'; Status = 'Pass'; Spec = @{ Grant = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = 's1' } } } }
        @{ Name = 'CA-010 gap: report-only policy';                    Id = 'ENT-CA-010'; Status = 'Gap';  Spec = @{ Grant = $MfaGrant; State = 'enabledForReportingButNotEnforced' } }
        @{ Name = 'CA-010 gap: only one group';                        Id = 'ENT-CA-010'; Status = 'Gap';  Spec = @{ Grant = $MfaGrant; Users = @{ includeUsers = @(); includeGroups = @('g1') } } }
        @{ Name = 'CA-010 gap: only some applications';                Id = 'ENT-CA-010'; Status = 'Gap';  Spec = @{ Grant = $MfaGrant; Apps = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000') } } }
        @{ Name = 'CA-010 gap: MFA only as an OR-alternative';         Id = 'ENT-CA-010'; Status = 'Gap';  Spec = @{ Grant = @{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') } } }
        # ENT-CA-013 managed device to register security information
        @{ Name = 'CA-013 pass: compliant device for registration';    Id = 'ENT-CA-013'; Status = 'Pass'; Spec = @{ Apps = @{ includeUserActions = @('urn:user:registersecurityinfo') }; Grant = @{ operator = 'OR'; builtInControls = @('compliantDevice') } } }
        @{ Name = 'CA-013 pass: compliant OR hybrid joined';           Id = 'ENT-CA-013'; Status = 'Pass'; Spec = @{ Apps = @{ includeUserActions = @('urn:user:registersecurityinfo') }; Grant = @{ operator = 'OR'; builtInControls = @('compliantDevice', 'domainJoinedDevice') } } }
        @{ Name = 'CA-013 gap: registration needs MFA, not a device';  Id = 'ENT-CA-013'; Status = 'Gap';  Spec = @{ Apps = @{ includeUserActions = @('urn:user:registersecurityinfo') }; Grant = $MfaGrant } }
        @{ Name = 'CA-013 gap: device plus another control';           Id = 'ENT-CA-013'; Status = 'Gap';  Spec = @{ Apps = @{ includeUserActions = @('urn:user:registersecurityinfo') }; Grant = @{ operator = 'OR'; builtInControls = @('compliantDevice', 'mfa') } } }
        @{ Name = 'CA-013 gap: policy is not about registration';      Id = 'ENT-CA-013'; Status = 'Gap';  Spec = @{ Grant = @{ operator = 'OR'; builtInControls = @('compliantDevice') } } }
        # ENT-CA-014 device code flow, ENT-CA-018 authentication transfer
        @{ Name = 'CA-014 pass: device code flow blocked';             Id = 'ENT-CA-014'; Status = 'Pass'; Spec = @{ Grant = $BlockGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } } }
        @{ Name = 'CA-014 pass: both flows in one comma-separated value'; Id = 'ENT-CA-014'; Status = 'Pass'; Spec = @{ Grant = $BlockGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' } } } }
        @{ Name = 'CA-014 gap: flow is covered but access is not blocked'; Id = 'ENT-CA-014'; Status = 'Gap'; Spec = @{ Grant = $MfaGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } } }
        @{ Name = 'CA-014 gap: only authentication transfer is blocked'; Id = 'ENT-CA-014'; Status = 'Gap'; Spec = @{ Grant = $BlockGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'authenticationTransfer' } } } }
        @{ Name = 'CA-014 gap: report-only';                           Id = 'ENT-CA-014'; Status = 'Gap';  Spec = @{ Grant = $BlockGrant; State = 'enabledForReportingButNotEnforced'; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } } }
        @{ Name = 'CA-018 pass: authentication transfer blocked';      Id = 'ENT-CA-018'; Status = 'Pass'; Spec = @{ Grant = $BlockGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'authenticationTransfer' } } } }
        @{ Name = 'CA-018 pass: found in a combined value';            Id = 'ENT-CA-018'; Status = 'Pass'; Spec = @{ Grant = $BlockGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' } } } }
        @{ Name = 'CA-018 gap: only device code flow is blocked';      Id = 'ENT-CA-018'; Status = 'Gap';  Spec = @{ Grant = $BlockGrant; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow' } } } }
        # ENT-CA-015 reauthentication of 7 days or less
        @{ Name = 'CA-015 pass: 7 days';                               Id = 'ENT-CA-015'; Status = 'Pass'; Spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'days'; value = 7 } } } }
        @{ Name = 'CA-015 pass: 168 hours';                            Id = 'ENT-CA-015'; Status = 'Pass'; Spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 168 } } } }
        @{ Name = 'CA-015 pass: every time';                           Id = 'ENT-CA-015'; Status = 'Pass'; Spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; frequencyInterval = 'everyTime' } } } }
        @{ Name = 'CA-015 gap: 8 days';                                Id = 'ENT-CA-015'; Status = 'Gap';  Spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'days'; value = 8 } } } }
        @{ Name = 'CA-015 gap: frequency switched off';                Id = 'ENT-CA-015'; Status = 'Gap';  Spec = @{ Session = @{ signInFrequency = @{ isEnabled = $false; type = 'days'; value = 1 } } } }
        @{ Name = 'CA-015 gap: risk-based policies are ignored';       Id = 'ENT-CA-015'; Status = 'Gap';  Spec = @{ Cond = @{ signInRiskLevels = @('high') }; Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 1 } } } }
        @{ Name = 'CA-015 gap: only some users';                       Id = 'ENT-CA-015'; Status = 'Gap';  Spec = @{ Users = @{ includeUsers = @(); includeGroups = @('g1') }; Session = @{ signInFrequency = @{ isEnabled = $true; type = 'days'; value = 1 } } } }
        # ENT-CA-017 token protection
        @{ Name = 'CA-017 pass: token protection on the three apps';   Id = 'ENT-CA-017'; Status = 'Pass'; Spec = @{ Apps = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe') }; Cond = @{ clientAppTypes = @('mobileAppsAndDesktopClients'); platforms = @{ includePlatforms = @('windows') } }; Session = @{ secureSignInSession = @{ isEnabled = $true } } } }
        @{ Name = 'CA-017 gap: Teams is missing';                      Id = 'ENT-CA-017'; Status = 'Gap';  Spec = @{ Apps = @{ includeApplications = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000') }; Cond = @{ clientAppTypes = @('mobileAppsAndDesktopClients'); platforms = @{ includePlatforms = @('windows') } }; Session = @{ secureSignInSession = @{ isEnabled = $true } } } }
        @{ Name = 'CA-017 gap: browsers are in scope';                 Id = 'ENT-CA-017'; Status = 'Gap';  Spec = @{ Cond = @{ clientAppTypes = @('browser', 'mobileAppsAndDesktopClients'); platforms = @{ includePlatforms = @('windows') } }; Session = @{ secureSignInSession = @{ isEnabled = $true } } } }
        @{ Name = 'CA-017 gap: not Windows';                           Id = 'ENT-CA-017'; Status = 'Gap';  Spec = @{ Cond = @{ clientAppTypes = @('mobileAppsAndDesktopClients'); platforms = @{ includePlatforms = @('iOS') } }; Session = @{ secureSignInSession = @{ isEnabled = $true } } } }
        # ENT-CA-016 geographic block (named locations in the fixture: loc-trusted is trusted, loc-country is untrusted)
        @{ Name = 'CA-016 pass: block everywhere except trusted locations'; Id = 'ENT-CA-016'; Status = 'Pass'; Spec = @{ Grant = $BlockGrant; Cond = @{ locations = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted') } } } }
        @{ Name = 'CA-016 pass: block an untrusted country, exclude a trusted IP range'; Id = 'ENT-CA-016'; Status = 'Pass'; Spec = @{ Grant = $BlockGrant; Cond = @{ locations = @{ includeLocations = @('loc-country'); excludeLocations = @('loc-trusted') } } } }
        @{ Name = 'CA-016 gap: no exclusions';                         Id = 'ENT-CA-016'; Status = 'Gap';  Spec = @{ Grant = $BlockGrant; Cond = @{ locations = @{ includeLocations = @('All'); excludeLocations = @() } } } }
        @{ Name = 'CA-016 gap: blocks only a trusted location';        Id = 'ENT-CA-016'; Status = 'Gap';  Spec = @{ Grant = $BlockGrant; Cond = @{ locations = @{ includeLocations = @('loc-trusted'); excludeLocations = @('loc-country') } } } }
        @{ Name = 'CA-016 gap: requires MFA instead of blocking';      Id = 'ENT-CA-016'; Status = 'Gap';  Spec = @{ Grant = $MfaGrant; Cond = @{ locations = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted') } } } }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeGraph.ps1')
    Enable-FakeGraph

    $script:RoleNames = 'Application Administrator', 'Authentication Administrator', 'Billing Administrator', 'Cloud Application Administrator',
    'Conditional Access Administrator', 'Exchange Administrator', 'Global Administrator', 'Global Reader', 'Helpdesk Administrator',
    'Password Administrator', 'Privileged Authentication Administrator', 'Privileged Role Administrator', 'Security Administrator',
    'SharePoint Administrator', 'User Administrator'
    $script:AllRoleIds = @($script:RoleNames | ForEach-Object { "role-$_" })

    # Builds one Graph policy object from a short spec (defaults: enabled, all users, all resources).
    function script:New-PolicyObject {
        param([string]$Name = 'P', [hashtable]$Spec)
        $users = if ($Spec.Users) { $Spec.Users } else { @{ includeUsers = @('All') } }
        $apps = if ($Spec.Apps) { $Spec.Apps } else { @{ includeApplications = @('All') } }
        $cond = @{ users = $users; applications = $apps }
        if ($Spec.Cond) { foreach ($k in @($Spec.Cond.Keys)) { $cond[$k] = $Spec.Cond[$k] } }
        $p = @{ displayName = $Name; state = $(if ($Spec.State) { $Spec.State } else { 'enabled' }); conditions = $cond }
        if ($Spec.Grant) { $p.grantControls = $Spec.Grant }
        if ($Spec.Session) { $p.sessionControls = $Spec.Session }
        $p
    }

    function script:Invoke-Ca {
        param([object[]]$Policies = @(), [bool]$SecurityDefaults = $false, [switch]$NoRoleTemplates, [switch]$PoliciesUnreadable)
        $templates = @($script:RoleNames | ForEach-Object { @{ id = "role-$_"; displayName = $_ } })
        $locations = @(
            @{ id = 'loc-trusted'; '@odata.type' = '#microsoft.graph.ipNamedLocation'; isTrusted = $true }
            @{ id = 'loc-country'; '@odata.type' = '#microsoft.graph.countryNamedLocation' }
        )
        $policyData = if ($PoliciesUnreadable) { { throw 'forbidden' } } else { J (@{ value = @($Policies) } | ConvertTo-Json -Depth 12) }
        $fixture = ConvertTo-Fixture ([ordered]@{
                'identitySecurityDefaultsEnforcementPolicy' = (J (@{ isEnabled = $SecurityDefaults } | ConvertTo-Json))
                'conditionalAccess/policies'                = $policyData
                'conditionalAccess/namedLocations'          = (J (@{ value = $locations } | ConvertTo-Json -Depth 6))
                'directoryRoleTemplates'                    = $(if ($NoRoleTemplates) { J '{"value":[]}' } else { J (@{ value = $templates } | ConvertTo-Json -Depth 4) })
            })
        Invoke-WithFixture -Fixture $fixture -Command 'Get-ConditionalAccessGaps'
    }

    # A policy for administrators: all required roles, all resources.
    function script:New-AdminPolicy {
        param([hashtable]$Spec, [string[]]$Roles = $script:AllRoleIds)
        $Spec.Users = @{ includeUsers = @(); includeRoles = $Roles }
        New-PolicyObject -Name 'Admins' -Spec $Spec
    }
    $script:Fido = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = 'pr'; allowedCombinations = @('fido2', 'windowsHelloForBusiness') } }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Conditional Access checks (CIS 5.2.2.x)' {
    It '<Name>' -ForEach $script:Cases {
        (Invoke-Ca -Policies @(New-PolicyObject -Spec $Spec))[$Id].Status | Should -Be $Status
    }

    It 'a tenant with no policies has a Gap for every all-user check and the admin checks' {
        $r = Invoke-Ca
        foreach ($id in 'ENT-CA-010', 'ENT-CA-011', 'ENT-CA-012', 'ENT-CA-013', 'ENT-CA-014', 'ENT-CA-015', 'ENT-CA-016', 'ENT-CA-017', 'ENT-CA-018') {
            $r[$id].Status | Should -Be 'Gap' -Because $id
        }
    }

    It 'reports each of the nine findings exactly once' {
        (Invoke-Ca).Keys.Count | Should -Be 9
    }

    It 'CA-010 explains that Security Defaults is not a Conditional Access policy' {
        (Invoke-Ca -SecurityDefaults $true)['ENT-CA-010'].Detail | Should -BeLike '*Security Defaults*not a Conditional Access policy*'
    }

    It 'CA-010 names a policy that offers MFA only as an alternative' {
        $f = (Invoke-Ca -Policies @(New-PolicyObject -Name 'MFA or device' -Spec @{ Grant = @{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') } }))['ENT-CA-010']
        $f.Detail | Should -BeLike '*operator OR*MFA or device*'
    }

    It 'a passing detail names the policy and its exclusions for review' {
        $spec = @{ Grant = @{ operator = 'OR'; builtInControls = @('mfa') }; Users = @{ includeUsers = @('All'); excludeUsers = @('bg1', 'bg2'); excludeGroups = @('g1') } }
        $f = (Invoke-Ca -Policies @(New-PolicyObject -Name 'MFA all' -Spec $spec))['ENT-CA-010']
        $f.Status | Should -Be 'Pass'
        $f.Detail | Should -BeLike '*MFA all*excludes 2 user(s), 1 group(s)*'
    }

    Context 'administrator controls (CA-011, CA-012)' {
        It 'CA-011 passes with 4 hours and a never-persistent browser for every required role' {
            $spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4 }; persistentBrowser = @{ isEnabled = $true; mode = 'never' } } }
            (Invoke-Ca -Policies @(New-AdminPolicy $spec))['ENT-CA-011'].Status | Should -Be 'Pass'
        }
        It 'CA-011 passes when the policy targets all users' {
            $spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 1 }; persistentBrowser = @{ isEnabled = $true; mode = 'never' } } }
            (Invoke-Ca -Policies @(New-PolicyObject -Spec $spec))['ENT-CA-011'].Status | Should -Be 'Pass'
        }
        It 'CA-011 gap: 5 hours is too long' {
            $spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 5 }; persistentBrowser = @{ isEnabled = $true; mode = 'never' } } }
            $f = (Invoke-Ca -Policies @(New-AdminPolicy $spec))['ENT-CA-011']
            $f.Status | Should -Be 'Gap'
            $f.Detail | Should -BeLike '*Admins*'
        }
        It 'CA-011 gap: 1 day is too long' {
            $spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'days'; value = 1 }; persistentBrowser = @{ isEnabled = $true; mode = 'never' } } }
            (Invoke-Ca -Policies @(New-AdminPolicy $spec))['ENT-CA-011'].Status | Should -Be 'Gap'
        }
        It 'CA-011 gap: the browser session may persist' {
            $spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4 } } }
            (Invoke-Ca -Policies @(New-AdminPolicy $spec))['ENT-CA-011'].Status | Should -Be 'Gap'
        }
        It 'CA-011 gap: one required role is missing' {
            $spec = @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4 }; persistentBrowser = @{ isEnabled = $true; mode = 'never' } } }
            (Invoke-Ca -Policies @(New-AdminPolicy $spec -Roles @($script:AllRoleIds | Select-Object -Skip 1)))['ENT-CA-011'].Status | Should -Be 'Gap'
        }
        It 'CA-012 passes with a phishing-resistant strength for every required role' {
            (Invoke-Ca -Policies @(New-AdminPolicy @{ Grant = $script:Fido }))['ENT-CA-012'].Status | Should -Be 'Pass'
        }
        It 'CA-012 gap: the strength also allows a weaker method, and says which policy' {
            $weak = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = 'mfa'; allowedCombinations = @('fido2', 'password,microsoftAuthenticatorPush') } }
            $f = (Invoke-Ca -Policies @(New-AdminPolicy @{ Grant = $weak }))['ENT-CA-012']
            $f.Status | Should -Be 'Gap'
            $f.Detail | Should -BeLike '*also allow weaker methods: Admins*'
        }
        It 'CA-012 gap: plain MFA is not phishing-resistant' {
            (Invoke-Ca -Policies @(New-AdminPolicy @{ Grant = @{ operator = 'OR'; builtInControls = @('mfa') } }))['ENT-CA-012'].Status | Should -Be 'Gap'
        }
        It 'CA-012 gap: one required role is missing' {
            (Invoke-Ca -Policies @(New-AdminPolicy @{ Grant = $script:Fido } -Roles @($script:AllRoleIds | Select-Object -Skip 1)))['ENT-CA-012'].Status | Should -Be 'Gap'
        }
        It 'CA-012 is NotAssessed, not a pass, when the strength methods are not returned' {
            $unknown = @{ operator = 'OR'; builtInControls = @(); authenticationStrength = @{ id = 'custom' } }
            $f = (Invoke-Ca -Policies @(New-AdminPolicy @{ Grant = $unknown }))['ENT-CA-012']
            $f.Status | Should -Be 'NotAssessed'
            $f.Detail | Should -BeLike '*could not be read*Admins*'
        }
        It 'both admin checks are NotAssessed when a required role is not in the tenant' {
            $r = Invoke-Ca -NoRoleTemplates
            $r['ENT-CA-011'].Status | Should -Be 'NotAssessed'
            $r['ENT-CA-012'].Status | Should -Be 'NotAssessed'
            $r['ENT-CA-011'].Detail | Should -BeLike '*not found*Application Administrator*'
            $r['ENT-CA-010'].Status | Should -Be 'Gap'    # the failure stays contained
        }
    }

    Context 'a tenant that meets every check' {
        BeforeAll {
            $three = @('00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe')
            $script:Healthy = @(
                (New-PolicyObject -Name 'MFA all' -Spec @{ Grant = @{ operator = 'OR'; builtInControls = @('mfa') } })
                (New-PolicyObject -Name 'Register' -Spec @{ Apps = @{ includeUserActions = @('urn:user:registersecurityinfo') }; Grant = @{ operator = 'OR'; builtInControls = @('compliantDevice') } })
                (New-PolicyObject -Name 'Flows' -Spec @{ Grant = @{ operator = 'OR'; builtInControls = @('block') }; Cond = @{ authenticationFlows = @{ transferMethods = 'deviceCodeFlow,authenticationTransfer' } } })
                (New-PolicyObject -Name 'Reauth' -Spec @{ Session = @{ signInFrequency = @{ isEnabled = $true; type = 'days'; value = 7 } } })
                (New-PolicyObject -Name 'Token' -Spec @{ Apps = @{ includeApplications = $three }; Cond = @{ clientAppTypes = @('mobileAppsAndDesktopClients'); platforms = @{ includePlatforms = @('windows') } }; Session = @{ secureSignInSession = @{ isEnabled = $true } } })
                (New-PolicyObject -Name 'Geo' -Spec @{ Grant = @{ operator = 'OR'; builtInControls = @('block') }; Cond = @{ locations = @{ includeLocations = @('All'); excludeLocations = @('AllTrusted') } } })
                (New-AdminPolicy @{ Grant = $script:Fido; Session = @{ signInFrequency = @{ isEnabled = $true; type = 'hours'; value = 4 }; persistentBrowser = @{ isEnabled = $true; mode = 'never' } } })
            )
        }
        It 'passes all nine, each reported once' {
            $r = Invoke-Ca -Policies $script:Healthy
            $r.Keys.Count | Should -Be 9
            ($r.Values | Where-Object Status -ne 'Pass' | ForEach-Object { "$($_.FindingId)=$($_.Status)" }) | Should -BeNullOrEmpty
        }
    }

    Context 'failures stay contained' {
        It 'unreadable policies make every check NotAssessed with the reason' {
            $r = Invoke-Ca -PoliciesUnreadable
            foreach ($id in 'ENT-CA-010', 'ENT-CA-011', 'ENT-CA-012', 'ENT-CA-013', 'ENT-CA-014', 'ENT-CA-015', 'ENT-CA-016', 'ENT-CA-017', 'ENT-CA-018') {
                $r[$id].Status | Should -Be 'NotAssessed' -Because $id
                $r[$id].Detail | Should -BeLike '*forbidden*'
            }
        }
    }
}
