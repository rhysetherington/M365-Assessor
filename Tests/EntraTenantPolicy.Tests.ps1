#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Private/Get-EntraTenantPolicyGaps.ps1 (CIS 5.1.x, 5.2.3.x, 5.3.5) against fake Graph responses: no tenant.
# Every case starts from a healthy baseline and changes one thing, so a failing case names the rule that broke.

BeforeDiscovery {
    $script:Cases = @(
        # ENT-POL-008 / ENT-POL-009 default user permissions
        @{ Name = 'POL-008 gap: users can create security groups';   Id = 'ENT-POL-008'; Status = 'Gap';  Set = @{ Authz = '{"defaultUserRolePermissions":{"allowedToCreateSecurityGroups":true,"allowedToReadBitlockerKeysForOwnedDevice":false}}' } }
        @{ Name = 'POL-008 NotAssessed: property not returned';      Id = 'ENT-POL-008'; Status = 'NotAssessed'; Set = @{ Authz = '{"defaultUserRolePermissions":{"allowedToReadBitlockerKeysForOwnedDevice":false}}' } }
        @{ Name = 'POL-009 gap: users can read BitLocker keys';      Id = 'ENT-POL-009'; Status = 'Gap';  Set = @{ Authz = '{"defaultUserRolePermissions":{"allowedToCreateSecurityGroups":false,"allowedToReadBitlockerKeysForOwnedDevice":true}}' } }
        @{ Name = 'POL-009 NotAssessed: property not returned';      Id = 'ENT-POL-009'; Status = 'NotAssessed'; Set = @{ Authz = '{"defaultUserRolePermissions":{"allowedToCreateSecurityGroups":false}}' } }
        # ENT-DEV-001..005 device registration (beta policy)
        @{ Name = 'DEV-001 gap: everyone can join';                  Id = 'ENT-DEV-001'; Status = 'Gap';  Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.allDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-001 pass: nobody can join';                   Id = 'ENT-DEV-001'; Status = 'Pass'; Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-001 NotAssessed: no membership type returned'; Id = 'ENT-DEV-001'; Status = 'NotAssessed'; Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-002 gap: quota 11';                           Id = 'ENT-DEV-002'; Status = 'Gap';  Set = @{ Device = '{"userDeviceQuota":11,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-002 gap: default quota 50';                   Id = 'ENT-DEV-002'; Status = 'Gap';  Set = @{ Device = '{"userDeviceQuota":50,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-002 pass: quota exactly 10';                  Id = 'ENT-DEV-002'; Status = 'Pass'; Set = @{} }
        @{ Name = 'DEV-003 gap: Global Administrators become local admins'; Id = 'ENT-DEV-003'; Status = 'Gap'; Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":true,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-004 gap: every joining user is a local admin'; Id = 'ENT-DEV-004'; Status = 'Gap'; Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.allDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-004 pass: selected users only';               Id = 'ENT-DEV-004'; Status = 'Pass'; Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.enumeratedDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}' } }
        @{ Name = 'DEV-005 gap: LAPS off';                           Id = 'ENT-DEV-005'; Status = 'Gap';  Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":false}}' } }
        @{ Name = 'DEV-005 NotAssessed: LAPS setting not returned';  Id = 'ENT-DEV-005'; Status = 'NotAssessed'; Set = @{ Device = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}}}' } }
        # ENT-AUTH-008..010 authentication method settings (beta policy)
        @{ Name = 'AUTH-008 gap: disabled';                          Id = 'ENT-AUTH-008'; Status = 'Gap'; Set = @{ Methods = '{"systemCredentialPreferences":{"state":"disabled","includeTargets":[{"id":"all_users"}]},"authenticationMethodConfigurations":[{"id":"Email","state":"disabled"},{"id":"MicrosoftAuthenticator","state":"enabled"}]}' } }
        @{ Name = 'AUTH-008 gap: Microsoft-managed default is not explicit'; Id = 'ENT-AUTH-008'; Status = 'Gap'; Set = @{ Methods = '{"systemCredentialPreferences":{"state":"default","includeTargets":[{"id":"all_users"}]},"authenticationMethodConfigurations":[{"id":"Email","state":"disabled"},{"id":"MicrosoftAuthenticator","state":"enabled"}]}' } }
        @{ Name = 'AUTH-008 gap: enabled for a group only';          Id = 'ENT-AUTH-008'; Status = 'Gap'; Set = @{ Methods = '{"systemCredentialPreferences":{"state":"enabled","includeTargets":[{"id":"group-1"}]},"authenticationMethodConfigurations":[{"id":"Email","state":"disabled"},{"id":"MicrosoftAuthenticator","state":"enabled"}]}' } }
        @{ Name = 'AUTH-008 NotAssessed: setting not returned';      Id = 'ENT-AUTH-008'; Status = 'NotAssessed'; Set = @{ Methods = '{"authenticationMethodConfigurations":[{"id":"Email","state":"disabled"},{"id":"MicrosoftAuthenticator","state":"enabled"}]}' } }
        @{ Name = 'AUTH-009 gap: Email OTP enabled';                 Id = 'ENT-AUTH-009'; Status = 'Gap'; Set = @{ Methods = '{"systemCredentialPreferences":{"state":"enabled","includeTargets":[{"id":"all_users"}]},"authenticationMethodConfigurations":[{"id":"Email","state":"enabled"},{"id":"MicrosoftAuthenticator","state":"enabled"}]}' } }
        @{ Name = 'AUTH-009 NotAssessed: no Email method returned';  Id = 'ENT-AUTH-009'; Status = 'NotAssessed'; Set = @{ Methods = '{"systemCredentialPreferences":{"state":"enabled","includeTargets":[{"id":"all_users"}]},"authenticationMethodConfigurations":[{"id":"MicrosoftAuthenticator","state":"enabled"}]}' } }
        @{ Name = 'AUTH-010 gap: companion app enabled';             Id = 'ENT-AUTH-010'; Status = 'Gap'; Set = @{ Authenticator = '{"state":"enabled","featureSettings":{"companionAppAllowedState":{"state":"enabled"}}}' } }
        @{ Name = 'AUTH-010 gap: companion app left on the Microsoft default'; Id = 'ENT-AUTH-010'; Status = 'Gap'; Set = @{ Authenticator = '{"state":"enabled","featureSettings":{"companionAppAllowedState":{"state":"default"}}}' } }
        @{ Name = 'AUTH-010 NotAssessed: setting not returned';      Id = 'ENT-AUTH-010'; Status = 'NotAssessed'; Set = @{ Authenticator = '{"state":"enabled","featureSettings":{}}' } }
        @{ Name = 'AUTH-010 pass: Authenticator method itself disabled'; Id = 'ENT-AUTH-010'; Status = 'Pass'; Set = @{ Methods = '{"systemCredentialPreferences":{"state":"enabled","includeTargets":[{"id":"all_users"}]},"authenticationMethodConfigurations":[{"id":"Email","state":"disabled"},{"id":"MicrosoftAuthenticator","state":"disabled"}]}' } }
        # ENT-PIM-002 approval for Privileged Role Administrator
        @{ Name = 'PIM-002 gap: approval not required';              Id = 'ENT-PIM-002'; Status = 'Gap';  Set = @{ Pim = '{"value":[{"policy":{"rules":[{"id":"Approval_EndUser_Assignment","setting":{"isApprovalRequired":false,"approvalStages":[]}}]}}]}' } }
        @{ Name = 'PIM-002 gap: approval required but no approvers'; Id = 'ENT-PIM-002'; Status = 'Gap';  Set = @{ Pim = '{"value":[{"policy":{"rules":[{"id":"Approval_EndUser_Assignment","setting":{"isApprovalRequired":true,"approvalStages":[{"primaryApprovers":[]}]}}]}}]}' } }
        @{ Name = 'PIM-002 NotAssessed: no policy returned';         Id = 'ENT-PIM-002'; Status = 'NotAssessed'; Set = @{ Pim = '{"value":[]}' } }
        @{ Name = 'PIM-002 NotAssessed: no approval rule';           Id = 'ENT-PIM-002'; Status = 'NotAssessed'; Set = @{ Pim = '{"value":[{"policy":{"rules":[{"id":"Expiration_EndUser_Assignment"}]}}]}' } }
    )
    $script:ServiceStrength = 'passwordAddition', 'passwordLifetime', 'customPasswordAddition'
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeGraph.ps1')
    Enable-FakeGraph

    # A tenant that meets every check; cases replace one response.
    $script:Healthy = @{
        Authz         = '{"defaultUserRolePermissions":{"allowedToCreateSecurityGroups":false,"allowedToReadBitlockerKeysForOwnedDevice":false}}'
        Device        = '{"userDeviceQuota":10,"azureADJoin":{"allowedToJoin":{"@odata.type":"#microsoft.graph.enumeratedDeviceRegistrationMembership"},"localAdmins":{"enableGlobalAdmins":false,"registeringUsers":{"@odata.type":"#microsoft.graph.noDeviceRegistrationMembership"}}},"localAdminPassword":{"isEnabled":true}}'
        Methods       = '{"systemCredentialPreferences":{"state":"enabled","includeTargets":[{"id":"all_users"}],"excludeTargets":[]},"authenticationMethodConfigurations":[{"id":"Email","state":"disabled"},{"id":"MicrosoftAuthenticator","state":"enabled"}]}'
        Authenticator = '{"state":"enabled","featureSettings":{"companionAppAllowedState":{"state":"disabled"}}}'
        Pim           = '{"value":[{"policy":{"rules":[{"id":"Approval_EndUser_Assignment","setting":{"isApprovalRequired":true,"approvalStages":[{"primaryApprovers":[{"id":"u1"}]}]}}]}}]}'
    }

    # Default app management policy with the same restrictions for applications and service principals unless Sp is given.
    function script:New-AppPolicy {
        param([bool]$Enabled = $true, $Pw, $Key, $SpPw, $SpKey)
        $none = '0001-01-01T00:00:00Z'
        if ($null -eq $Pw) { $Pw = @(@{ restrictionType = 'passwordAddition'; state = 'enabled'; restrictForAppsCreatedAfterDateTime = $none },
                @{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P180D'; restrictForAppsCreatedAfterDateTime = $none },
                @{ restrictionType = 'customPasswordAddition'; state = 'enabled'; restrictForAppsCreatedAfterDateTime = $none }) }
        if ($null -eq $Key) { $Key = @(@{ restrictionType = 'asymmetricKeyLifetime'; state = 'enabled'; maxLifetime = 'P90D'; restrictForAppsCreatedAfterDateTime = $none }) }
        if ($null -eq $SpPw) { $SpPw = $Pw }
        if ($null -eq $SpKey) { $SpKey = $Key }
        @{ isEnabled = $Enabled
            applicationRestrictions      = @{ passwordCredentials = $Pw; keyCredentials = $Key }
            servicePrincipalRestrictions = @{ passwordCredentials = $SpPw; keyCredentials = $SpKey } }
    }

    function script:Invoke-Tenant {
        param([hashtable]$Set = @{}, $App = (New-AppPolicy))
        $d = $script:Healthy.Clone()
        foreach ($k in $Set.Keys) { $d[$k] = $Set[$k] }
        # A script block stands for a refused call (it throws when the fake Graph is asked); anything else is JSON or a policy object.
        $data = { param($v) if ($v -is [scriptblock]) { $v } elseif ($v -is [string]) { J $v } else { J (ConvertTo-Json $v -Depth 20) } }
        $fixture = ConvertTo-Fixture ([ordered]@{
                'policies/authorizationPolicy'                              = (& $data $d.Authz)
                'policies/deviceRegistrationPolicy'                         = (& $data $d.Device)
                'policies/defaultAppManagementPolicy'                       = (& $data $App)
                'authenticationMethodConfigurations/microsoftAuthenticator' = (& $data $d.Authenticator)
                'policies/authenticationMethodsPolicy'                      = (& $data $d.Methods)
                'roleManagementPolicyAssignments'                           = (& $data $d.Pim)
            })
        Invoke-WithFixture -Fixture $fixture -Command 'Get-EntraTenantPolicyGaps'
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Entra tenant policy checks' {
    It '<Name>' -ForEach $script:Cases {
        (Invoke-Tenant -Set $Set)[$Id].Status | Should -Be $Status
    }

    It 'a healthy tenant passes all 15 checks, each reported once' {
        $r = Invoke-Tenant
        $r.Keys.Count | Should -Be 15
        ($r.Values | Where-Object Status -ne 'Pass' | ForEach-Object { "$($_.FindingId)=$($_.Status)" }) | Should -BeNullOrEmpty
    }

    It 'reports a refused call as NotAssessed for only the checks that need it' {
        $r = Invoke-Tenant -Set @{ Device = { throw 'forbidden' } }
        foreach ($id in 'ENT-DEV-001', 'ENT-DEV-002', 'ENT-DEV-003', 'ENT-DEV-004', 'ENT-DEV-005') { $r[$id].Status | Should -Be 'NotAssessed' -Because $id }
        $r['ENT-DEV-001'].Detail | Should -BeLike '*forbidden*'
        $r['ENT-POL-008'].Status | Should -Be 'Pass'
    }
}

Describe 'Default app management policy (ENT-APP-005..008)' {
    It 'passes when applications and service principals are both restricted' {
        $r = Invoke-Tenant
        foreach ($id in 'ENT-APP-005', 'ENT-APP-006', 'ENT-APP-007', 'ENT-APP-008') { $r[$id].Status | Should -Be 'Pass' -Because $id }
    }
    It 'is a gap on every check when the policy is switched off' {
        $r = Invoke-Tenant -App (New-AppPolicy -Enabled $false)
        foreach ($id in 'ENT-APP-005', 'ENT-APP-006', 'ENT-APP-007', 'ENT-APP-008') { $r[$id].Status | Should -Be 'Gap' -Because $id }
        $r['ENT-APP-005'].AffectedObjects | Should -BeLike '*switched off*'
    }
    It 'is a gap when there is no restriction of that type at all' {
        $r = Invoke-Tenant -App (New-AppPolicy -Pw @(@{ restrictionType = 'passwordAddition'; state = 'enabled' }))
        $r['ENT-APP-005'].Status | Should -Be 'Pass'
        $r['ENT-APP-006'].Status | Should -Be 'Gap'
        $r['ENT-APP-007'].Status | Should -Be 'Gap'
    }
    It 'is a gap when the restriction exists but is disabled' {
        $r = Invoke-Tenant -App (New-AppPolicy -Pw @(@{ restrictionType = 'passwordAddition'; state = 'disabled' }, @{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P90D' }, @{ restrictionType = 'customPasswordAddition'; state = 'enabled' }))
        $r['ENT-APP-005'].Status | Should -Be 'Gap'
        $r['ENT-APP-006'].Status | Should -Be 'Pass'
    }
    It 'is a gap when only the application half is restricted, and says which half is missing' {
        $r = Invoke-Tenant -App (New-AppPolicy -SpPw @(@{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P90D' }))
        $r['ENT-APP-005'].Status | Should -Be 'Gap'
        $r['ENT-APP-005'].AffectedObjects | Should -BeLike '*service principals*'
        $r['ENT-APP-005'].AffectedObjects | Should -Not -BeLike '*for applications*'
    }
    It 'is a gap when the restriction only starts in the future' {
        $future = @(@{ restrictionType = 'passwordAddition'; state = 'enabled'; restrictForAppsCreatedAfterDateTime = '2099-01-01T00:00:00Z' })
        (Invoke-Tenant -App (New-AppPolicy -Pw $future))['ENT-APP-005'].Status | Should -Be 'Gap'
    }
    It 'passes when the restriction applies to apps created after a date in the past' {
        $past = @(@{ restrictionType = 'passwordAddition'; state = 'enabled'; restrictForAppsCreatedAfterDateTime = '2020-01-01T00:00:00Z' })
        (Invoke-Tenant -App (New-AppPolicy -Pw $past))['ENT-APP-005'].Status | Should -Be 'Pass'
    }
    It 'is a gap when the lifetime is longer than 180 days, and names the value' {
        $long = @(@{ restrictionType = 'passwordLifetime'; state = 'enabled'; maxLifetime = 'P1Y' })
        $f = (Invoke-Tenant -App (New-AppPolicy -Pw $long))['ENT-APP-006']
        $f.Status | Should -Be 'Gap'
        $f.AffectedObjects | Should -BeLike '*P1Y*'
    }
    It 'is a gap when a lifetime restriction sets no maximum' {
        $none = @(@{ restrictionType = 'passwordLifetime'; state = 'enabled' })
        (Invoke-Tenant -App (New-AppPolicy -Pw $none))['ENT-APP-006'].Status | Should -Be 'Gap'
    }
    It 'checks the certificate lifetime on the key credentials' {
        $long = @(@{ restrictionType = 'asymmetricKeyLifetime'; state = 'enabled'; maxLifetime = 'P365D' })
        (Invoke-Tenant -App (New-AppPolicy -Key $long))['ENT-APP-008'].Status | Should -Be 'Gap'
    }
    It 'is NotAssessed when the policy cannot be read' {
        (Invoke-Tenant -App { throw 'forbidden' })['ENT-APP-005'].Status | Should -Be 'NotAssessed'
    }
}

Describe 'Test-IsoDurationAtMostDays' {
    It '<Duration> against <Max> days is <Expected>' -ForEach @(
        @{ Duration = 'P180D'; Max = 180; Expected = $true }
        @{ Duration = 'P181D'; Max = 180; Expected = $false }
        @{ Duration = 'P90D'; Max = 180; Expected = $true }
        @{ Duration = 'P6M'; Max = 180; Expected = $true }
        @{ Duration = 'P7M'; Max = 180; Expected = $false }
        @{ Duration = 'P1Y'; Max = 180; Expected = $false }
        @{ Duration = 'PT24H'; Max = 1; Expected = $true }
    ) {
        InModuleScope M365GapAssessment -Parameters @{ D = $Duration; M = $Max } { Test-IsoDurationAtMostDays -Duration $D -MaxDays $M } | Should -Be $Expected
    }
}
