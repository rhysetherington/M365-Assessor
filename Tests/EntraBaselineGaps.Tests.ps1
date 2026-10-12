#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Offline tests for Private/Get-EntraBaselineGaps.ps1. The two Graph request functions are replaced inside the module with a
# fixture-driven fake, so nothing touches a tenant. A fixture is a list of { Match, Data }: the first entry whose Match text
# appears in the requested URI wins; Data may be a scriptblock to simulate a Graph error.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop

    InModuleScope M365GapAssessment {
        $script:Fixture = @()
        function script:Resolve-Fixture {
            param($Uri)
            foreach ($e in $script:Fixture) {
                if ($Uri.Contains($e.Match)) { if ($e.Data -is [scriptblock]) { return (& $e.Data) } else { return $e.Data } }
            }
            throw "No fixture for $Uri"
        }
        function script:Invoke-GraphRequestWithRetry { param($Uri, $Headers, $MaxRetries) Resolve-Fixture $Uri }
        function script:Get-GraphPagedResult {
            param($Uri, $Headers, $MaxItems)
            $r = Resolve-Fixture $Uri
            if ($null -ne $r.value) { @($r.value) } else { $r }
        }
    }

    function script:J($Json) { $Json | ConvertFrom-Json }

    # Healthy tenant by default; each test overrides only what it is about.
    function script:New-Fixture {
        param([hashtable]$Override = @{})
        $base = [ordered]@{
            'identitySecurityDefaultsEnforcementPolicy' = (J '{"isEnabled":true}')
            'authorizationPolicy'                       = (J '{"allowedToUseSSPR":true}')
            'groupSettings'                             = (J '{"value":[]}')
            '/domains'                                  = (J '{"value":[{"id":"contoso.com","isVerified":true,"authenticationType":"Managed","passwordValidityPeriodInDays":2147483647}]}')
            'groups?$filter'                            = (J '{"value":[]}')
            '/members'                                  = (J '{"value":[]}')
            'conditionalAccess/policies'                = (J '{"value":[]}')
            'roleAssignmentScheduleInstances'           = (J '{"value":[]}')
        }
        foreach ($k in $Override.Keys) { $base[$k] = $Override[$k] }
        @($base.Keys | ForEach-Object { [pscustomobject]@{ Match = $_; Data = $base[$_] } })
    }

    # Runs the collector against a fixture and returns findings keyed by ID.
    function script:Invoke-Baseline {
        param([hashtable]$Override = @{})
        $fixture = New-Fixture -Override $Override
        $findings = InModuleScope M365GapAssessment -Parameters @{ F = $fixture } { $script:Fixture = $F; Get-EntraBaselineGaps 3>$null }
        $byId = @{}
        foreach ($f in $findings) { $byId[$f.FindingId] = $f }
        $byId
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'ENT-POL-006 Security Defaults / baseline MFA' {
    It 'passes when Security Defaults is enabled' {
        (Invoke-Baseline)['ENT-POL-006'].Status | Should -Be 'Pass'
    }
    It 'fails when Security Defaults is off and no all-user MFA policy exists' {
        $r = Invoke-Baseline @{ 'identitySecurityDefaultsEnforcementPolicy' = (J '{"isEnabled":false}') }
        $r['ENT-POL-006'].Status | Should -Be 'Gap'
    }
    It 'passes when Security Defaults is off but Conditional Access requires MFA for all users and apps' {
        $ca = J '{"value":[{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]}'
        $r = Invoke-Baseline @{ 'identitySecurityDefaultsEnforcementPolicy' = (J '{"isEnabled":false}'); 'conditionalAccess/policies' = $ca }
        $r['ENT-POL-006'].Status | Should -Be 'Pass'
    }
    It 'ignores report-only MFA policies' {
        $ca = J '{"value":[{"displayName":"MFA all","state":"enabledForReportingButNotEnforced","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]}'
        $r = Invoke-Baseline @{ 'identitySecurityDefaultsEnforcementPolicy' = (J '{"isEnabled":false}'); 'conditionalAccess/policies' = $ca }
        $r['ENT-POL-006'].Status | Should -Be 'Gap'
    }
    It 'still evaluates Security Defaults when Conditional Access cannot be read' {
        $r = Invoke-Baseline @{ 'conditionalAccess/policies' = { throw 'forbidden' } }
        $r['ENT-POL-006'].Status | Should -Be 'Pass'
        $r['ENT-POL-006'].Detail | Should -BeLike '*could not be read*'
    }
}

Describe 'ENT-POL-007 SSPR' {
    It 'passes when allowedToUseSSPR is true' { (Invoke-Baseline)['ENT-POL-007'].Status | Should -Be 'Pass' }
    It 'fails when allowedToUseSSPR is false' {
        (Invoke-Baseline @{ 'authorizationPolicy' = (J '{"allowedToUseSSPR":false}') })['ENT-POL-007'].Status | Should -Be 'Gap'
    }
    It 'is not assessed when the property is missing' {
        (Invoke-Baseline @{ 'authorizationPolicy' = (J '{"id":"authorizationPolicy"}') })['ENT-POL-007'].Status | Should -Be 'NotAssessed'
    }
}

Describe 'ENT-AUTH-005/006 smart lockout' {
    It 'passes both with Microsoft defaults (no Password Rule Settings)' {
        $r = Invoke-Baseline
        $r['ENT-AUTH-005'].Status | Should -Be 'Pass'
        $r['ENT-AUTH-006'].Status | Should -Be 'Pass'
        $r['ENT-AUTH-005'].Detail | Should -BeLike '*default*'
    }
    It 'fails when threshold is above 10 and duration below 60' {
        $rules = J '{"value":[{"displayName":"Password Rule Settings","values":[{"name":"LockoutThreshold","value":"20"},{"name":"LockoutDurationInSeconds","value":"30"}]}]}'
        $r = Invoke-Baseline @{ 'groupSettings' = $rules }
        $r['ENT-AUTH-005'].Status | Should -Be 'Gap'
        $r['ENT-AUTH-006'].Status | Should -Be 'Gap'
    }
    It 'passes at the boundary values (10 and 60)' {
        $rules = J '{"value":[{"displayName":"Password Rule Settings","values":[{"name":"LockoutThreshold","value":"10"},{"name":"LockoutDurationInSeconds","value":"60"}]}]}'
        $r = Invoke-Baseline @{ 'groupSettings' = $rules }
        $r['ENT-AUTH-005'].Status | Should -Be 'Pass'
        $r['ENT-AUTH-006'].Status | Should -Be 'Pass'
    }
}

Describe 'ENT-AUTH-007 password expiry' {
    It 'passes when passwords never expire' { (Invoke-Baseline)['ENT-AUTH-007'].Status | Should -Be 'Pass' }
    It 'fails when a managed domain expires passwords' {
        $d = J '{"value":[{"id":"contoso.com","isVerified":true,"authenticationType":"Managed","passwordValidityPeriodInDays":90}]}'
        $r = Invoke-Baseline @{ '/domains' = $d }
        $r['ENT-AUTH-007'].Status | Should -Be 'Gap'
        $r['ENT-AUTH-007'].AffectedObjects[0] | Should -BeLike 'contoso.com*90 days*'
    }
    It 'ignores federated and unverified domains' {
        $d = J '{"value":[{"id":"fed.com","isVerified":true,"authenticationType":"Federated","passwordValidityPeriodInDays":90},{"id":"new.com","isVerified":false,"authenticationType":"Managed","passwordValidityPeriodInDays":90}]}'
        (Invoke-Baseline @{ '/domains' = $d })['ENT-AUTH-007'].Status | Should -Be 'Pass'
    }
}

Describe 'ENT-GRP-003 public Microsoft 365 groups' {
    It 'passes with no groups' { (Invoke-Baseline)['ENT-GRP-003'].Status | Should -Be 'Pass' }
    It 'fails only for Public groups' {
        $g = J '{"value":[{"displayName":"Open Team","visibility":"Public","createdDateTime":"2025-01-02T00:00:00Z"},{"displayName":"Private Team","visibility":"Private","createdDateTime":"2025-01-02T00:00:00Z"}]}'
        $r = Invoke-Baseline @{ 'groups?$filter' = $g }
        $r['ENT-GRP-003'].Status | Should -Be 'Gap'
        $r['ENT-GRP-003'].AffectedCount | Should -Be 1
        $r['ENT-GRP-003'].AffectedObjects[0] | Should -BeLike 'Open Team*'
    }
}

Describe 'ENT-CA-009 emergency access accounts' {
    BeforeAll {
        # Two permanent Global Admins; one is excluded directly from 2 policies, the other only via an excluded group in 1 policy.
        $script:Roles = J '{"value":[
            {"assignmentType":"Assigned","endDateTime":null,"roleDefinition":{"displayName":"Global Administrator"},"principal":{"@odata.type":"#microsoft.graph.user","id":"u1","userPrincipalName":"bg1@contoso.onmicrosoft.com","displayName":"BG1"}},
            {"assignmentType":"Assigned","endDateTime":null,"roleDefinition":{"displayName":"Global Administrator"},"principal":{"@odata.type":"#microsoft.graph.user","id":"u2","userPrincipalName":"bg2@contoso.onmicrosoft.com","displayName":"BG2"}},
            {"assignmentType":"Assigned","endDateTime":"2030-01-01T00:00:00Z","roleDefinition":{"displayName":"Global Administrator"},"principal":{"@odata.type":"#microsoft.graph.user","id":"u3","userPrincipalName":"timeboxed@contoso.com","displayName":"Timeboxed"}}]}'
        $script:Policies = J '{"value":[
            {"displayName":"P1","state":"enabled","conditions":{"users":{"excludeUsers":["u1"],"excludeGroups":["g1"]}}},
            {"displayName":"P2","state":"enabled","conditions":{"users":{"excludeUsers":["u1"],"excludeGroups":[]}}},
            {"displayName":"P3","state":"enabled","conditions":{"users":{"excludeUsers":[],"excludeGroups":[]}}},
            {"displayName":"Off","state":"disabled","conditions":{"users":{"excludeUsers":["u2"],"excludeGroups":[]}}}]}'
        $script:Members = J '{"value":[{"id":"u2"}]}'
        $script:Override = @{ 'roleAssignmentScheduleInstances' = $script:Roles; 'conditionalAccess/policies' = $script:Policies; '/members' = $script:Members }
    }

    It 'is not assessed while the detection rule is unimplemented (returns $null)' {
        $r = Invoke-Baseline $script:Override
        $r['ENT-CA-009'].Status | Should -Be 'NotAssessed'
        $r['ENT-CA-009'].Detail | Should -BeLike '*not implemented*'
    }

    Context 'with a stand-in rule (cloud-only accounts count)' {
        BeforeAll {
            InModuleScope M365GapAssessment {
                $script:Seen = @()
                function script:Test-EmergencyAccessCandidate { param($Candidate) $script:Seen += $Candidate; return [bool]$Candidate.IsCloudOnlyDomain }
            }
        }
        It 'passes when two accounts are identified' {
            (Invoke-Baseline $script:Override)['ENT-CA-009'].Status | Should -Be 'Pass'
        }
        It 'feeds the rule one record per permanent Global Administrator (time-boxed assignments are skipped)' {
            $null = Invoke-Baseline $script:Override
            $seen = InModuleScope M365GapAssessment { $script:Seen | Sort-Object UserPrincipalName -Unique }
            @($seen).Count | Should -Be 2
            ($seen.UserPrincipalName -join ',') | Should -Not -BeLike '*timeboxed*'
        }
        It 'counts direct and group-based exclusions from enabled policies only' {
            $null = Invoke-Baseline $script:Override
            $seen = InModuleScope M365GapAssessment { $script:Seen }
            ($seen | Where-Object UserPrincipalName -like 'bg1@*' | Select-Object -First 1).ExcludedPolicyCount | Should -Be 2   # P1 and P2
            ($seen | Where-Object UserPrincipalName -like 'bg2@*' | Select-Object -First 1).ExcludedPolicyCount | Should -Be 1   # P1 via group g1; disabled policy ignored
            ($seen | Select-Object -First 1).EnabledPolicyCount | Should -Be 3
        }
        It 'fails when fewer than two accounts are identified' {
            $one = J '{"value":[{"assignmentType":"Assigned","endDateTime":null,"roleDefinition":{"displayName":"Global Administrator"},"principal":{"@odata.type":"#microsoft.graph.user","id":"u1","userPrincipalName":"bg1@contoso.onmicrosoft.com","displayName":"BG1"}}]}'
            $r = Invoke-Baseline @{ 'roleAssignmentScheduleInstances' = $one; 'conditionalAccess/policies' = $script:Policies; '/members' = $script:Members }
            $r['ENT-CA-009'].Status | Should -Be 'Gap'
        }
    }
}
