#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Conditional Access MFA logic:
#  - a policy that lists MFA only as one OR-alternative ("MFA or compliant device") does not guarantee MFA
#  - ENT-CA-006 severity drops to Medium when Security Defaults covers guests 'when necessary'
#  - ENT-CA-005 warns when no Intune devices exist; ENT-POL-006 notes licensed-but-on-Security-Defaults
#  - Conditional Access policies are fetched once per run, not once per collector

BeforeDiscovery {
    $script:PolicyCases = @(
        @{ Name = 'MFA alone';                            Json = '{"grantControls":{"operator":"AND","builtInControls":["mfa"]}}';                                 Expected = $true }
        @{ Name = 'MFA alone with operator OR';           Json = '{"grantControls":{"operator":"OR","builtInControls":["mfa"]}}';                                  Expected = $true }
        @{ Name = 'MFA AND compliant device';             Json = '{"grantControls":{"operator":"AND","builtInControls":["mfa","compliantDevice"]}}';              Expected = $true }
        @{ Name = 'MFA OR compliant device';              Json = '{"grantControls":{"operator":"OR","builtInControls":["mfa","compliantDevice"]}}';               Expected = $false }
        @{ Name = 'authentication strength alone';        Json = '{"grantControls":{"operator":"OR","builtInControls":[],"authenticationStrength":{"id":"s1"}}}'; Expected = $true }
        @{ Name = 'authentication strength OR device';    Json = '{"grantControls":{"operator":"OR","builtInControls":["compliantDevice"],"authenticationStrength":{"id":"s1"}}}'; Expected = $false }
        @{ Name = 'compliant device only';                Json = '{"grantControls":{"operator":"AND","builtInControls":["compliantDevice"]}}';                    Expected = $false }
        @{ Name = 'block';                                Json = '{"grantControls":{"operator":"OR","builtInControls":["block"]}}';                                Expected = $false }
        @{ Name = 'no grant controls';                    Json = '{"conditions":{}}';                                                                              Expected = $false }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeGraph.ps1')
    Enable-FakeGraph

    function script:Policy($Name, $Grant, $Users = '{"includeUsers":["All"]}') {
        J ('{"value":[{"displayName":"' + $Name + '","state":"enabled","conditions":{"users":' + $Users + ',"applications":{"includeApplications":["All"]}},"grantControls":' + $Grant + '}]}')
    }
    $script:MfaOrDevice = Policy 'MFA or device' '{"operator":"OR","builtInControls":["mfa","compliantDevice"]}'
    $script:MfaOnly     = Policy 'MFA only' '{"operator":"OR","builtInControls":["mfa"]}'
    $script:NoPolicies  = J '{"value":[]}'

    # Fixture covering what the Entra collectors request; anything else has no entry and is reported NotAssessed.
    function script:Invoke-Entra {
        param($Policies, $SecurityDefaults = (J '{"isEnabled":false}'), $Devices = (J '{"value":[{"id":"d1"}]}'), [string]$Command = 'Get-EntraIDGaps; Get-EntraPolicyGaps')
        Invoke-WithFixture -Command $Command -Fixture (ConvertTo-Fixture ([ordered]@{
                    'identitySecurityDefaultsEnforcementPolicy' = $SecurityDefaults
                    'conditionalAccess/policies'                = $Policies
                    'conditionalAccess/namedLocations'          = (J '{"value":[]}')
                    'managedDevices'                            = $Devices
                }))
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Test-PolicyEnforcesMfa' {
    It '<Name> -> <Expected>' -ForEach $script:PolicyCases {
        $policy = J $Json
        InModuleScope M365GapAssessment -Parameters @{ P = $policy } { Test-PolicyEnforcesMfa -Policy $P } | Should -Be $Expected
    }
}

Describe 'MFA policies that only offer MFA as an OR-alternative' {
    It 'ENT-CA-004 reports a Gap and names the rejected policy' {
        $f = (Invoke-Entra -Policies $script:MfaOrDevice)['ENT-CA-004']
        $f.Status | Should -Be 'Gap'
        $f.Detail | Should -BeLike '*operator OR*MFA or device*'
    }
    It 'ENT-CA-004 passes when MFA is the only control' {
        (Invoke-Entra -Policies $script:MfaOnly)['ENT-CA-004'].Status | Should -Be 'Pass'
    }
    It 'ENT-CA-006 reports a Gap for the OR policy' {
        (Invoke-Entra -Policies $script:MfaOrDevice)['ENT-CA-006'].Status | Should -Be 'Gap'
    }
    It 'ENT-CA-006 passes when MFA is the only control' {
        (Invoke-Entra -Policies $script:MfaOnly)['ENT-CA-006'].Status | Should -Be 'Pass'
    }
    It 'ENT-POL-006 does not treat the OR policy as baseline MFA' {
        (Invoke-Entra -Policies $script:MfaOrDevice)['ENT-POL-006'].Status | Should -Be 'Gap'
    }
    It 'ENT-POL-006 passes with a real all-user MFA policy' {
        (Invoke-Entra -Policies $script:MfaOnly)['ENT-POL-006'].Status | Should -Be 'Pass'
    }
}

Describe 'ENT-CA-006 severity with Security Defaults' {
    It 'is High when Security Defaults is off and no policy covers guests' {
        $f = (Invoke-Entra -Policies $script:NoPolicies)['ENT-CA-006']
        $f.Status | Should -Be 'Gap'
        $f.Severity | Should -Be 'High'
    }
    It 'drops to Medium, with an explanation, when Security Defaults is on' {
        $f = (Invoke-Entra -Policies $script:NoPolicies -SecurityDefaults (J '{"isEnabled":true}'))['ENT-CA-006']
        $f.Status | Should -Be 'Gap'
        $f.Severity | Should -Be 'Medium'
        $f.Detail | Should -BeLike '*when Microsoft deems it necessary*'
    }
    It 'stays a Pass (and High-severity record) when a policy covers guests, regardless of Security Defaults' {
        $f = (Invoke-Entra -Policies $script:MfaOnly -SecurityDefaults (J '{"isEnabled":true}'))['ENT-CA-006']
        $f.Status | Should -Be 'Pass'
    }
}

Describe 'Context notes' {
    It 'ENT-CA-005 warns when no Intune-managed devices exist' {
        $f = (Invoke-Entra -Policies $script:NoPolicies -Devices (J '{"value":[]}'))['ENT-CA-005']
        $f.Status | Should -Be 'Gap'
        $f.Detail | Should -BeLike '*No Intune-managed devices*'
    }
    It 'ENT-CA-005 has no devices warning when devices exist' {
        (Invoke-Entra -Policies $script:NoPolicies)['ENT-CA-005'].Detail | Should -Not -BeLike '*No Intune-managed devices*'
    }
    It 'ENT-POL-006 notes a licensed tenant that still relies on Security Defaults' {
        InModuleScope M365GapAssessment { $script:LicenseCapabilities = @{ EntraP1 = $true; EntraP2 = $true } }
        try {
            $f = (Invoke-Entra -Policies $script:NoPolicies -SecurityDefaults (J '{"isEnabled":true}'))['ENT-POL-006']
            $f.Status | Should -Be 'Pass'
            $f.Detail | Should -BeLike '*licensed for Conditional Access*'
        }
        finally { InModuleScope M365GapAssessment { $script:LicenseCapabilities = $null } }
    }
    It 'ENT-POL-006 adds no licence note for an unlicensed tenant' {
        (Invoke-Entra -Policies $script:NoPolicies -SecurityDefaults (J '{"isEnabled":true}'))['ENT-POL-006'].Detail | Should -Not -BeLike '*licensed for Conditional Access*'
    }
}

Describe 'Conditional Access policy caching' {
    It 'fetches the policy list once for all collectors in a run' {
        $script:CaCalls = 0
        $counting = { $script:CaCalls++; [pscustomobject]@{ value = @() } }
        $null = Invoke-Entra -Policies $counting
        $script:CaCalls | Should -Be 1
    }
    It 'fetches again for the next run (cache is cleared between tenants)' {
        $script:CaCalls = 0
        $counting = { $script:CaCalls++; [pscustomobject]@{ value = @() } }
        $null = Invoke-Entra -Policies $counting
        $null = Invoke-Entra -Policies $counting
        $script:CaCalls | Should -Be 2
    }
    It 'does not cache a failed read: each collector reports its own error' {
        $script:CaCalls = 0
        $failing = { $script:CaCalls++; throw 'forbidden' }
        $r = Invoke-Entra -Policies $failing
        $script:CaCalls | Should -BeGreaterThan 1
        $r['ENT-CA-004'].Status | Should -Be 'NotAssessed'
    }
}
