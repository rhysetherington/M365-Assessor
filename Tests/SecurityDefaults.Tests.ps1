#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# ENT-CA-003 (legacy auth block) and ENT-CA-004 (admin MFA) must treat Security Defaults as coverage: it blocks legacy
# authentication and requires admin MFA, so reporting a Gap for tenants that rely on it is a false positive.
# Regression for a live-tenant result where Security Defaults was on yet both checks reported Gaps.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeGraph.ps1')
    Enable-FakeGraph

    $script:LegacyBlockPolicy = J '{"value":[{"displayName":"Block legacy auth","state":"enabled","conditions":{"clientAppTypes":["exchangeActiveSync","other"],"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["block"]}}]}'
    $script:MfaPolicy = J '{"value":[{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]}'
    $script:NoPolicies = J '{"value":[]}'

    # Only the Conditional Access block of Get-EntraIDGaps is under test; its other checks have no fixtures and report NotAssessed.
    function script:Invoke-CaChecks {
        param($SecurityDefaults, $Policies)
        Invoke-WithFixture -Command 'Get-EntraIDGaps' -Fixture (ConvertTo-Fixture ([ordered]@{
                    'identitySecurityDefaultsEnforcementPolicy' = $SecurityDefaults
                    'conditionalAccess/policies'                = $Policies
                }))
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Get-SecurityDefaultsState' {
    It 'returns $true when enabled' {
        $f = ConvertTo-Fixture ([ordered]@{ 'identitySecurityDefaultsEnforcementPolicy' = (J '{"isEnabled":true}') })
        InModuleScope M365GapAssessment -Parameters @{ F = $f } { $script:Fixture = $F; Reset-CollectorCache; Get-SecurityDefaultsState } | Should -BeTrue
    }
    It 'returns $false when disabled' {
        $f = ConvertTo-Fixture ([ordered]@{ 'identitySecurityDefaultsEnforcementPolicy' = (J '{"isEnabled":false}') })
        InModuleScope M365GapAssessment -Parameters @{ F = $f } { $script:Fixture = $F; Reset-CollectorCache; Get-SecurityDefaultsState } | Should -BeFalse
    }
    It 'returns $null (not an error) when the policy cannot be read' {
        $f = ConvertTo-Fixture ([ordered]@{ 'identitySecurityDefaultsEnforcementPolicy' = { throw 'forbidden' } })
        InModuleScope M365GapAssessment -Parameters @{ F = $f } { $script:Fixture = $F; Reset-CollectorCache; Get-SecurityDefaultsState } | Should -BeNullOrEmpty
    }
}

Describe 'ENT-CA-003 and ENT-CA-004 with Security Defaults' {
    Context 'Security Defaults enabled, no Conditional Access' {
        BeforeAll { $script:r = Invoke-CaChecks -SecurityDefaults (J '{"isEnabled":true}') -Policies $script:NoPolicies }
        It 'passes the legacy authentication check' { $script:r['ENT-CA-003'].Status | Should -Be 'Pass' }
        It 'passes the admin MFA check' { $script:r['ENT-CA-004'].Status | Should -Be 'Pass' }
        It 'says the coverage comes from Security Defaults' {
            $script:r['ENT-CA-003'].Detail | Should -BeLike '*Security Defaults*'
            $script:r['ENT-CA-004'].Detail | Should -BeLike '*Security Defaults*'
        }
    }

    Context 'Security Defaults disabled, no Conditional Access' {
        BeforeAll { $script:r = Invoke-CaChecks -SecurityDefaults (J '{"isEnabled":false}') -Policies $script:NoPolicies }
        It 'reports a Gap for both checks' {
            $script:r['ENT-CA-003'].Status | Should -Be 'Gap'
            $script:r['ENT-CA-004'].Status | Should -Be 'Gap'
        }
        It 'states that Security Defaults is not enabled' { $script:r['ENT-CA-004'].Detail | Should -BeLike '*Security Defaults is not enabled*' }
    }

    Context 'Security Defaults state unreadable, no Conditional Access' {
        BeforeAll { $script:r = Invoke-CaChecks -SecurityDefaults { throw 'forbidden' } -Policies $script:NoPolicies }
        It 'keeps the Gap rather than assuming coverage' {
            $script:r['ENT-CA-003'].Status | Should -Be 'Gap'
            $script:r['ENT-CA-004'].Status | Should -Be 'Gap'
        }
        It 'tells the reader the state could not be read' { $script:r['ENT-CA-004'].Detail | Should -BeLike '*could not be read*' }
    }

    Context 'Security Defaults disabled, Conditional Access policies in place' {
        It 'passes legacy authentication via the blocking policy' {
            $r = Invoke-CaChecks -SecurityDefaults (J '{"isEnabled":false}') -Policies $script:LegacyBlockPolicy
            $r['ENT-CA-003'].Status | Should -Be 'Pass'
            $r['ENT-CA-003'].Detail | Should -BeLike '*Block legacy auth*'
        }
        It 'passes admin MFA via the MFA policy' {
            $r = Invoke-CaChecks -SecurityDefaults (J '{"isEnabled":false}') -Policies $script:MfaPolicy
            $r['ENT-CA-004'].Status | Should -Be 'Pass'
            $r['ENT-CA-004'].Detail | Should -BeLike '*MFA all*'
        }
        It 'does not pass legacy authentication from an MFA-only policy' {
            (Invoke-CaChecks -SecurityDefaults (J '{"isEnabled":false}') -Policies $script:MfaPolicy)['ENT-CA-003'].Status | Should -Be 'Gap'
        }
    }

    Context 'Conditional Access is reported as the source when both apply' {
        It 'names the policy, not Security Defaults' {
            $r = Invoke-CaChecks -SecurityDefaults (J '{"isEnabled":true}') -Policies $script:MfaPolicy
            $r['ENT-CA-004'].Detail | Should -BeLike '*MFA all*'
        }
    }
}
