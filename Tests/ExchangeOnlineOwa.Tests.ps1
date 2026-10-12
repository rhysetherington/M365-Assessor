#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# EXO-008: Outlook on the web storage providers (Get-ExchangeOnlineGaps). The Exchange session and cmdlets are fakes: no tenant.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeCmdlets.ps1')
    InModuleScope M365GapAssessment { function script:Start-ExchangeSession { param($TenantId) [pscustomobject]@{ Ready = $true; Error = $null } } }

    function script:J($Json) { $Json | ConvertFrom-Json }
    function script:Get-Exo008 {
        param($Policies)
        # Only Get-OwaMailboxPolicy is defined; every other Exchange check goes NotAssessed, which must not affect EXO-008.
        $data = @{}
        if ($null -ne $Policies) { $data['Get-OwaMailboxPolicy'] = $Policies }
        (Invoke-WithCmdlets -Data $data -Command 'Get-ExchangeOnlineGaps')['EXO-008']
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'EXO-008 Outlook on the web storage providers' {
    It 'passes when no policy allows additional storage providers' {
        $f = Get-Exo008 (J '[{"Name":"OwaMailboxPolicy-Default","AdditionalStorageProvidersAvailable":false}]')
        $f.Status | Should -Be 'Pass'
        $f.Detail | Should -BeLike '0 of 1*'
    }
    It 'is a gap when the default policy allows them' {
        (Get-Exo008 (J '[{"Name":"OwaMailboxPolicy-Default","AdditionalStorageProvidersAvailable":true}]')).Status | Should -Be 'Gap'
    }
    It 'is a gap when only a non-default policy allows them, and names that policy' {
        $f = Get-Exo008 (J '[{"Name":"OwaMailboxPolicy-Default","AdditionalStorageProvidersAvailable":false},{"Name":"Sales","AdditionalStorageProvidersAvailable":true}]')
        $f.Status | Should -Be 'Gap'
        @($f.AffectedObjects) | Should -Be @('Sales')
    }
    It 'is NotAssessed, not a pass, when the setting is not returned' {
        $f = Get-Exo008 (J '[{"Name":"OwaMailboxPolicy-Default"}]')
        $f.Status | Should -Be 'NotAssessed'
        $f.Detail | Should -BeLike '*OwaMailboxPolicy-Default*'
    }
    It 'is NotAssessed when no policy is returned' {
        (Get-Exo008 (J '[]')).Status | Should -Be 'NotAssessed'
    }
    It 'is NotAssessed when the cmdlet is refused or missing' {
        (Get-Exo008 { throw 'access denied' }).Status | Should -Be 'NotAssessed'
        (Get-Exo008 $null).Status | Should -Be 'NotAssessed'
    }
}
