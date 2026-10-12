#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Every value accepted by Invoke-M365SecurityReview -Domain must be handled by its collector switch, and every finding ID a
# collector can emit must exist in the mapping. Catches a domain that validates but silently does nothing.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    $script:Domains = (Get-Command Invoke-M365SecurityReview).Parameters['Domain'].Attributes |
        Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues }
    $script:ReviewSource = Get-Content -Raw (Join-Path (Split-Path (Get-ModuleUnderTestPath)) 'Public/Invoke-M365SecurityReview.ps1')
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Domain registration' {
    It 'accepts the Defender for Office 365 and Purview domains' {
        $script:Domains | Should -Contain 'DefenderO365'
        $script:Domains | Should -Contain 'Purview'
    }

    It 'has a collector case for every accepted domain' {
        foreach ($d in $script:Domains) {
            $script:ReviewSource | Should -BeLike "*'$d' {*" -Because "domain '$d' validates but no switch case runs it"
        }
    }

    It 'closes the shared Exchange and Purview sessions after collection' {
        $script:ReviewSource | Should -BeLike '*finally { Stop-ExchangeSessions }*'
    }

    It 'maps every finding ID the Defender for Office 365 and Purview collectors can emit' {
        $ids = InModuleScope M365GapAssessment { @($script:DefenderO365Ids) + @($script:PurviewIds) }
        $mapped = InModuleScope M365GapAssessment { @($script:ControlMapping.Keys) }
        foreach ($id in $ids) { $mapped | Should -Contain $id }
    }
}
