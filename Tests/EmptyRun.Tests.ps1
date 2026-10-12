#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# A run that produces no findings (every selected domain returned nothing) must complete and produce a valid, empty assessment
# instead of failing with a parameter-binding error.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    $script:Support = Join-Path $PSScriptRoot 'Support/TestSupport.ps1'
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Empty finding lists' {
    It 'Measure-AssessmentScore returns nothing to score instead of throwing' {
        InModuleScope M365GapAssessment { Measure-AssessmentScore -Findings @() } | Should -BeNullOrEmpty
    }
    It 'Set-AcceptedRisk accepts an empty list' {
        { InModuleScope M365GapAssessment { Set-AcceptedRisk -Findings @() -Risks @() } } | Should -Not -Throw
    }
    It 'reports can be written for an assessment with no findings' {
        $a = InModuleScope M365GapAssessment -Parameters @{ S = $script:Support } { . $S; $x = New-MockAssessment; $x.Findings = @(); $x.Summary.TotalChecks = 0; $x.Summary.Gaps = 0; $x.Summary.Passed = 0; $x.Score = $null; $x }
        $dir = Join-Path $TestDrive 'empty'
        { Export-M365GapReport -Assessment $a -ExportPath $dir -Format JSON, Markdown, HTML -IncludeEvidence -CisView } | Should -Not -Throw
        Test-Path (Join-Path $dir 'M365_Security_Gap_Assessment.md') | Should -BeTrue
        Test-Path (Join-Path $dir 'M365_Security_Gap_Assessment.html') | Should -BeTrue
        Test-Path (Join-Path $dir 'evidence') | Should -BeFalse
    }
}

Describe 'Invoke-M365SecurityReview when nothing is found' {
    It 'completes with zero checks and no score' {
        InModuleScope M365GapAssessment {
            function script:Connect-M365Assessment { param([Parameter(ValueFromRemainingArguments = $true)]$R) [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'a@b' } }
            function script:Get-LicenseInventory { $null }
            function script:Get-LicenseGaps { param($Inventory) @() }
            function script:Invoke-GraphRequestWithRetry { param($Uri) [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @() }) } }
        }
        $r = InModuleScope M365GapAssessment { Invoke-M365SecurityReview -TenantId contoso.com -Domain Licensing -NoExport -NoPrompt 3>$null }
        $r.Summary.TotalChecks | Should -Be 0
        $r.Score | Should -BeNullOrEmpty
        @($r.Findings).Count | Should -Be 0
    }
}
