#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Regression: -HideTenantId must remove the tenant GUID from every client-facing report (HTML and Markdown),
# including reports re-rendered from saved JSON. The raw JSON export is the record and keeps the GUID.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    $script:ModulePath = Get-ModuleUnderTestPath
    Import-Module $script:ModulePath -Force -ErrorAction Stop
    $script:Guid = '11111111-2222-3333-4444-555555555555'
    $script:Name = 'Contoso Ltd'
}

AfterAll {
    Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue
}

Describe 'Tenant ID visibility in reports' {
    BeforeAll {
        # Export once per setting; the helper runs in module scope so it can build findings from the control mapping.
        $support = Join-Path $PSScriptRoot 'Support/TestSupport.ps1'
        $script:Assessment = InModuleScope M365GapAssessment -Parameters @{ Support = $support } { . $Support; New-MockAssessment }
        foreach ($hide in $true, $false) {
            $dir = Join-Path $TestDrive "export-hide-$hide"
            $null = Export-M365GapReport -Assessment $script:Assessment -ExportPath $dir -Format JSON, Markdown, HTML -Branding @{ HideTenantId = $hide }
            Set-Variable -Scope Script -Name "Dir$hide" -Value $dir
        }
    }

    Context 'without -HideTenantId (default)' {
        It 'shows the tenant ID in the Markdown report' {
            Get-Content -Raw (Join-Path $script:DirFalse 'M365_Security_Gap_Assessment.md') | Should -BeLike "*$script:Guid*"
        }
        It 'shows the tenant ID in the HTML report' {
            Get-Content -Raw (Join-Path $script:DirFalse 'M365_Security_Gap_Assessment.html') | Should -BeLike "*$script:Guid*"
        }
    }

    Context 'with -HideTenantId' {
        It 'removes the tenant ID from the Markdown report' {
            Get-Content -Raw (Join-Path $script:DirTrue 'M365_Security_Gap_Assessment.md') | Should -Not -BeLike "*$script:Guid*"
        }
        It 'removes the tenant ID from the HTML report' {
            Get-Content -Raw (Join-Path $script:DirTrue 'M365_Security_Gap_Assessment.html') | Should -Not -BeLike "*$script:Guid*"
        }
        It 'still shows the tenant display name in the Markdown report' {
            Get-Content -Raw (Join-Path $script:DirTrue 'M365_Security_Gap_Assessment.md') | Should -BeLike "*| **Tenant** | $script:Name |*"
        }
        It 'keeps the tenant ID in the raw JSON record' {
            (Get-Content -Raw (Join-Path $script:DirTrue 'AssessmentFindings.json') | ConvertFrom-Json).TenantId | Should -Be $script:Guid
        }
    }

    Context 'Convert-M365Report re-rendering saved JSON' {
        BeforeAll {
            $json = Join-Path $script:DirFalse 'AssessmentFindings.json'
            $script:Converted = @(Convert-M365Report -Path $json -OutputPath (Join-Path $TestDrive 'converted') -Format HTML, Markdown -HideTenantId)
        }
        It 'writes both requested files' {
            $script:Converted | Should -HaveCount 2
        }
        It 'omits the tenant ID from every re-rendered report' {
            foreach ($file in $script:Converted) {
                Get-Content -Raw $file | Should -Not -BeLike "*$script:Guid*" -Because "$(Split-Path $file -Leaf) must honour -HideTenantId"
            }
        }
    }
}
