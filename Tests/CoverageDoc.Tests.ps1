#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Docs/Coverage.md is generated from ControlMapping.json by Docs/Update-Coverage.ps1. These tests fail when a finding is
# added, removed or renamed without regenerating the document, so the published coverage never drifts from the tool.

BeforeAll {
    $script:Repo = Join-Path $PSScriptRoot '..'
    $script:Generator = Join-Path $script:Repo 'Docs/Update-Coverage.ps1'
    $script:DocPath = Join-Path $script:Repo 'Docs/Coverage.md'
    # $env:M365GA_MAPPING_PATH points a run at a modified mapping (used to prove these tests fail on drift).
    $script:MappingPath = if ($env:M365GA_MAPPING_PATH) { $env:M365GA_MAPPING_PATH } else { Join-Path $script:Repo 'M365GapAssessment/Data/ControlMapping.json' }
    $script:Controls = @((Get-Content -Raw $script:MappingPath | ConvertFrom-Json).controls)
    $script:Doc = Get-Content -Raw $script:DocPath
    $script:DocDate = [regex]::Match($script:Doc, ' on (\d{4}-\d{2}-\d{2}):').Groups[1].Value
}

Describe 'Docs/Coverage.md' {
    It 'is up to date with the generator output (run: pwsh ./Docs/Update-Coverage.ps1)' {
        $regenerated = Join-Path $TestDrive 'Coverage.md'
        & $script:Generator -OutputPath $regenerated -Date $script:DocDate -MappingPath $script:MappingPath
        (Get-Content -Raw $regenerated) | Should -BeExactly $script:Doc -Because 'Coverage.md must be regenerated after changing ControlMapping.json or the generator text'
    }

    It 'states the finding count from the mapping' {
        $script:Doc | Should -BeLike "*$($script:Controls.Count) findings*"
    }

    It 'lists every finding exactly once' {
        foreach ($c in $script:Controls) {
            ([regex]::Matches($script:Doc, "(?m)^\| $([regex]::Escape($c.id)) \|")).Count | Should -Be 1 -Because "$($c.id) must appear once in the console tables"
        }
    }

    It 'has console section counts that add up to the total' {
        $sum = 0
        foreach ($m in [regex]::Matches($script:Doc, '(?m)^### .+ \((\d+)\)$')) { $sum += [int]$m.Groups[1].Value }
        $sum | Should -Be $script:Controls.Count
    }

    It 'has a header date' {
        $script:DocDate | Should -Match '^\d{4}-\d{2}-\d{2}$'
    }
}
