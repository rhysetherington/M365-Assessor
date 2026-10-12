#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Module layout: Public/ holds only the exported cmdlets (one function per file, named after the file), everything else lives in
# Private/, and the manifest, Export-ModuleMember and the files agree. A function defined twice would be silently overridden by the
# later dot-source, so names must be unique across the module.

BeforeDiscovery {
    $root = Join-Path $PSScriptRoot '../M365GapAssessment'
    $script:PublicFiles = @(Get-ChildItem (Join-Path $root 'Public') -Filter *.ps1 | ForEach-Object { @{ Name = $_.BaseName } })
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    # Read the module under test (the repo copy, or $env:M365GA_MODULE_PATH when proving the tests catch a mistake).
    $script:Root = Split-Path (Get-ModuleUnderTestPath)

    function script:Get-TopLevelFunctions($Path) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Parent.Parent -eq $ast }, $false) | ForEach-Object { $_.Name })
    }
    $script:PublicNames = @(Get-ChildItem (Join-Path $script:Root 'Public') -Filter *.ps1 | ForEach-Object BaseName | Sort-Object)
    $manifest = Import-PowerShellDataFile (Join-Path $script:Root 'M365GapAssessment.psd1')
    $script:Manifest = @($manifest.FunctionsToExport | Sort-Object)
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Public folder' {
    It '<Name>.ps1 defines exactly one function, named after the file' -ForEach $script:PublicFiles {
        $defined = @(Get-TopLevelFunctions (Join-Path $script:Root "Public/$Name.ps1"))
        $defined | Should -Be @($Name) -Because "helpers belong in Private/; found: $($defined -join ', ')"
    }
}

Describe 'Exports' {
    It 'the manifest exports exactly the Public cmdlets' {
        $script:Manifest | Should -Be $script:PublicNames
    }
    It 'Export-ModuleMember in the root module lists exactly the manifest functions' {
        $psm1 = Get-Content -Raw (Join-Path $script:Root 'M365GapAssessment.psm1')
        $listed = @([regex]::Matches(($psm1 -split 'Export-ModuleMember')[-1], "'([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
        $listed | Should -Be $script:Manifest
    }
    It 'the loaded module exports exactly those functions and no private helper' {
        $exported = @((Get-Module M365GapAssessment).ExportedFunctions.Keys | Sort-Object)
        $exported | Should -Be $script:Manifest
    }
}

Describe 'Function names' {
    It 'are unique across Public and Private (a duplicate is silently overridden by the later dot-source)' {
        $all = foreach ($f in Get-ChildItem $script:Root -Recurse -Filter *.ps1 | Where-Object { $_.DirectoryName -match '[/\\](Public|Private)$' }) {
            foreach ($n in (Get-TopLevelFunctions $f.FullName)) { [pscustomobject]@{ Name = $n; File = $f.Name } }
        }
        $dupes = $all | Group-Object Name | Where-Object Count -gt 1 | ForEach-Object { "$($_.Name) in $(($_.Group.File) -join ' and ')" }
        $dupes | Should -BeNullOrEmpty -Because "duplicates: $($dupes -join '; ')"
    }
    It 'report builders live in Private, not Public' {
        $publicDefined = foreach ($f in Get-ChildItem (Join-Path $script:Root 'Public') -Filter *.ps1) { Get-TopLevelFunctions $f.FullName }
        foreach ($n in 'New-AssessmentHtml', 'New-AssessmentMarkdown', 'Get-ComplianceMatrix', 'ConvertTo-MdCell', 'Get-ScoreText') {
            $publicDefined | Should -Not -Contain $n
        }
    }
}

Describe 'README "Extending" section' {
    BeforeAll {
        $readme = Get-Content -Raw (Join-Path (Split-Path (Get-ModuleUnderTestPath)) 'README.md')
        $script:Extending = ($readme -split '(?m)^## Extending')[1] -split '(?m)^## ' | Select-Object -First 1
    }
    It 'is present' { $script:Extending | Should -Not -BeNullOrEmpty }
    It 'names every mapping field a contributor must or may supply' {
        foreach ($field in 'id', 'domain', 'name', 'severity', 'scf', 'nistCsf', 'remediation', 'cis', 'license', 'retiredIds') {
            $script:Extending.Contains("``$field``") | Should -BeTrue -Because "the mapping field '$field' should be documented"
        }
    }
    It 'tells contributors to test offline and regenerate the coverage document' {
        $script:Extending | Should -BeLike '*Invoke-Pester*'
        $script:Extending | Should -BeLike '*Update-Coverage.ps1*'
    }
    It 'says unreadable data must be NotAssessed, never a pass' {
        $script:Extending | Should -BeLike '*NotAssessed*never Pass*'
    }
}
