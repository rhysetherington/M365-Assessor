#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Docs/Get-CisCoverage.ps1 with an invented benchmark list and mapping: the real CIS list is licensed and is never used in tests.

BeforeAll {
    $script:Generator = Join-Path $PSScriptRoot '../Docs/Get-CisCoverage.ps1'

    $script:Mapping = Join-Path $TestDrive 'mapping.json'
    @'
{ "controls": [
  { "id": "AAA-001", "cis": ["1.1.1", "9.9.9"], "cisPartial": ["1.1.2"] },
  { "id": "AAA-002", "cis": ["1.1.1"] },
  { "id": "AAA-003", "cisPartial": ["2.1.1"] },
  { "id": "AAA-004" },
  { "id": "AAA-005", "cisPartial": ["1.1.1"] }
] }
'@ | Set-Content $script:Mapping

    function script:New-Csv {
        param([string]$Name, [string]$Text)
        $p = Join-Path $TestDrive $Name; $Text | Set-Content $p; $p
    }
    function script:Invoke-Coverage {
        param([string]$Csv, [string]$Out = (Join-Path $TestDrive 'out.md'))
        & $script:Generator -BenchmarkCsv $Csv -OutputPath $Out -MappingPath $script:Mapping -PassThru 6>$null 3>$null
    }
    $script:GoodCsv = New-Csv 'good.csv' @'
Recommendation,Title,Level,Section
1.1.1,First thing,L1,1
1.1.2,Second thing,L1,1
1.1.3,Third thing,L2,1
2.1.1,Fourth thing,L1,2
'@
}

Describe 'Get-CisCoverage.ps1' {
    It 'classifies Covered, Partial and Missing from cis and cisPartial' {
        $r = Invoke-Coverage $script:GoodCsv
        ($r | Where-Object Recommendation -eq '1.1.1').Status | Should -Be 'Covered'
        ($r | Where-Object Recommendation -eq '1.1.2').Status | Should -Be 'Partial'
        ($r | Where-Object Recommendation -eq '2.1.1').Status | Should -Be 'Partial'
        ($r | Where-Object Recommendation -eq '1.1.3').Status | Should -Be 'Missing'
    }

    It 'lists every finding that references a recommendation, full or partial' {
        $f = (Invoke-Coverage $script:GoodCsv | Where-Object Recommendation -eq '1.1.1').Findings
        @($f) | Should -Be @('AAA-001', 'AAA-002', 'AAA-005')
    }

    It 'a full cover wins over a partial one from another finding' {
        (Invoke-Coverage $script:GoodCsv | Where-Object Recommendation -eq '1.1.1').Status | Should -Be 'Covered'
    }

    It 'reports mapped numbers that are not in the benchmark, instead of dropping them' {
        $out = Join-Path $TestDrive 'unknown.md'
        $null = Invoke-Coverage $script:GoodCsv $out
        Get-Content -Raw $out | Should -BeLike '*not found in the benchmark CSV*9.9.9*'
    }

    It 'writes the summary counts and the level table' {
        $out = Join-Path $TestDrive 'summary.md'
        $null = Invoke-Coverage $script:GoodCsv $out
        $md = Get-Content -Raw $out
        $md | Should -BeLike '*| Covered | 1 | 25% |*'
        $md | Should -BeLike '*| Partial | 2 | 50% |*'
        $md | Should -BeLike '*| Missing | 1 | 25% |*'
        $md | Should -BeLike '*| L2 | 0 | 0 | 1 |*'
    }

    It 'sorts numerically, so 1.10 follows 1.2' {
        $csv = New-Csv 'sort.csv' "Recommendation,Title`n1.10,Ten`n1.2,Two`n1.1,One"
        @((Invoke-Coverage $csv).Recommendation) | Should -Be @('1.1', '1.2', '1.10')
    }

    It 'accepts Id as the number column and groups by the first number when there is no Section column' {
        $csv = New-Csv 'id.csv' "Id,Title`n3.1,Thing"
        $r = Invoke-Coverage $csv
        $r.Recommendation | Should -Be '3.1'
        $r.Section | Should -Be '3'
    }

    It 'creates the output folder when it does not exist' {
        $out = Join-Path $TestDrive 'new/folder/out.md'
        $null = Invoke-Coverage $script:GoodCsv $out
        Test-Path $out | Should -BeTrue
    }

    Context 'bad input is refused, not guessed at' {
        It 'a missing file' { { Invoke-Coverage (Join-Path $TestDrive 'nope.csv') } | Should -Throw '*not found*' }
        It 'an empty list' { { Invoke-Coverage (New-Csv 'empty.csv' 'Recommendation,Title') } | Should -Throw '*no rows*' }
        It 'a row with no number' { { Invoke-Coverage (New-Csv 'nonum.csv' "Title`nSomething") } | Should -Throw '*no recommendation number*' }
        It 'a number that is not like 1.1.1' { { Invoke-Coverage (New-Csv 'badnum.csv' "Recommendation,Title`n1.x,Bad") } | Should -Throw "*not a number*" }
        It 'duplicate numbers' { { Invoke-Coverage (New-Csv 'dup.csv' "Recommendation,Title`n1.1,A`n1.1,B") } | Should -Throw '*Duplicate*1.1*' }
    }
}

Describe 'repository hygiene for licensed content' {
    It 'git-ignores benchmark CSVs and the generated coverage report' {
        $ignore = Get-Content -Raw (Join-Path $PSScriptRoot '../.gitignore')
        $ignore | Should -BeLike '*Docs/*benchmark*.csv*'
        $ignore | Should -BeLike '*CIS-coverage*.md*'
    }
}
