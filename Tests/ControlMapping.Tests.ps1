#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Integrity of Data/ControlMapping.json: the single source of truth for severity, SCF, NIST CSF 2.0, CIS and remediation.
# Every finding a collector emits must resolve to a well-formed entry, or reports silently show blanks.

BeforeDiscovery {
    # $env:M365GA_MAPPING_PATH lets a test run point at a deliberately broken copy to prove the rules bite.
    $mappingPath = if ($env:M365GA_MAPPING_PATH) { $env:M365GA_MAPPING_PATH } else { Join-Path $PSScriptRoot '../M365GapAssessment/Data/ControlMapping.json' }
    $mapping = Get-Content -Raw $mappingPath | ConvertFrom-Json
    $script:Controls = @($mapping.controls)
    $script:RetiredIds = @($mapping.retiredIds)
}

BeforeAll {
    # Variables set in BeforeDiscovery are NOT visible inside It blocks (only -ForEach can use them), so load again for run time.
    # Without this the tests below saw $null and passed without checking anything.
    $mappingPath = if ($env:M365GA_MAPPING_PATH) { $env:M365GA_MAPPING_PATH } else { Join-Path $PSScriptRoot '../M365GapAssessment/Data/ControlMapping.json' }
    $mapping = Get-Content -Raw $mappingPath | ConvertFrom-Json
    $script:Controls = @($mapping.controls)
    $script:RetiredIds = @($mapping.retiredIds)
}

Describe 'ControlMapping.json' {
    It 'is actually loaded (guards against tests that pass because they saw nothing)' {
        @($script:Controls).Count | Should -BeGreaterThan 50
    }

    It 'has no duplicate finding IDs' {
        $dupes = $script:Controls | Group-Object id | Where-Object Count -gt 1 | ForEach-Object Name
        $dupes | Should -BeNullOrEmpty -Because "duplicate IDs: $($dupes -join ', ')"
    }

    It 'keeps entries sorted by id (ordinal), so additions land in a predictable place and diffs stay small' {
        $ids = @($script:Controls | ForEach-Object id)
        $sorted = [string[]]$ids.Clone()
        [array]::Sort($sorted, [System.StringComparer]::Ordinal)
        ($ids -join ',') | Should -BeExactly ($sorted -join ',')
    }

    It 'has no unexplained gaps in the numbering of any id series (a gap must be listed in retiredIds)' {
        $gaps = foreach ($g in ($script:Controls | Group-Object { $_.id -replace '-\d{3}$', '' })) {
            $nums = @($g.Group | ForEach-Object { [int]($_.id -replace '^.*-(\d{3})$', '$1') })
            foreach ($n in 1..($nums | Measure-Object -Maximum).Maximum) { if ($n -notin $nums) { '{0}-{1:D3}' -f $g.Name, $n } }
        }
        $unexplained = @($gaps | Where-Object { $_ -notin $script:RetiredIds })
        $unexplained | Should -BeNullOrEmpty -Because "numbering gaps not listed in retiredIds: $($unexplained -join ', ')"
    }

    It 'never reuses a retired id' {
        $reused = @($script:Controls | Where-Object { $_.id -in $script:RetiredIds } | ForEach-Object id)
        $reused | Should -BeNullOrEmpty -Because "retired ids must stay retired: $($reused -join ', ')"
    }

    It 'lists in retiredIds only ids that are really absent (no stale entries)' {
        $present = @($script:RetiredIds | Where-Object { $_ -in @($script:Controls | ForEach-Object id) })
        $present | Should -BeNullOrEmpty
    }

    It 'uses only known severities' {
        $bad = $script:Controls | Where-Object { $_.severity -notin 'Critical', 'High', 'Medium', 'Low', 'Informational' } | ForEach-Object id
        $bad | Should -BeNullOrEmpty -Because "invalid severity on: $($bad -join ', ')"
    }

    # One test per entry so a failure names the exact finding ID. Formats are strict enough to catch typos
    # (a swapped SCF/NIST value, a missing digit) but still accept every real ID style in use (ENT-CA-001, SSC-001, IAC-06.1).
    Context 'Entry <id>' -ForEach $script:Controls {
        It 'has non-empty id, domain and name' {
            $_.id     | Should -Match '^[A-Z]{2,4}(-[A-Z]{2,4})?-\d{3}$'
            $_.domain | Should -Not -BeNullOrEmpty
            $_.name   | Should -Not -BeNullOrEmpty
        }
        It 'has an SCF control ID like AST-02 or IAC-06.1' {
            $_.scf | Should -Match '^[A-Z]{3}-\d{2}(\.\d+)?$'
        }
        It 'has a NIST CSF 2.0 subcategory like PR.AA-03' {
            $_.nistCsf | Should -Match '^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}$'
        }
        It 'has at least two non-empty remediation steps' {
            @($_.remediation | Where-Object { $_ -is [string] -and $_.Trim() }).Count | Should -BeGreaterOrEqual 2
        }
        It 'uses only known values for the optional license and cis fields' {
            if ($_.license) { $_.license | Should -BeIn 'EntraP1', 'EntraP2', 'Intune', 'DefenderO365', 'DefenderEndpoint' }
            foreach ($ref in @($_.cis)) { if ($ref) { $ref | Should -Match '^\d+(\.\d+)*$' } }
        }
    }
}
