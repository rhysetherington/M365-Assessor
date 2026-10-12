#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Integrity of Data/ControlMapping.json: the single source of truth for severity, SCF, NIST CSF 2.0, CIS and remediation.
# Every finding a collector emits must resolve to a well-formed entry, or reports silently show blanks.

BeforeDiscovery {
    $mappingPath = Join-Path $PSScriptRoot '../M365GapAssessment/Data/ControlMapping.json'
    $script:Controls = @((Get-Content -Raw $mappingPath | ConvertFrom-Json).controls)
}

Describe 'ControlMapping.json' {
    It 'has no duplicate finding IDs' {
        $dupes = $script:Controls | Group-Object id | Where-Object Count -gt 1 | ForEach-Object Name
        $dupes | Should -BeNullOrEmpty -Because "duplicate IDs: $($dupes -join ', ')"
    }

    It 'uses only known severities' {
        $bad = $script:Controls | Where-Object { $_.severity -notin 'Critical', 'High', 'Medium', 'Low', 'Informational' } | ForEach-Object id
        $bad | Should -BeNullOrEmpty -Because "invalid severity on: $($bad -join ', ')"
    }

    Context 'Required fields and formats' {
        # TODO(human): decide what "well-formed" means for a control entry and assert it here.
        # Each entry has: id, domain, name, severity, scf, nistCsf, remediation[] and optionally cis[] and license.
        # Pick rules that would catch a real mistake but not reject legitimate entries (see the guidance in chat).
    }
}
