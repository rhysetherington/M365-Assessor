# Shared helpers for the Pester suite. Dot-source from a test file's BeforeAll block.
# The module under test defaults to the repo copy; set $env:M365GA_MODULE_PATH to a different .psd1 (e.g. an older revision)
# to prove a test catches a regression.

function Get-ModuleUnderTestPath {
    if ($env:M365GA_MODULE_PATH) { return $env:M365GA_MODULE_PATH }
    Join-Path $PSScriptRoot '../../M365GapAssessment/M365GapAssessment.psd1'
}

function New-MockAssessment {
    <#
    .SYNOPSIS
        Builds an in-memory assessment shaped like Invoke-M365SecurityReview output (no tenant, no Graph calls).
        Call inside InModuleScope so New-Finding can read the control mapping.
    #>
    param(
        [string]$TenantId = '11111111-2222-3333-4444-555555555555',
        [string]$TenantName = 'Contoso Ltd'
    )
    $findings = @(
        (New-Finding -Id 'ENT-CA-004' -Status Gap -Detail 'No enforced admin MFA policy.')
        (New-Finding -Id 'ENT-USR-004' -Status Pass)
        (New-Finding -Id 'SSC-001' -Status Pass)
    )
    [pscustomobject]@{
        TenantId      = $TenantId
        TenantName    = $TenantName
        AssessedAt    = [datetime]::UtcNow
        AssessedBy    = 'pester'
        ModuleVersion = '0.0.0-test'
        Score         = 50.0
        Summary       = [pscustomobject]@{
            TotalChecks = 3; Gaps = 1; Passed = 2; NotAssessed = 0; Accepted = 0
            GapsBySeverity = [pscustomobject]@{ Critical = 1; High = 0; Medium = 0; Low = 0 }
        }
        Findings      = $findings
        Metadata      = $null
    }
}
