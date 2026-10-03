@{
    RootModule           = 'M365GapAssessment.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'c2c7f43b-d44c-4425-bd29-a322815d254e'
    Author               = 'Rhys Etherington'
    CompanyName          = 'EtherAI'
    Description          = 'Read-only Microsoft 365 security gap assessment mapped to SCF and NIST CSF 2.0. Designed for Global Reader and multi-tenant consulting workflows.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    # Microsoft.Graph.Authentication provides Connect-MgGraph / Invoke-MgGraphRequest and ships inside both
    # the Microsoft.Graph and Microsoft.Graph.Beta meta-modules; /beta endpoints are reached through it.
    RequiredModules      = @(@{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.0.0' })
    FunctionsToExport    = @('Connect-M365Assessment', 'Invoke-M365SecurityReview', 'Export-M365GapReport', 'Compare-M365Assessment', 'Convert-M365Report')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Microsoft365', 'EntraID', 'Security', 'Assessment', 'NIST', 'SCF', 'MicrosoftGraph')
            ProjectUri = ''
        }
    }
}
