@{
    RootModule           = 'M365GapAssessment.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'c2c7f43b-d44c-4425-bd29-a322815d254e'
    Author               = 'Rhys Etherington'
    CompanyName          = 'EtherAI'
    Copyright            = '(c) 2026 Rhys Etherington. Released under the MIT licence.'
    Description          = 'Read-only Microsoft 365 security gap assessment mapped to SCF, NIST CSF 2.0 and CIS. Designed for Global Reader and multi-tenant consulting workflows.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    # Microsoft.Graph.Authentication (2.0.0 or later) provides Connect-MgGraph / Invoke-MgGraphRequest and ships inside both the
    # Microsoft.Graph and Microsoft.Graph.Beta meta-modules; /beta endpoints are reached through it. It is NOT listed in RequiredModules:
    # PowerShell would then fail with a generic message before any of this module's code runs. M365GapAssessment.psm1 checks for it
    # first and says how to install it.
    FunctionsToExport    = @('Connect-M365Assessment', 'Invoke-M365SecurityReview', 'Export-M365GapReport', 'Compare-M365Assessment', 'Convert-M365Report')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Microsoft365', 'EntraID', 'Security', 'Assessment', 'NIST', 'SCF', 'CIS', 'MicrosoftGraph')
            ProjectUri = 'https://github.com/rhysetherington/M365-Assessor'
            LicenseUri = 'https://github.com/rhysetherington/M365-Assessor/blob/main/LICENSE'
        }
    }
}
