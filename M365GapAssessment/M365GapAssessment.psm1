# Root module: dot-source private + public functions, load the control mapping once.
$script:ModuleRoot       = $PSScriptRoot
$script:SeverityOrder    = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
$script:AssessmentContext = $null

# Scopes are read-only. Role/Group/Application/Device/Security scopes extend the base list so each collector can read its data.
$script:RequiredScopes = @(
    'User.Read', 'User.Read.All', 'Directory.Read.All', 'Policy.Read.All',
    'SecurityEvents.Read.All', 'SecurityAlert.Read.All', 'SecurityIncident.Read.All',
    'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'Reports.Read.All',
    'RoleManagement.Read.Directory', 'Application.Read.All', 'Group.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'RoleManagementPolicy.Read.Directory', 'IdentityRiskyUser.Read.All', 'AccessReview.Read.All',
    'EntitlementManagement.Read.All', 'Agreement.Read.All'
)

foreach ($file in @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -ErrorAction Stop)) {
    . $file.FullName
}
foreach ($file in @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -ErrorAction Stop)) {
    . $file.FullName
}

$script:ControlMapping = @{}
$mappingPath = Join-Path $PSScriptRoot 'Data/ControlMapping.json'
foreach ($entry in (Get-Content -Raw -Path $mappingPath | ConvertFrom-Json).controls) {
    $script:ControlMapping[$entry.id] = $entry
}

Export-ModuleMember -Function 'Connect-M365Assessment', 'Invoke-M365SecurityReview', 'Export-M365GapReport', 'Compare-M365Assessment', 'Convert-M365Report'
