# Runs every assessment domain, including the opt-in Exchange Online, Defender for Office 365, Purview and Teams domains.
# The tenant is never stored here: you are prompted for it (and for sign-in) each run. The opt-in domains each open one more sign-in
# and need the ExchangeOnlineManagement (Exchange, Defender for Office 365, Purview) and MicrosoftTeams modules; without them those
# checks are reported as NotAssessed. To run fewer domains, call Invoke-M365SecurityReview -Domain ... directly (see the README).
Import-Module "$PSScriptRoot/M365GapAssessment/M365GapAssessment.psd1" -Force

# Taken from the command itself so a domain added later is included automatically.
$allDomains = (Get-Command Invoke-M365SecurityReview).Parameters['Domain'].Attributes |
    Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
    ForEach-Object { $_.ValidValues }

Invoke-M365SecurityReview -ExportPath "$PSScriptRoot/Assessments" -Format JSON,Markdown,HTML -Domain $allDomains | Out-Null
