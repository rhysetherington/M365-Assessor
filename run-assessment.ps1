Import-Module "$PSScriptRoot/M365GapAssessment/M365GapAssessment.psd1" -Force
Invoke-M365SecurityReview -TenantId 00000000-0000-0000-0000-000000000000 -ExportPath "$PSScriptRoot/Assessments" -Format JSON,Markdown,HTML `
    -Domain Licensing,EntraID,EntraPolicy,Defender,SecureScore,EmailDns,ExchangeOnline,Teams,SharePoint | Out-Null
