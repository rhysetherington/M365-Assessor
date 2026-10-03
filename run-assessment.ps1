# Runs the full assessment. The tenant is never stored here: you are prompted for it (and for sign-in) each run.
Import-Module "$PSScriptRoot/M365GapAssessment/M365GapAssessment.psd1" -Force
Invoke-M365SecurityReview -ExportPath "$PSScriptRoot/Assessments" -Format JSON,Markdown,HTML `
    -Domain Licensing,EntraID,EntraPolicy,Defender,SecureScore,EmailDns,ExchangeOnline,Teams,SharePoint | Out-Null
