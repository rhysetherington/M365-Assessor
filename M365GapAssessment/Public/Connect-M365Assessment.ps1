function Connect-M365Assessment {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with read-only scopes and verifies the signed-in identity holds a read-capable role.
    .DESCRIPTION
        Interactive (default), device code, app-only client secret (-Credential: username = client ID, password = secret)
        or app-only certificate (-ClientId + -CertificateThumbprint). Switching tenants disconnects the previous session first.
    .EXAMPLE
        Connect-M365Assessment -TenantId contoso.onmicrosoft.com
    .EXAMPLE
        Connect-M365Assessment -TenantId $tid -ClientId $appId -CertificateThumbprint $thumb
    #>
    [CmdletBinding(DefaultParameterSetName = 'Interactive')]
    param(
        [string]$TenantId,
        [Parameter(ParameterSetName = 'Device')][switch]$UseDeviceAuthentication,
        [Parameter(ParameterSetName = 'Secret', Mandatory)][pscredential]$Credential,
        [Parameter(ParameterSetName = 'Cert', Mandatory)][string]$CertificateThumbprint,
        [Parameter(ParameterSetName = 'Cert', Mandatory)][string]$ClientId,
        [string]$Environment = 'Global',
        [switch]$SkipRoleCheck,
        [switch]$Force
    )

    $isAppOnly = $PSCmdlet.ParameterSetName -in 'Secret', 'Cert'
    $acceptedRoles = 'Global Reader', 'Global Administrator', 'Security Reader', 'Security Administrator'

    $ctx = Get-MgContext
    if ($ctx) {
        $sameTenant = (-not $TenantId) -or ($ctx.TenantId -eq $TenantId)
        $missing = if ($ctx.AuthType -eq 'Delegated') { @($script:RequiredScopes | Where-Object { $_ -notin $ctx.Scopes }) } else { @() }
        if ($Force -or -not $sameTenant -or $missing.Count) {
            Write-Verbose "Disconnecting existing Graph session (tenant $($ctx.TenantId))."
            Disconnect-MgGraph | Out-Null
            $ctx = $null
        }
    }

    if (-not $ctx) {
        $connect = @{ NoWelcome = $true; ContextScope = 'Process'; Environment = $Environment; ErrorAction = 'Stop' }
        # 'organizations' restricts sign-in to work/school accounts; the default 'common' authority also admits
        # personal Microsoft accounts, which cannot consent to these directory scopes (AADSTS70011).
        $connect.TenantId = if ($TenantId) { $TenantId } else { 'organizations' }
        switch ($PSCmdlet.ParameterSetName) {
            'Secret' { $connect.ClientSecretCredential = $Credential }
            'Cert' { $connect.ClientId = $ClientId; $connect.CertificateThumbprint = $CertificateThumbprint }
            'Device' { $connect.Scopes = $script:RequiredScopes; $connect.UseDeviceAuthentication = $true }
            default { $connect.Scopes = $script:RequiredScopes }
        }
        try { Connect-MgGraph @connect | Out-Null }
        catch { throw "Microsoft Graph sign-in failed: $($_.Exception.Message)" }
        $ctx = Get-MgContext
        if (-not $ctx) { throw 'Connect-MgGraph returned without establishing a session (sign-in not completed). Retry, or use -UseDeviceAuthentication.' }
    }

    $roles = @()
    if ($ctx.AuthType -eq 'Delegated' -and -not $SkipRoleCheck) {
        try {
            $roles = @(Get-GraphPagedResult -Uri '/v1.0/me/memberOf/microsoft.graph.directoryRole?$select=displayName' | ForEach-Object { $_.displayName })
        }
        catch { throw "Could not read the signed-in user's directory roles: $($_.Exception.Message)" }

        if (-not ($roles | Where-Object { $_ -in $acceptedRoles })) {
            Disconnect-MgGraph | Out-Null
            throw "Signed-in account holds no read-capable role (needs one of: $($acceptedRoles -join ', ')). Roles found: $(if ($roles) { $roles -join ', ' } else { 'none' }). If the role is PIM-eligible, activate it first. Use -SkipRoleCheck to bypass."
        }
        if ('Global Administrator' -in $roles -and 'Global Reader' -notin $roles) {
            Write-Warning 'Signed in as Global Administrator. This tool is read-only; Global Reader is the recommended least-privilege role.'
        }
    }
    elseif ($ctx.AuthType -ne 'Delegated') {
        Write-Verbose 'App-only session: verify the app registration has the read-only application permissions consented.'
    }

    $script:AssessmentContext = [pscustomobject]@{
        TenantId  = $ctx.TenantId
        Account   = if ($ctx.Account) { $ctx.Account } else { "app:$($ctx.ClientId)" }
        AuthType  = $ctx.AuthType
        Scopes    = @($ctx.Scopes)
        Roles     = $roles
        Connected = [datetime]::UtcNow
    }
    $script:AssessmentContext
}
