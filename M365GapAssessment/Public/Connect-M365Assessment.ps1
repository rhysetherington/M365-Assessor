function Connect-M365Assessment {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with read-only scopes and verifies the signed-in identity holds a read-capable role.
    .DESCRIPTION
        Interactive (default), device code, app-only client secret (-Credential: username = client ID, password = secret)
        or app-only certificate (-ClientId + -CertificateThumbprint). Switching tenants disconnects the previous session first.
        An account that holds the Global Administrator role is not needed (Global Reader is enough), so the run asks for confirmation
        (default No) when one is used, and stops in a session that cannot ask unless -AllowGlobalAdministrator is passed on purpose.
        -Environment selects the Microsoft cloud (Global, USGov = GCC High, USGovDoD, China). Exchange, Security & Compliance and
        Teams follow the same cloud. Only Global has been run against a live tenant; the others warn that they are untested.
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
        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')][string]$Environment = 'Global',
        [switch]$SkipRoleCheck,
        [switch]$AllowGlobalAdministrator,
        [switch]$Force
    )

    $isAppOnly = $PSCmdlet.ParameterSetName -in 'Secret', 'Cert'
    $acceptedRoles = 'Global Reader', 'Global Administrator', 'Security Reader', 'Security Administrator'

    $ctx = Get-MgContext
    if ($ctx) {
        $sameTenant = (-not $TenantId) -or ($ctx.TenantId -eq $TenantId)
        $missing = if ($ctx.AuthType -eq 'Delegated') { @($script:RequiredScopes | Where-Object { $_ -notin $ctx.Scopes }) } else { @() }
        $sameCloud = (-not $ctx.Environment) -or ($ctx.Environment -eq $Environment)
        if ($Force -or -not $sameTenant -or -not $sameCloud -or $missing.Count) {
            Write-Verbose "Disconnecting existing Graph session (tenant $($ctx.TenantId))."
            Disconnect-MgGraph | Out-Null
            $ctx = $null
        }
    }

    if (-not $ctx) {
        $script:GlobalAdminAcknowledged = $null   # a new sign-in has to be confirmed again
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

    # Refuse to assess a tenant through the wrong cloud: the session must be in the cloud that was asked for.
    if ($ctx.Environment -and $ctx.Environment -ne $Environment) {
        Disconnect-MgGraph | Out-Null
        throw "The Graph session is in the '$($ctx.Environment)' cloud but -Environment '$Environment' was requested. Disconnected; nothing was assessed."
    }
    # Exchange, Security & Compliance and Teams read this to connect to the same cloud.
    $script:CloudEnvironmentName = $Environment
    $cloud = Get-CloudEnvironment -Name $Environment
    if (-not $cloud.LiveTested) {
        Write-Warning "Cloud '$Environment' ($($cloud.Display)) is wired up but has not been tested against a live tenant: any endpoint this cloud does not offer is reported as NotAssessed. Review results before relying on them."
    }

    $roles = @()
    if ($ctx.AuthType -eq 'Delegated') {
        # The roles are read even with -SkipRoleCheck: that switch waives the read-role requirement, not the Global Administrator
        # confirmation, so a script cannot sidestep the guard by skipping the check.
        try { $roles = @(Get-SignedInDirectoryRoles) }
        catch {
            if (-not $SkipRoleCheck) { throw "Could not read the signed-in user's directory roles: $($_.Exception.Message)" }
            Write-Warning "Could not read the signed-in user's directory roles, so it was not possible to check whether this account is a Global Administrator: $($_.Exception.Message)"
        }

        if (-not $SkipRoleCheck -and -not ($roles | Where-Object { $_ -in $acceptedRoles })) {
            Disconnect-MgGraph | Out-Null
            throw "Signed-in account holds no read-capable role (needs one of: $($acceptedRoles -join ', ')). Roles found: $(if ($roles) { $roles -join ', ' } else { 'none' }). If the role is PIM-eligible, activate it first. Use -SkipRoleCheck to bypass."
        }
        # Any account that holds Global Administrator is covered, including one that also holds Global Reader.
        if ('Global Administrator' -in $roles) {
            Confirm-GlobalAdministratorUse -Account $ctx.Account -TenantId $ctx.TenantId -Allow:$AllowGlobalAdministrator
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
